#include "cw/AobScanner.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <limits>
#include <vector>

namespace cw {
namespace {

constexpr SIZE_T kChunkSize = 4ull * 1024ull * 1024ull;
constexpr std::size_t kMaxResults = 1'000'000;

bool readableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) return false;
    switch (protect & 0xFFu) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

bool writableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) return false;
    switch (protect & 0xFFu) {
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

bool executableProtection(DWORD protect) {
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0) return false;
    switch (protect & 0xFFu) {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

bool regionAllowed(const MEMORY_BASIC_INFORMATION& mbi, const ScanOptions& options, bool executableOnly) {
    if (mbi.State != MEM_COMMIT || !readableProtection(mbi.Protect)) return false;
    if (options.writableOnly && !writableProtection(mbi.Protect)) return false;
    if (options.privateOnly && mbi.Type != MEM_PRIVATE) return false;
    if (executableOnly && !executableProtection(mbi.Protect)) return false;
    return true;
}

} // namespace

void AobScanner::clear() {
    results_.clear();
    pattern_.bytes.clear();
    resetCancel();
}

void AobScanner::reportProgress(const ScanStats& stats) const {
    if (!progressCallback_) return;
    progressCallback_(ScanProgress{stats.bytesRead, stats.regionsRead, results_.size()});
}

ScanStats AobScanner::scan(const AobPattern& pattern) {
    clear();
    pattern_ = pattern;
    ScanStats stats{};
    const auto started = std::chrono::steady_clock::now();
    auto finish = [&] {
        stats.resultCount = results_.size();
        stats.elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
        return stats;
    };

    if (!process_ || pattern.empty()) return finish();

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    const auto systemMin = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const auto systemMax = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
    std::uintptr_t current = (std::max)(systemMin, options_.minAddress);
    const std::uintptr_t maximum = (std::min)(systemMax, options_.maxAddress);
    if (current > maximum) return finish();

    const std::size_t overlap = pattern.size() > 0 ? pattern.size() - 1 : 0;
    std::vector<std::byte> buffer(kChunkSize + overlap);
    MEMORY_BASIC_INFORMATION mbi{};
    const SIZE_T pageSize = (std::max)(static_cast<SIZE_T>(systemInfo.dwPageSize), SIZE_T{1});

    const auto scanBuffer = [&](std::uintptr_t base, const std::byte* data,
                                std::size_t availableBytes, std::size_t candidateStarts) -> bool {
        if (availableBytes < pattern.size() || candidateStarts == 0) return true;
        candidateStarts = (std::min)(candidateStarts, availableBytes);
        const std::size_t maxByAvailable = availableBytes - pattern.size() + 1;
        candidateStarts = (std::min)(candidateStarts, maxByAvailable);
        for (std::size_t offset = 0; offset < candidateStarts; ++offset) {
            if (matchAob(data + offset, pattern)) {
                results_.push_back(base + offset);
                if (results_.size() >= kMaxResults) {
                    stats.truncated = true;
                    return false;
                }
            }
        }
        return true;
    };

    while (current <= maximum) {
        if (cancelRequested_.load(std::memory_order_relaxed)) {
            stats.cancelled = true;
            break;
        }

        const SIZE_T queried = VirtualQueryEx(
            process_, reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi));
        if (queried == 0) {
            const auto step = (std::max)(static_cast<std::uintptr_t>(systemInfo.dwPageSize), std::uintptr_t{1});
            if (step > maximum - current) break;
            current += step;
            continue;
        }

        const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        if (mbi.RegionSize == 0 ||
            regionBase > (std::numeric_limits<std::uintptr_t>::max)() - mbi.RegionSize) break;
        const auto regionEnd = regionBase + mbi.RegionSize;
        const auto clippedBase = (std::max)(regionBase, current);
        auto clippedEnd = regionEnd;
        if (maximum != (std::numeric_limits<std::uintptr_t>::max)()) {
            clippedEnd = (std::min)(clippedEnd, maximum + 1);
        }

        if (clippedBase < clippedEnd && regionAllowed(mbi, options_, executableOnly_)) {
            for (std::uintptr_t chunkBase = clippedBase; chunkBase < clippedEnd;) {
                if (cancelRequested_.load(std::memory_order_relaxed)) {
                    stats.cancelled = true;
                    break;
                }
                const SIZE_T remaining = static_cast<SIZE_T>(clippedEnd - chunkBase);
                const SIZE_T primarySize = (std::min)(kChunkSize, remaining);
                if (primarySize == 0) break;
                const SIZE_T readSize = (std::min)(
                    remaining, primarySize + static_cast<SIZE_T>(overlap));
                if (buffer.size() < readSize) buffer.resize(readSize);

                SIZE_T bytesRead = 0;
                const BOOL ok = ReadProcessMemory(
                    process_, reinterpret_cast<LPCVOID>(chunkBase), buffer.data(), readSize, &bytesRead);
                if (bytesRead > 0) {
                    ++stats.regionsRead;
                    stats.bytesRead += bytesRead;
                    const auto starts = static_cast<std::size_t>((std::min)(primarySize, bytesRead));
                    if (!scanBuffer(chunkBase, buffer.data(), static_cast<std::size_t>(bytesRead), starts)) {
                        reportProgress(stats);
                        return finish();
                    }
                    reportProgress(stats);
                }

                if ((!ok || bytesRead < readSize) && bytesRead < primarySize) {
                    SIZE_T retryOffset = bytesRead;
                    while (retryOffset < primarySize) {
                        const SIZE_T pagePrimary = (std::min)(pageSize, primarySize - retryOffset);
                        const auto pageBase = chunkBase + retryOffset;
                        const SIZE_T pageRemaining = static_cast<SIZE_T>(clippedEnd - pageBase);
                        const SIZE_T pageReadSize = (std::min)(
                            pageRemaining, pagePrimary + static_cast<SIZE_T>(overlap));
                        if (buffer.size() < pageReadSize) buffer.resize(pageReadSize);
                        SIZE_T pageBytes = 0;
                        ReadProcessMemory(process_, reinterpret_cast<LPCVOID>(pageBase),
                                          buffer.data(), pageReadSize, &pageBytes);
                        if (pageBytes > 0) {
                            ++stats.regionsRead;
                            stats.bytesRead += pageBytes;
                            const auto starts = static_cast<std::size_t>((std::min)(pagePrimary, pageBytes));
                            if (!scanBuffer(pageBase, buffer.data(), static_cast<std::size_t>(pageBytes), starts)) {
                                reportProgress(stats);
                                return finish();
                            }
                            reportProgress(stats);
                        }
                        retryOffset += pagePrimary;
                    }
                }
                if (stats.truncated || stats.cancelled) break;
                chunkBase += primarySize;
            }
        }
        if (stats.truncated || stats.cancelled) break;
        if (regionEnd <= current) break;
        current = regionEnd;
    }

    return finish();
}

} // namespace cw
