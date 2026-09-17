#include "cw/PointerScanner.hpp"

#include "cw/PointerAlgorithms.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <new>

namespace cw {
namespace {

constexpr SIZE_T kChunkSize = 4ull * 1024ull * 1024ull;

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

bool readableRegion(const MEMORY_BASIC_INFORMATION& mbi, const PointerScanOptions& options) {
    if (mbi.State != MEM_COMMIT || !readableProtection(mbi.Protect)) return false;
    if (options.writableOnly && !writableProtection(mbi.Protect)) return false;
    if (options.privateOnly && mbi.Type != MEM_PRIVATE) return false;
    return true;
}

std::size_t effectiveAlignment(const PointerScanOptions& options, std::size_t pointerSize) {
    return options.alignment == 0 ? pointerSize : options.alignment;
}

std::vector<PointerModule> toPointerModules(const std::vector<ModuleInfo>& modules) {
    std::vector<PointerModule> out;
    out.reserve(modules.size());
    for (const auto& module : modules) {
        out.push_back(PointerModule{module.base, module.size, module.name});
    }
    return out;
}

std::optional<std::uintptr_t> addSignedOffset(std::uintptr_t base, std::int64_t offset) {
    if (offset >= 0) {
        const auto amount = static_cast<std::uint64_t>(offset);
        if (amount > static_cast<std::uint64_t>((std::numeric_limits<std::uintptr_t>::max)() - base)) return std::nullopt;
        return base + static_cast<std::uintptr_t>(amount);
    }
    const auto magnitude = static_cast<std::uint64_t>(-(offset + 1)) + 1u;
    if (magnitude > static_cast<std::uint64_t>(base)) return std::nullopt;
    return base - static_cast<std::uintptr_t>(magnitude);
}

} // namespace

void PointerScanner::setProcess(HANDLE process, std::size_t pointerSize, std::vector<ModuleInfo> modules) {
    process_ = process;
    pointerSize_ = pointerSize;
    modules_ = std::move(modules);
    clearIndex();
    resetCancel();
    // Deliberately keep chains_: this permits pointer-rescan after restarting
    // and reattaching to the target. clearChains() is explicit.
}

void PointerScanner::clearIndex() {
    index_.clear();
    index_.shrink_to_fit();
}

void PointerScanner::clearChains() {
    chains_.clear();
    chains_.shrink_to_fit();
    chainPointerSize_ = 0;
}

void PointerScanner::reportProgress(const PointerScanStats& stats) const {
    if (!progressCallback_) return;
    progressCallback_(PointerProgress{stats.bytesRead, stats.regionsRead, index_.size()});
}

bool PointerScanner::buildIndex(const PointerScanOptions& options, PointerScanStats& stats) {
    clearIndex();
    if (!process_ || (pointerSize_ != 4 && pointerSize_ != 8)) return false;

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    const auto minimum = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto maximum = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    const std::size_t pageSize = si.dwPageSize ? static_cast<std::size_t>(si.dwPageSize) : 4096u;

    std::vector<std::byte> buffer;
    try {
        buffer.resize(static_cast<std::size_t>(kChunkSize) + pointerSize_ - 1);
        index_.reserve((std::min)(options.maxIndexEntries, std::size_t{1'000'000}));
    } catch (const std::bad_alloc&) {
        return false;
    }

    const std::size_t alignment = effectiveAlignment(options, pointerSize_);
    if (alignment == 0 || alignment > 8 || (alignment & (alignment - 1)) != 0) return false;

    auto processBuffer = [&](std::uintptr_t base, const std::byte* data,
                             std::size_t available, std::size_t primary) -> bool {
        if (available < pointerSize_ || primary == 0) return true;
        std::size_t start = 0;
        const auto rem = static_cast<std::size_t>(base % alignment);
        if (rem != 0) start = alignment - rem;

        for (std::size_t offset = start;
             offset < primary && offset + pointerSize_ <= available;
             offset += alignment) {
            std::uintptr_t value = 0;
            if (pointerSize_ == 4) {
                std::uint32_t v{};
                std::memcpy(&v, data + offset, sizeof(v));
                value = static_cast<std::uintptr_t>(v);
            } else {
                std::uint64_t v{};
                std::memcpy(&v, data + offset, sizeof(v));
                if (v > (std::numeric_limits<std::uintptr_t>::max)()) continue;
                value = static_cast<std::uintptr_t>(v);
            }

            if (value < minimum || value >= maximum) continue;
            index_.push_back(PointerEntry{value, base + offset});
            if (index_.size() >= options.maxIndexEntries) {
                stats.indexTruncated = true;
                return false;
            }
        }
        return true;
    };

    auto readAndProcess = [&](std::uintptr_t base, std::size_t primary, std::uintptr_t regionEnd) -> bool {
        std::size_t extra = 0;
        if (base + primary < regionEnd && pointerSize_ > 1) extra = pointerSize_ - 1;
        auto toRead = primary + extra;
        if (base + toRead > regionEnd) toRead = static_cast<std::size_t>(regionEnd - base);

        SIZE_T bytesRead = 0;
        const BOOL ok = ReadProcessMemory(
            process_, reinterpret_cast<LPCVOID>(base), buffer.data(), toRead, &bytesRead);
        if ((ok || bytesRead > 0) && bytesRead >= pointerSize_) {
            stats.bytesRead += bytesRead;
            return processBuffer(base, buffer.data(), static_cast<std::size_t>(bytesRead), primary);
        }
        return true; // caller may retry at page granularity
    };

    std::uintptr_t current = minimum;
    while (current < maximum) {
        if (cancelRequested_.load(std::memory_order_relaxed)) {
            stats.cancelled = true;
            break;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi))) break;
        const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const auto regionSize = static_cast<std::uintptr_t>(mbi.RegionSize);
        const auto regionEnd = regionBase + regionSize;
        if (regionEnd <= current) break;

        if (readableRegion(mbi, options)) {
            ++stats.regionsRead;
            std::uintptr_t p = regionBase;
            while (p < regionEnd) {
                if (cancelRequested_.load(std::memory_order_relaxed)) {
                    stats.cancelled = true;
                    break;
                }
                const auto remaining = regionEnd - p;
                const auto primary = static_cast<std::size_t>((std::min<std::uintptr_t>)(remaining, kChunkSize));

                SIZE_T probeRead = 0;
                std::size_t extra = (p + primary < regionEnd && pointerSize_ > 1) ? pointerSize_ - 1 : 0;
                std::size_t toRead = primary + extra;
                if (p + toRead > regionEnd) toRead = static_cast<std::size_t>(regionEnd - p);
                const BOOL ok = ReadProcessMemory(
                    process_, reinterpret_cast<LPCVOID>(p), buffer.data(), toRead, &probeRead);

                bool keepGoing = true;
                if ((ok || probeRead > 0) && probeRead >= pointerSize_) {
                    stats.bytesRead += probeRead;
                    keepGoing = processBuffer(p, buffer.data(), static_cast<std::size_t>(probeRead), primary);
                } else {
                    // A region can race with protection changes. Retry this chunk page-by-page
                    // so one bad page does not hide pointers in the rest of it.
                    const auto chunkEnd = p + primary;
                    for (auto page = p; page < chunkEnd; page += pageSize) {
                        const auto pagePrimary = static_cast<std::size_t>((std::min<std::uintptr_t>)(pageSize, chunkEnd - page));
                        if (!readAndProcess(page, pagePrimary, regionEnd)) {
                            keepGoing = false;
                            break;
                        }
                    }
                }

                reportProgress(stats);
                if (!keepGoing || stats.indexTruncated) break;
                p += primary;
            }
        }

        if (stats.cancelled || stats.indexTruncated) break;
        current = regionEnd;
    }

    std::sort(index_.begin(), index_.end());
    index_.erase(std::unique(index_.begin(), index_.end(), [](const PointerEntry& a, const PointerEntry& b) {
        return a.value == b.value && a.address == b.address;
    }), index_.end());
    return true;
}

PointerScanStats PointerScanner::captureIndex(const PointerScanOptions& options) {
    PointerScanStats stats;
    stats.pointerSize = pointerSize_;
    resetCancel();

    const auto indexStart = std::chrono::steady_clock::now();
    if (!buildIndex(options, stats)) {
        stats.indexMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - indexStart).count();
        stats.indexEntries = index_.size();
        return stats;
    }
    stats.indexMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - indexStart).count();
    stats.indexEntries = index_.size();
    return stats;
}

PointerScanStats PointerScanner::scan(std::uintptr_t target, const PointerScanOptions& options) {
    PointerScanStats stats;
    stats.pointerSize = pointerSize_;
    resetCancel();
    chains_.clear();
    chainPointerSize_ = pointerSize_;

    const auto indexStart = std::chrono::steady_clock::now();
    if (!buildIndex(options, stats)) {
        stats.indexMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - indexStart).count();
        return stats;
    }
    stats.indexMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - indexStart).count();
    stats.indexEntries = index_.size();

    if (stats.cancelled) return stats;

    const auto searchStart = std::chrono::steady_clock::now();
    bool searchTruncated = false;
    chains_ = findPointerChains(index_, toPointerModules(modules_), target, options, &searchTruncated);
    stats.searchMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - searchStart).count();
    stats.chains = chains_.size();
    stats.chainsTruncated = searchTruncated;
    return stats;
}

std::optional<std::uintptr_t> PointerScanner::readPointer(std::uintptr_t address) const {
    if (!process_) return std::nullopt;
    SIZE_T bytesRead = 0;
    if (pointerSize_ == 4) {
        std::uint32_t value{};
        if (!ReadProcessMemory(process_, reinterpret_cast<LPCVOID>(address), &value, sizeof(value), &bytesRead) ||
            bytesRead != sizeof(value)) return std::nullopt;
        return static_cast<std::uintptr_t>(value);
    }
    if (pointerSize_ == 8) {
        std::uint64_t value{};
        if (!ReadProcessMemory(process_, reinterpret_cast<LPCVOID>(address), &value, sizeof(value), &bytesRead) ||
            bytesRead != sizeof(value)) return std::nullopt;
        if (value > (std::numeric_limits<std::uintptr_t>::max)()) return std::nullopt;
        return static_cast<std::uintptr_t>(value);
    }
    return std::nullopt;
}

const ModuleInfo* PointerScanner::findModule(const std::wstring& name) const {
    auto lower = [](wchar_t c) {
        return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
    };
    for (const auto& module : modules_) {
        if (module.name.size() != name.size()) continue;
        bool equal = true;
        for (std::size_t i = 0; i < name.size(); ++i) {
            if (lower(module.name[i]) != lower(name[i])) {
                equal = false;
                break;
            }
        }
        if (equal) return &module;
    }
    return nullptr;
}

std::optional<std::uintptr_t> PointerScanner::resolve(const PointerChain& chain) const {
    const auto* module = findModule(chain.moduleName);
    if (!module) return std::nullopt;
    if (chain.rootOffset >= module->size) return std::nullopt;

    std::uintptr_t address = module->base + chain.rootOffset;
    for (const auto offset : chain.offsets) {
        const auto pointer = readPointer(address);
        if (!pointer) return std::nullopt;
        const auto next = addSignedOffset(*pointer, offset);
        if (!next) return std::nullopt;
        address = *next;
    }
    return address;
}

std::optional<std::uintptr_t> PointerScanner::resolve(std::size_t chainIndex) const {
    if (chainIndex >= chains_.size()) return std::nullopt;
    if (chainPointerSize_ != 0 && pointerSize_ != chainPointerSize_) return std::nullopt;
    return resolve(chains_[chainIndex]);
}

std::size_t PointerScanner::rescan(std::uintptr_t target) {
    if (!process_) return 0;
    if (chainPointerSize_ != 0 && pointerSize_ != chainPointerSize_) return 0;
    std::vector<PointerChain> kept;
    kept.reserve(chains_.size());
    for (const auto& chain : chains_) {
        const auto resolved = resolve(chain);
        if (resolved && *resolved == target) kept.push_back(chain);
    }
    chains_.swap(kept);
    return chains_.size();
}

} // namespace cw
