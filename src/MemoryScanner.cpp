#include "cw/MemoryScanner.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <type_traits>
#include <utility>

namespace cw {
namespace {

constexpr SIZE_T kChunkSize = 4ull * 1024ull * 1024ull;
constexpr std::size_t kMaxResults = 5'000'000;
constexpr std::size_t kValueTypeCount = 6;

std::size_t valueTypeIndex(ValueType type) {
    switch (type) {
        case ValueType::Byte: return 0;
        case ValueType::Int16: return 1;
        case ValueType::Int32: return 2;
        case ValueType::Int64: return 3;
        case ValueType::Float: return 4;
        case ValueType::Double: return 5;
    }
    return kValueTypeCount;
}

ValueType valueTypeFromIndex(std::size_t index) {
    static constexpr std::array<ValueType, kValueTypeCount> types{
        ValueType::Byte, ValueType::Int16, ValueType::Int32,
        ValueType::Int64, ValueType::Float, ValueType::Double};
    return index < types.size() ? types[index] : ValueType::Int32;
}

std::size_t alignedStartOffset(std::uintptr_t base, std::size_t alignment) {
    if (alignment == 0) return 0;
    const auto remainder = static_cast<std::size_t>(base % alignment);
    return remainder == 0 ? 0 : alignment - remainder;
}

bool snapshotBitSet(const std::vector<std::uint64_t>& bits, std::size_t index) {
    const std::size_t word = index / 64;
    return word < bits.size() && (bits[word] & (std::uint64_t{1} << (index % 64))) != 0;
}

void setSnapshotBit(std::vector<std::uint64_t>& bits, std::size_t index) {
    const std::size_t word = index / 64;
    if (word < bits.size()) bits[word] |= std::uint64_t{1} << (index % 64);
}

template <typename T>
bool isType(ValueType type) {
    return (type == ValueType::Byte && std::is_same_v<T, std::uint8_t>) ||
           (type == ValueType::Int16 && std::is_same_v<T, std::int16_t>) ||
           (type == ValueType::Int32 && std::is_same_v<T, std::int32_t>) ||
           (type == ValueType::Int64 && std::is_same_v<T, std::int64_t>) ||
           (type == ValueType::Float && std::is_same_v<T, float>) ||
           (type == ValueType::Double && std::is_same_v<T, double>);
}

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

std::uint32_t rankingTypeScore(ValueType type) {
    switch (type) {
        case ValueType::Int32: return 30;
        case ValueType::Float: return 30;
        case ValueType::Int64: return 18;
        case ValueType::Double: return 18;
        case ValueType::Int16: return 10;
        case ValueType::Byte: return 4;
    }
    return 0;
}

std::uint32_t rankingValueScore(const ScanResult& result) {
    switch (result.type) {
        case ValueType::Byte: {
            const auto value = unpackScanValue<std::uint8_t>(result.previousBits);
            if (value == 0) return 0;
            return 2u + (value <= 100 ? 4u : 0u);
        }
        case ValueType::Int16: {
            const auto value = unpackScanValue<std::int16_t>(result.previousBits);
            if (value == 0) return 0;
            return 3u + (value >= -10'000 && value <= 10'000 ? 6u : 0u);
        }
        case ValueType::Int32: {
            const auto value = unpackScanValue<std::int32_t>(result.previousBits);
            if (value == 0) return 0;
            std::uint32_t score = 4;
            if (value >= -1'000'000'000 && value <= 1'000'000'000) score += 6;
            if (value >= -10'000'000 && value <= 10'000'000) score += 8;
            return score;
        }
        case ValueType::Int64: {
            const auto value = unpackScanValue<std::int64_t>(result.previousBits);
            if (value == 0) return 0;
            std::uint32_t score = 4;
            if (value >= -1'000'000'000LL && value <= 1'000'000'000LL) score += 6;
            if (value >= -10'000'000LL && value <= 10'000'000LL) score += 8;
            return score;
        }
        case ValueType::Float: {
            const auto value = unpackScanValue<float>(result.previousBits);
            if (!std::isfinite(value) || value == 0.0f) return 0;
            const float magnitude = std::fabs(value);
            std::uint32_t score = 4;
            if (std::fpclassify(value) != FP_SUBNORMAL) score += 4;
            if (magnitude >= 1.0e-6f && magnitude <= 1.0e9f) score += 8;
            if (magnitude >= 1.0e-3f && magnitude <= 1.0e7f) score += 6;
            return score;
        }
        case ValueType::Double: {
            const auto value = unpackScanValue<double>(result.previousBits);
            if (!std::isfinite(value) || value == 0.0) return 0;
            const double magnitude = std::fabs(value);
            std::uint32_t score = 4;
            if (std::fpclassify(value) != FP_SUBNORMAL) score += 4;
            if (magnitude >= 1.0e-6 && magnitude <= 1.0e9) score += 8;
            if (magnitude >= 1.0e-3 && magnitude <= 1.0e7) score += 6;
            return score;
        }
    }
    return 0;
}

std::uint32_t rankingGoalTypeScore(ValueType type, GuidedGoal goal) {
    switch (goal) {
        case GuidedGoal::Generic:
            return 0;
        case GuidedGoal::Money:
            switch (type) {
                case ValueType::Int32: return 36;
                case ValueType::Int64: return 28;
                case ValueType::Int16: return 8;
                case ValueType::Float: return 4;
                case ValueType::Double: return 2;
                case ValueType::Byte: return 1;
            }
            break;
        case GuidedGoal::Health:
            switch (type) {
                case ValueType::Float: return 24;
                case ValueType::Int32: return 18;
                case ValueType::Double: return 12;
                case ValueType::Int16: return 10;
                case ValueType::Byte: return 6;
                case ValueType::Int64: return 4;
            }
            break;
        case GuidedGoal::Ammo:
            switch (type) {
                case ValueType::Int32: return 34;
                case ValueType::Int16: return 22;
                case ValueType::Byte: return 16;
                case ValueType::Int64: return 10;
                case ValueType::Float: return 2;
                case ValueType::Double: return 0;
            }
            break;
    }
    return 0;
}

bool rankingNearWhole(double value) {
    if (!std::isfinite(value)) return false;
    const double rounded = std::round(value);
    const double tolerance = (std::max)(0.001, std::fabs(value) * 1.0e-5);
    return std::fabs(value - rounded) <= tolerance;
}

std::uint32_t rankingGoalValueScore(const ScanResult& result, GuidedGoal goal) {
    double value = 0.0;
    bool integralType = false;
    switch (result.type) {
        case ValueType::Byte:
            value = unpackScanValue<std::uint8_t>(result.previousBits);
            integralType = true;
            break;
        case ValueType::Int16:
            value = unpackScanValue<std::int16_t>(result.previousBits);
            integralType = true;
            break;
        case ValueType::Int32:
            value = unpackScanValue<std::int32_t>(result.previousBits);
            integralType = true;
            break;
        case ValueType::Int64:
            value = static_cast<double>(unpackScanValue<std::int64_t>(result.previousBits));
            integralType = true;
            break;
        case ValueType::Float:
            value = unpackScanValue<float>(result.previousBits);
            break;
        case ValueType::Double:
            value = unpackScanValue<double>(result.previousBits);
            break;
    }
    if (!std::isfinite(value)) return 0;

    const double magnitude = std::fabs(value);
    std::uint32_t score = 0;
    // Generic tie-breakers deliberately stay small: they refine plausibility,
    // but never outweigh memory-region/type signals.
    if (value > 0.0) score += 2;
    if (magnitude >= 0.001 && magnitude <= 1000.0) score += 4;
    if (magnitude >= 1.0 && magnitude <= 100000.0) score += 3;
    if (rankingNearWhole(value)) score += integralType ? 3u : 8u;

    switch (goal) {
        case GuidedGoal::Generic:
            return score;
        case GuidedGoal::Money:
            if (value >= 0.0) score += 10;
            if (value >= 1.0 && value <= 1.0e9) score += 6;
            if (value <= 1.0e7) score += 4;
            if (!integralType && rankingNearWhole(value)) score += 5;
            break;
        case GuidedGoal::Health:
            if (value >= 0.0 && value <= 1000.0) score += 12;
            if (value >= 0.0 && value <= 250.0) score += 8;
            if (!integralType && value >= 0.0 && value <= 1.0) score += 5;
            break;
        case GuidedGoal::Ammo:
            if (value >= 0.0 && value <= 1000.0) score += 12;
            if (value >= 0.0 && value <= 500.0) score += 8;
            if (value >= 0.0 && value <= 100.0) score += 4;
            if (integralType) score += 4;
            break;
    }
    return score;
}

std::uint32_t rankingIsolationScore(const std::vector<ScanResult>& results, std::size_t index) {
    if (index >= results.size()) return 0;
    const auto& result = results[index];
    std::uintptr_t nearest = (std::numeric_limits<std::uintptr_t>::max)();
    constexpr std::size_t kLookAround = 8;
    const auto consider = [&](std::size_t otherIndex) {
        const auto& other = results[otherIndex];
        if (other.type != result.type) return;
        const std::uintptr_t distance = other.address > result.address
            ? other.address - result.address
            : result.address - other.address;
        if (distance != 0 && distance < nearest) nearest = distance;
    };
    for (std::size_t delta = 1; delta <= kLookAround; ++delta) {
        if (index >= delta) consider(index - delta);
        if (index + delta < results.size()) consider(index + delta);
    }
    if (nearest == (std::numeric_limits<std::uintptr_t>::max)()) return 8;
    const std::uintptr_t width = static_cast<std::uintptr_t>(valueTypeSize(result.type));
    if (nearest >= width * 256u) return 12;
    if (nearest >= width * 64u) return 9;
    if (nearest >= width * 16u) return 6;
    if (nearest >= width * 4u) return 3;
    return 0;
}

bool regionAllowed(const MEMORY_BASIC_INFORMATION& mbi, const ScanOptions& options) {
    if (mbi.State != MEM_COMMIT) return false;
    if (!readableProtection(mbi.Protect)) return false;
    if (options.writableOnly && !writableProtection(mbi.Protect)) return false;
    if (options.privateOnly && mbi.Type != MEM_PRIVATE) return false;
    return true;
}

template <typename T>
std::size_t alignedCandidateCount(
    std::uintptr_t base,
    std::size_t availableBytes,
    std::size_t candidateBytes,
    std::size_t alignment)
{
    if (availableBytes < sizeof(T) || candidateBytes == 0 || alignment == 0) return 0;
    candidateBytes = (std::min)(candidateBytes, availableBytes);

    std::size_t start = 0;
    const auto remainder = static_cast<std::size_t>(base % alignment);
    if (remainder != 0) start = alignment - remainder;
    if (start >= candidateBytes || start + sizeof(T) > availableBytes) return 0;

    const std::size_t maxStartByAvailable = availableBytes - sizeof(T);
    const std::size_t maxStartByCandidate = candidateBytes - 1;
    const std::size_t maxStart = (std::min)(maxStartByAvailable, maxStartByCandidate);
    return 1 + (maxStart - start) / alignment;
}

template <typename T, typename Callback>
bool visitCandidates(
    std::uintptr_t base,
    const std::byte* data,
    std::size_t availableBytes,
    std::size_t candidateBytes,
    std::size_t alignment,
    Callback&& callback)
{
    if (!data || availableBytes < sizeof(T) || candidateBytes == 0 || alignment == 0) return true;
    candidateBytes = (std::min)(candidateBytes, availableBytes);

    std::size_t start = 0;
    const auto remainder = static_cast<std::size_t>(base % alignment);
    if (remainder != 0) start = alignment - remainder;

    for (std::size_t offset = start;
         offset < candidateBytes && offset + sizeof(T) <= availableBytes;
         offset += alignment) {
        T current{};
        std::memcpy(&current, data + offset, sizeof(T));
        if (!callback(base + offset, current)) return false;
    }
    return true;
}

template <typename ShouldCancel, typename Progress, typename Callback>
bool visitReadableMemory(
    HANDLE process,
    const ScanOptions& options,
    std::size_t overlapBytes,
    ScanStats& stats,
    ShouldCancel&& shouldCancel,
    Progress&& progress,
    Callback&& callback)
{
    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);

    const std::uintptr_t systemMin = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const std::uintptr_t systemMax = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
    std::uintptr_t current = (std::max)(systemMin, options.minAddress);
    const std::uintptr_t maximum = (std::min)(systemMax, options.maxAddress);
    if (current > maximum) return true;

    MEMORY_BASIC_INFORMATION mbi{};
    std::vector<std::byte> buffer(kChunkSize + overlapBytes);
    const SIZE_T pageSize = (std::max)(static_cast<SIZE_T>(systemInfo.dwPageSize), SIZE_T{1});

    while (current <= maximum) {
        if (shouldCancel()) {
            stats.cancelled = true;
            return false;
        }

        const SIZE_T queried = VirtualQueryEx(
            process, reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi));
        if (queried == 0) {
            const std::uintptr_t step = (std::max)(
                static_cast<std::uintptr_t>(systemInfo.dwPageSize), std::uintptr_t{1});
            if (step > maximum - current) break;
            current += step;
            continue;
        }

        const auto regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        if (mbi.RegionSize == 0 ||
            regionBase > (std::numeric_limits<std::uintptr_t>::max)() - mbi.RegionSize) {
            break;
        }
        const std::uintptr_t regionEnd = regionBase + mbi.RegionSize; // exclusive

        const std::uintptr_t clippedBase = (std::max)(regionBase, current);
        std::uintptr_t clippedEnd = regionEnd;
        if (maximum != (std::numeric_limits<std::uintptr_t>::max)()) {
            clippedEnd = (std::min)(clippedEnd, maximum + 1);
        }

        if (clippedBase < clippedEnd && regionAllowed(mbi, options)) {
            for (std::uintptr_t chunkBase = clippedBase; chunkBase < clippedEnd;) {
                if (shouldCancel()) {
                    stats.cancelled = true;
                    return false;
                }

                const SIZE_T remaining = static_cast<SIZE_T>(clippedEnd - chunkBase);
                const SIZE_T primarySize = (std::min)(kChunkSize, remaining);
                if (primarySize == 0) break;
                const SIZE_T readSize = (std::min)(
                    remaining,
                    primarySize + static_cast<SIZE_T>(overlapBytes));
                if (buffer.size() < readSize) buffer.resize(readSize);

                SIZE_T bytesRead = 0;
                const BOOL ok = ReadProcessMemory(
                    process, reinterpret_cast<LPCVOID>(chunkBase),
                    buffer.data(), readSize, &bytesRead);

                if (bytesRead > 0) {
                    ++stats.regionsRead;
                    stats.bytesRead += static_cast<std::uint64_t>(bytesRead);
                    const std::size_t starts = static_cast<std::size_t>((std::min)(primarySize, bytesRead));
                    if (!callback(chunkBase, buffer.data(), static_cast<std::size_t>(bytesRead), starts)) {
                        progress();
                        return false;
                    }
                    progress();
                    if (shouldCancel()) {
                        stats.cancelled = true;
                        return false;
                    }
                }

                // A partial/failed large read can hide readable pages later in the chunk.
                // Retry only the unprocessed primary range, page by page, with the same overlap.
                if ((!ok || bytesRead < readSize) && bytesRead < primarySize) {
                    SIZE_T retryOffset = bytesRead;
                    while (retryOffset < primarySize) {
                        if (shouldCancel()) {
                            stats.cancelled = true;
                            return false;
                        }

                        const SIZE_T pagePrimary = (std::min)(pageSize, primarySize - retryOffset);
                        const std::uintptr_t pageBase = chunkBase + retryOffset;
                        const SIZE_T pageRemaining = static_cast<SIZE_T>(clippedEnd - pageBase);
                        const SIZE_T pageReadSize = (std::min)(
                            pageRemaining,
                            pagePrimary + static_cast<SIZE_T>(overlapBytes));
                        if (buffer.size() < pageReadSize) buffer.resize(pageReadSize);

                        SIZE_T pageBytes = 0;
                        ReadProcessMemory(
                            process,
                            reinterpret_cast<LPCVOID>(pageBase),
                            buffer.data(), pageReadSize, &pageBytes);
                        if (pageBytes > 0) {
                            ++stats.regionsRead;
                            stats.bytesRead += static_cast<std::uint64_t>(pageBytes);
                            const std::size_t starts = static_cast<std::size_t>((std::min)(pagePrimary, pageBytes));
                            if (!callback(pageBase, buffer.data(), static_cast<std::size_t>(pageBytes), starts)) {
                                progress();
                                return false;
                            }
                            progress();
                        }
                        retryOffset += pagePrimary;
                    }
                }

                chunkBase += primarySize;
            }
        }

        if (regionEnd <= current) break;
        if (regionEnd > maximum) break;
        current = regionEnd;
    }
    return true;
}

template <typename T>
std::optional<T> typedWanted(const std::optional<Value>& wanted) {
    if (!wanted) return std::nullopt;
    if (const auto* value = std::get_if<T>(&*wanted)) return *value;
    return std::nullopt;
}

} // namespace

MemoryScanner::~MemoryScanner() {
    closeSnapshotBacking();
}

bool MemoryScanner::openSnapshotBacking() {
    if (snapshotFile_ != INVALID_HANDLE_VALUE) return true;

    wchar_t tempDir[MAX_PATH]{};
    wchar_t tempPath[MAX_PATH]{};
    const DWORD dirLength = GetTempPathW(MAX_PATH, tempDir);
    if (dirLength == 0 || dirLength >= MAX_PATH) return false;
    if (GetTempFileNameW(tempDir, L"MCE", 0, tempPath) == 0) return false;

    const HANDLE file = CreateFileW(
        tempPath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        DeleteFileW(tempPath);
        return false;
    }

    snapshotFile_ = file;
    snapshotFileBytes_ = 0;
    return true;
}

void MemoryScanner::closeSnapshotBacking() noexcept {
    if (snapshotFile_ != INVALID_HANDLE_VALUE) {
        CloseHandle(snapshotFile_);
        snapshotFile_ = INVALID_HANDLE_VALUE;
    }
    snapshotFileBytes_ = 0;
}

void MemoryScanner::clearSnapshotStorage() noexcept {
    snapshot_.clear();
    closeSnapshotBacking();
}

bool MemoryScanner::readSnapshotBytes(std::uint64_t offset, void* data, std::size_t size) const {
    if (size == 0) return true;
    if (snapshotFile_ == INVALID_HANDLE_VALUE || !data) return false;
    if (offset > static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)())) return false;

    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(snapshotFile_, position, nullptr, FILE_BEGIN)) return false;

    auto* output = static_cast<std::byte*>(data);
    std::size_t remaining = size;
    while (remaining != 0) {
        const DWORD chunk = static_cast<DWORD>((std::min<std::size_t>)(remaining, 1ull << 30));
        DWORD read = 0;
        if (!ReadFile(snapshotFile_, output, chunk, &read, nullptr) || read != chunk) return false;
        output += read;
        remaining -= read;
    }
    return true;
}

bool MemoryScanner::writeSnapshotBytes(std::uint64_t offset, const void* data, std::size_t size) const {
    if (size == 0) return true;
    if (snapshotFile_ == INVALID_HANDLE_VALUE || !data) return false;
    if (offset > static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)())) return false;

    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(snapshotFile_, position, nullptr, FILE_BEGIN)) return false;

    const auto* input = static_cast<const std::byte*>(data);
    std::size_t remaining = size;
    while (remaining != 0) {
        const DWORD chunk = static_cast<DWORD>((std::min<std::size_t>)(remaining, 1ull << 30));
        DWORD written = 0;
        if (!WriteFile(snapshotFile_, input, chunk, &written, nullptr) || written != chunk) return false;
        input += written;
        remaining -= written;
    }
    return true;
}

bool MemoryScanner::appendSnapshotBytes(const void* data, std::size_t size, std::uint64_t& offsetOut) {
    if (!openSnapshotBacking()) return false;
    if (size > (std::numeric_limits<std::uint64_t>::max)() - snapshotFileBytes_) return false;
    offsetOut = snapshotFileBytes_;
    if (!writeSnapshotBytes(offsetOut, data, size)) return false;
    snapshotFileBytes_ += static_cast<std::uint64_t>(size);
    return true;
}

void MemoryScanner::setProcess(HANDLE process) {
    process_ = process;
    clear();
}

void MemoryScanner::clear() {
    results_.clear();
    clearSnapshotStorage();
    hasScan_ = false;
    unknownSnapshotActive_ = false;
    unknownSnapshotSourceTruncated_ = false;
    mixedScanActive_ = false;
    unknownCandidateCount_ = 0;
    refinementHistory_.clear();
    resetCancel();
}

void MemoryScanner::setOptions(const ScanOptions& options) {
    ScanOptions normalized = options;
    if (!std::isfinite(normalized.floatTolerance) || normalized.floatTolerance < 0.0) {
        normalized.floatTolerance = 0.0;
    }
    options_ = normalized;
    clear();
}

bool MemoryScanner::restoreMaterializedScan(
    ValueType primaryType,
    bool mixed,
    const ScanOptions& options,
    std::vector<ScanResult> results)
{
    ScanOptions normalized = options;
    if (!std::isfinite(normalized.floatTolerance) || normalized.floatTolerance < 0.0) {
        normalized.floatTolerance = 0.0;
    }
    if (normalized.minAddress > normalized.maxAddress) return false;

    for (const auto& result : results) {
        if (valueTypeSize(result.type) == 0) return false;
        if (!mixed && result.type != primaryType) return false;
    }

    type_ = primaryType;
    options_ = normalized;
    results_ = std::move(results);
    clearSnapshotStorage();
    hasScan_ = true;
    unknownSnapshotActive_ = false;
    unknownSnapshotSourceTruncated_ = false;
    mixedScanActive_ = mixed;
    unknownCandidateCount_ = results_.size();
    refinementHistory_.clear();
    resetCancel();
    return true;
}

void MemoryScanner::setProgressCallback(ProgressCallback callback) {
    progressCallback_ = std::move(callback);
}

void MemoryScanner::reportProgress(const ScanStats& stats, std::size_t resultCount) const {
    if (progressCallback_) {
        progressCallback_(ScanProgress{stats.bytesRead, stats.regionsRead, resultCount});
    }
}

std::size_t MemoryScanner::candidateCount() const noexcept {
    return unknownSnapshotActive_ ? unknownCandidateCount_ : results_.size();
}

std::array<std::size_t, 6> MemoryScanner::candidateCountsByType() const noexcept {
    std::array<std::size_t, 6> counts{};
    const auto add = [](std::size_t& total, std::size_t value) {
        const auto max = (std::numeric_limits<std::size_t>::max)();
        total = value > max - total ? max : total + value;
    };

    if (unknownSnapshotActive_) {
        for (const auto& block : snapshot_) {
            for (std::size_t i = 0; i < kValueTypeCount; ++i) {
                add(counts[i], block.candidates[i].activeCount);
            }
        }
        return counts;
    }

    if (mixedScanActive_) {
        for (const auto& result : results_) {
            const auto index = valueTypeIndex(result.type);
            if (index < counts.size()) add(counts[index], 1);
        }
        return counts;
    }

    if (hasScan_) {
        const auto index = valueTypeIndex(type_);
        if (index < counts.size()) counts[index] = results_.size();
    }
    return counts;
}

void MemoryScanner::recordRefinementStep(
    ScanMode mode,
    std::size_t beforeCount,
    const std::array<std::size_t, 6>& beforeByType,
    const ScanStats& stats)
{
    if (!hasScan_ || stats.cancelled) return;
    constexpr std::size_t kMaxHistory = 128;
    if (refinementHistory_.size() >= kMaxHistory) {
        refinementHistory_.erase(refinementHistory_.begin());
    }
    ScanRefinementStep step;
    step.mode = mode;
    step.beforeCount = beforeCount;
    step.afterCount = candidateCount();
    step.beforeByType = beforeByType;
    step.afterByType = candidateCountsByType();
    step.elapsedMs = stats.elapsedMs;
    refinementHistory_.push_back(std::move(step));
}

std::optional<GuidedWizardSuggestion> MemoryScanner::guidedSuggestion(GuidedGoal goal) const noexcept {
    if (!hasScan_) return std::nullopt;

    GuidedWizardSuggestion suggestion;
    suggestion.candidateCount = candidateCount();
    suggestion.refinementDepth = refinementHistory_.size();
    suggestion.snapshotActive = unknownSnapshotActive_;
    suggestion.rankingAvailable = !unknownSnapshotActive_ && !results_.empty();
    suggestion.inspectRecommended = suggestion.rankingAvailable && suggestion.candidateCount <= 100'000;

    const auto lastMode = refinementHistory_.empty()
        ? std::optional<ScanMode>{}
        : std::optional<ScanMode>{refinementHistory_.back().mode};

    if (goal == GuidedGoal::Generic) {
        suggestion.recommendedMode = !lastMode || *lastMode == ScanMode::Unchanged
            ? ScanMode::Changed
            : ScanMode::Unchanged;
        return suggestion;
    }

    if (!lastMode) {
        suggestion.recommendedMode = ScanMode::Decreased;
        return suggestion;
    }
    if (*lastMode != ScanMode::Unchanged) {
        suggestion.recommendedMode = ScanMode::Unchanged;
        return suggestion;
    }

    std::optional<ScanMode> lastDirectional;
    for (auto it = refinementHistory_.rbegin(); it != refinementHistory_.rend(); ++it) {
        if (it->mode == ScanMode::Decreased || it->mode == ScanMode::Increased) {
            lastDirectional = it->mode;
            break;
        }
    }
    suggestion.recommendedMode = lastDirectional && *lastDirectional == ScanMode::Decreased
        ? ScanMode::Increased
        : ScanMode::Decreased;
    return suggestion;
}

std::vector<RankedScanResult> MemoryScanner::rankedResults(std::size_t limit, GuidedGoal goal) const {
    std::vector<RankedScanResult> best;
    if (limit == 0 || !process_ || unknownSnapshotActive_ || results_.empty()) return best;
    limit = (std::min)(limit, results_.size());
    best.reserve(limit);

    auto better = [&](const RankedScanResult& a, const RankedScanResult& b) {
        if (a.score != b.score) return a.score > b.score;
        const auto& ar = results_[a.resultIndex];
        const auto& br = results_[b.resultIndex];
        if (ar.address != br.address) return ar.address < br.address;
        if (ar.type != br.type) return static_cast<int>(ar.type) < static_cast<int>(br.type);
        return a.resultIndex < b.resultIndex;
    };

    MEMORY_BASIC_INFORMATION cached{};
    std::uintptr_t cachedBegin = 0;
    std::uintptr_t cachedEnd = 0;
    bool cachedValid = false;

    for (std::size_t i = 0; i < results_.size(); ++i) {
        const auto address = results_[i].address;
        if (!cachedValid || address < cachedBegin || address >= cachedEnd) {
            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T queried = VirtualQueryEx(
                process_, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
            if (queried != 0 && mbi.RegionSize != 0) {
                cached = mbi;
                cachedBegin = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                if (cachedBegin <= (std::numeric_limits<std::uintptr_t>::max)() - mbi.RegionSize) {
                    cachedEnd = cachedBegin + mbi.RegionSize;
                    cachedValid = address >= cachedBegin && address < cachedEnd;
                } else {
                    cachedEnd = (std::numeric_limits<std::uintptr_t>::max)();
                    cachedValid = address >= cachedBegin;
                }
            } else {
                cachedValid = false;
            }
        }

        RankedScanResult ranked;
        ranked.resultIndex = i;
        ranked.score = rankingTypeScore(results_[i].type) + rankingValueScore(results_[i]) +
            rankingGoalTypeScore(results_[i].type, goal) + rankingGoalValueScore(results_[i], goal) +
            rankingIsolationScore(results_, i);
        if (cachedValid) {
            ranked.privateMemory = cached.Type == MEM_PRIVATE;
            ranked.writable = writableProtection(cached.Protect);
            ranked.executable = executableProtection(cached.Protect);
            if (ranked.privateMemory) ranked.score += 50;
            if (ranked.writable) ranked.score += 30;
            if (!ranked.executable) ranked.score += 10;
        }

        if (best.size() < limit) {
            best.push_back(ranked);
            std::push_heap(best.begin(), best.end(), better);
        } else if (better(ranked, best.front())) {
            std::pop_heap(best.begin(), best.end(), better);
            best.back() = ranked;
            std::push_heap(best.begin(), best.end(), better);
        }
    }

    std::sort(best.begin(), best.end(), better);
    return best;
}

bool MemoryScanner::disableMixedType(ValueType type) {
    if (!hasScan_ || !mixedScanActive_) return false;
    const auto index = valueTypeIndex(type);
    if (index >= kValueTypeCount) return false;

    bool changed = false;
    if (unknownSnapshotActive_) {
        for (auto& block : snapshot_) {
            auto& candidates = block.candidates[index];
            if (candidates.activeCount == 0) continue;
            candidates.activeCount = 0;
            candidates.mode = SnapshotMaskMode::None;
            candidates.bits.clear();
            changed = true;
        }
        if (changed) {
            unknownCandidateCount_ = 0;
            const auto counts = candidateCountsByType();
            for (const auto count : counts) {
                const auto max = (std::numeric_limits<std::size_t>::max)();
                unknownCandidateCount_ = count > max - unknownCandidateCount_ ? max : unknownCandidateCount_ + count;
            }
        }
        return changed;
    }

    const auto oldSize = results_.size();
    results_.erase(std::remove_if(results_.begin(), results_.end(), [&](const ScanResult& result) {
        return result.type == type;
    }), results_.end());
    changed = results_.size() != oldSize;
    unknownCandidateCount_ = results_.size();
    return changed;
}

ScanStats MemoryScanner::firstScan(ValueType type, const Value& wanted) {
    refinementHistory_.clear();
    type_ = type;
    if (!valueMatchesType(type, wanted)) {
        clear();
        return {};
    }

    return std::visit([&](const auto& typedValue) -> ScanStats {
        using T = std::decay_t<decltype(typedValue)>;
        if (!isType<T>(type)) return {};
        return firstScanTyped<T>(typedValue);
    }, wanted);
}

ScanStats MemoryScanner::firstScanUnknown(ValueType type) {
    refinementHistory_.clear();
    type_ = type;
    switch (type) {
        case ValueType::Byte: return firstScanUnknownTyped<std::uint8_t>(options_);
        case ValueType::Int16: return firstScanUnknownTyped<std::int16_t>(options_);
        case ValueType::Int32: return firstScanUnknownTyped<std::int32_t>(options_);
        case ValueType::Int64: return firstScanUnknownTyped<std::int64_t>(options_);
        case ValueType::Float: return firstScanUnknownTyped<float>(options_);
        case ValueType::Double: return firstScanUnknownTyped<double>(options_);
    }
    return {};
}

ScanStats MemoryScanner::firstScanUnknownSmart(ValueType type) {
    refinementHistory_.clear();
    ScanOptions sourceOptions = options_;
    sourceOptions.writableOnly = true;
    sourceOptions.privateOnly = true;
    type_ = type;
    switch (type) {
        case ValueType::Byte: return firstScanUnknownTyped<std::uint8_t>(sourceOptions);
        case ValueType::Int16: return firstScanUnknownTyped<std::int16_t>(sourceOptions);
        case ValueType::Int32: return firstScanUnknownTyped<std::int32_t>(sourceOptions);
        case ValueType::Int64: return firstScanUnknownTyped<std::int64_t>(sourceOptions);
        case ValueType::Float: return firstScanUnknownTyped<float>(sourceOptions);
        case ValueType::Double: return firstScanUnknownTyped<double>(sourceOptions);
    }
    return {};
}

ScanStats MemoryScanner::firstScanAllExact(const std::string& text) {
    refinementHistory_.clear();
    ScanStats stats{};
    results_.clear();
    clearSnapshotStorage();
    hasScan_ = false;
    unknownSnapshotActive_ = false;
    unknownSnapshotSourceTruncated_ = false;
    mixedScanActive_ = false;
    unknownCandidateCount_ = 0;
    resetCancel();
    if (!process_) return stats;

    const auto targets = parseAllCompatibleValues(text);
    if (targets.empty()) return stats;

    const auto started = std::chrono::steady_clock::now();
    try {
        visitReadableMemory(
            process_, options_, 7, stats,
            [&] { return cancelRequested(); },
            [&] { reportProgress(stats, results_.size()); },
            [&](std::uintptr_t base, const std::byte* data, std::size_t size, std::size_t candidateBytes) {
                for (const auto& [type, wantedValue] : targets) {
                    bool keepGoing = true;
                    std::visit([&](const auto& wanted) {
                        using T = std::decay_t<decltype(wanted)>;
                        if (!isType<T>(type)) return;
                        const std::size_t alignment = options_.alignment == AlignmentMode::Byte ? 1u : sizeof(T);
                        keepGoing = visitCandidates<T>(
                            base, data, size, candidateBytes, alignment,
                            [&](std::uintptr_t address, T current) {
                                if (!scanMatches(ScanMode::Exact, current, T{}, std::optional<T>{wanted}, options_.floatTolerance)) {
                                    return true;
                                }
                                if (results_.size() >= kMaxResults) {
                                    stats.truncated = true;
                                    return false;
                                }
                                results_.push_back(ScanResult{address, packScanValue(current), type});
                                return true;
                            });
                    }, wantedValue);
                    if (!keepGoing || stats.truncated) return false;
                }
                return true;
            });
    } catch (const std::bad_alloc&) {
        stats.truncated = true;
    }

    std::sort(results_.begin(), results_.end(), [](const ScanResult& a, const ScanResult& b) {
        if (a.address != b.address) return a.address < b.address;
        return static_cast<int>(a.type) < static_cast<int>(b.type);
    });
    hasScan_ = true;
    mixedScanActive_ = true;
    stats.resultCount = results_.size();
    stats.elapsedMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    return stats;
}


ScanStats MemoryScanner::firstScanAllUnknown() {
    return firstScanAllUnknownWithOptions(options_);
}

ScanStats MemoryScanner::firstScanAllUnknownSmart() {
    ScanOptions sourceOptions = options_;
    sourceOptions.writableOnly = true;
    sourceOptions.privateOnly = true;
    return firstScanAllUnknownWithOptions(sourceOptions);
}

ScanStats MemoryScanner::firstScanAllUnknownWithOptions(const ScanOptions& sourceOptions) {
    refinementHistory_.clear();
    ScanStats stats{};
    results_.clear();
    clearSnapshotStorage();
    hasScan_ = false;
    unknownSnapshotActive_ = false;
    unknownSnapshotSourceTruncated_ = false;
    mixedScanActive_ = false;
    unknownCandidateCount_ = 0;
    resetCancel();
    if (!process_) return stats;

    const auto started = std::chrono::steady_clock::now();
    bool storageFailed = false;

    const auto saturatingAdd = [&](std::size_t value) {
        const auto max = (std::numeric_limits<std::size_t>::max)();
        if (value > max - unknownCandidateCount_) unknownCandidateCount_ = max;
        else unknownCandidateCount_ += value;
    };

    try {
        visitReadableMemory(
            process_, sourceOptions, 7, stats,
            [&] { return cancelRequested(); },
            [&] { reportProgress(stats, unknownCandidateCount_); },
            [&](std::uintptr_t base, const std::byte* data, std::size_t size, std::size_t candidateBytes) {
                SnapshotBlock block;
                block.base = base;
                block.size = size;
                block.candidateBytes = (std::min)(candidateBytes, size);
                if (!appendSnapshotBytes(data, size, block.fileOffset)) {
                    storageFailed = true;
                    return false;
                }

                const auto countFor = [&](ValueType type, auto dummy) {
                    using T = decltype(dummy);
                    const std::size_t alignment = sourceOptions.alignment == AlignmentMode::Byte ? 1u : sizeof(T);
                    const std::size_t count = alignedCandidateCount<T>(
                        base, size, block.candidateBytes, alignment);
                    auto& candidates = block.candidates[valueTypeIndex(type)];
                    candidates.candidateCount = count;
                    candidates.activeCount = count;
                    candidates.mode = count ? SnapshotMaskMode::All : SnapshotMaskMode::None;
                    saturatingAdd(count);
                };
                countFor(ValueType::Byte, std::uint8_t{});
                countFor(ValueType::Int16, std::int16_t{});
                countFor(ValueType::Int32, std::int32_t{});
                countFor(ValueType::Int64, std::int64_t{});
                countFor(ValueType::Float, float{});
                countFor(ValueType::Double, double{});

                snapshot_.push_back(std::move(block));
                return true;
            });
    } catch (const std::bad_alloc&) {
        storageFailed = true;
        stats.truncated = true;
    }

    if (storageFailed || stats.cancelled) {
        const bool cancelled = stats.cancelled;
        clear();
        stats.cancelled = cancelled;
        stats.truncated = storageFailed;
        stats.resultCount = 0;
        stats.elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
        return stats;
    }

    hasScan_ = true;
    unknownSnapshotActive_ = true;
    unknownSnapshotSourceTruncated_ = false;
    mixedScanActive_ = true;
    stats.resultCount = unknownCandidateCount_;
    stats.elapsedMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    return stats;
}

ScanStats MemoryScanner::nextScan(const Value& wanted) {
    return nextScan(ScanMode::Exact, wanted);
}

ScanStats MemoryScanner::nextScan(ScanMode mode, const std::optional<Value>& wanted) {
    if (!hasScan_ || mixedScanActive_) return {};
    if (scanModeNeedsValue(mode)) {
        if (!wanted || !valueMatchesType(type_, *wanted)) return {};
    } else if (wanted && !valueMatchesType(type_, *wanted)) {
        return {};
    }

    const std::size_t beforeCount = candidateCount();
    const auto beforeByType = candidateCountsByType();
    ScanStats stats{};
    switch (type_) {
        case ValueType::Byte: {
            const auto tw = typedWanted<std::uint8_t>(wanted);
            stats = unknownSnapshotActive_ ? nextScanFromSnapshotTyped<std::uint8_t>(mode, tw)
                                           : nextScanTyped<std::uint8_t>(mode, tw);
            break;
        }
        case ValueType::Int16: {
            const auto tw = typedWanted<std::int16_t>(wanted);
            stats = unknownSnapshotActive_ ? nextScanFromSnapshotTyped<std::int16_t>(mode, tw)
                                           : nextScanTyped<std::int16_t>(mode, tw);
            break;
        }
        case ValueType::Int32: {
            const auto tw = typedWanted<std::int32_t>(wanted);
            stats = unknownSnapshotActive_ ? nextScanFromSnapshotTyped<std::int32_t>(mode, tw)
                                           : nextScanTyped<std::int32_t>(mode, tw);
            break;
        }
        case ValueType::Int64: {
            const auto tw = typedWanted<std::int64_t>(wanted);
            stats = unknownSnapshotActive_ ? nextScanFromSnapshotTyped<std::int64_t>(mode, tw)
                                           : nextScanTyped<std::int64_t>(mode, tw);
            break;
        }
        case ValueType::Float: {
            const auto tw = typedWanted<float>(wanted);
            stats = unknownSnapshotActive_ ? nextScanFromSnapshotTyped<float>(mode, tw)
                                           : nextScanTyped<float>(mode, tw);
            break;
        }
        case ValueType::Double: {
            const auto tw = typedWanted<double>(wanted);
            stats = unknownSnapshotActive_ ? nextScanFromSnapshotTyped<double>(mode, tw)
                                           : nextScanTyped<double>(mode, tw);
            break;
        }
    }
    recordRefinementStep(mode, beforeCount, beforeByType, stats);
    return stats;
}

ScanStats MemoryScanner::nextScanMixed(ScanMode mode, const std::optional<std::string>& wantedText) {
    if (!hasScan_ || !mixedScanActive_) return {};
    std::vector<std::pair<ValueType, Value>> wantedByType;
    if (scanModeNeedsValue(mode)) {
        if (!wantedText) return {};
        wantedByType = parseAllCompatibleValues(*wantedText);
        if (wantedByType.empty()) return {};
    } else if (wantedText) {
        wantedByType = parseAllCompatibleValues(*wantedText);
    }
    const std::size_t beforeCount = candidateCount();
    const auto beforeByType = candidateCountsByType();
    ScanStats stats = unknownSnapshotActive_
        ? nextScanMixedFromSnapshot(mode, wantedByType)
        : nextScanMixedInternal(mode, wantedByType);
    recordRefinementStep(mode, beforeCount, beforeByType, stats);
    return stats;
}

ScanStats MemoryScanner::nextScanMixedFromSnapshot(
    ScanMode mode,
    const std::vector<std::pair<ValueType, Value>>& wantedByType)
{
    ScanStats stats{};
    resetCancel();
    if (!process_) return stats;

    const auto started = std::chrono::steady_clock::now();
    results_.clear();

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    const SIZE_T pageSize = (std::max)(static_cast<SIZE_T>(systemInfo.dwPageSize), SIZE_T{1});

    auto wantedFor = [&](ValueType type) -> std::optional<Value> {
        for (const auto& [candidateType, value] : wantedByType) {
            if (candidateType == type) return value;
        }
        return std::nullopt;
    };
    auto candidateActive = [&](const SnapshotCandidates& candidates, std::size_t index) {
        if (index >= candidates.candidateCount) return false;
        if (candidates.mode == SnapshotMaskMode::All) return true;
        return candidates.mode == SnapshotMaskMode::Explicit && snapshotBitSet(candidates.bits, index);
    };
    auto recordCandidate = [&](SnapshotCandidates& candidates, std::size_t index) {
        if (candidates.mode != SnapshotMaskMode::Explicit) {
            candidates.bits.assign((candidates.candidateCount + 63) / 64, 0);
            candidates.mode = SnapshotMaskMode::Explicit;
        }
        if (!snapshotBitSet(candidates.bits, index)) {
            setSnapshotBit(candidates.bits, index);
            ++candidates.activeCount;
        }
    };
    auto normalizeCandidates = [&](SnapshotCandidates& candidates) {
        if (candidates.activeCount == 0) {
            candidates.mode = SnapshotMaskMode::None;
            candidates.bits.clear();
        } else if (candidates.activeCount == candidates.candidateCount) {
            candidates.mode = SnapshotMaskMode::All;
            candidates.bits.clear();
        }
    };
    const auto saturatingAdd = [](std::size_t& total, std::size_t value) {
        const auto max = (std::numeric_limits<std::size_t>::max)();
        total = value > max - total ? max : total + value;
    };

    std::size_t survivors = 0;
    bool storageFailed = false;
    try {
        for (auto& block : snapshot_) {
            if (cancelRequested()) {
                stats.cancelled = true;
                break;
            }
            if (block.size == 0 || block.candidateBytes == 0) continue;

            std::vector<std::byte> snapshotBytes(block.size);
            if (!readSnapshotBytes(block.fileOffset, snapshotBytes.data(), snapshotBytes.size())) {
                storageFailed = true;
                break;
            }
            std::vector<std::byte> current = snapshotBytes;
            std::vector<std::pair<std::size_t, std::size_t>> readableSegments;

            SIZE_T bytesRead = 0;
            const BOOL ok = ReadProcessMemory(
                process_, reinterpret_cast<LPCVOID>(block.base),
                current.data(), block.size, &bytesRead);
            ++stats.regionsRead;
            stats.bytesRead += static_cast<std::uint64_t>(bytesRead);
            if (bytesRead > 0) {
                readableSegments.emplace_back(0, static_cast<std::size_t>(bytesRead));
            }

            if ((!ok || bytesRead < block.size) && bytesRead < block.size) {
                SIZE_T offset = bytesRead;
                while (offset < block.size) {
                    if (cancelRequested()) {
                        stats.cancelled = true;
                        break;
                    }
                    const SIZE_T request = (std::min)(pageSize, block.size - offset);
                    SIZE_T pageBytes = 0;
                    ReadProcessMemory(
                        process_, reinterpret_cast<LPCVOID>(block.base + offset),
                        current.data() + offset, request, &pageBytes);
                    ++stats.regionsRead;
                    stats.bytesRead += static_cast<std::uint64_t>(pageBytes);
                    if (pageBytes > 0) {
                        readableSegments.emplace_back(
                            static_cast<std::size_t>(offset), static_cast<std::size_t>(pageBytes));
                    }
                    offset += request;
                }
                if (stats.cancelled) break;
            }

            const bool fullEqual = ok && bytesRead == block.size &&
                std::memcmp(current.data(), snapshotBytes.data(), block.size) == 0;
            std::array<SnapshotCandidates, kValueTypeCount> nextCandidates{};
            std::array<bool, kValueTypeCount> preserve{};
            std::array<bool, kValueTypeCount> evaluate{};

            for (std::size_t typeIndex = 0; typeIndex < kValueTypeCount; ++typeIndex) {
                const auto& oldCandidates = block.candidates[typeIndex];
                nextCandidates[typeIndex].candidateCount = oldCandidates.candidateCount;
                if (oldCandidates.activeCount == 0) continue;

                const ValueType type = valueTypeFromIndex(typeIndex);
                const auto wanted = wantedFor(type);
                if (scanModeNeedsValue(mode) && !wanted) continue;

                if (fullEqual && mode == ScanMode::Unchanged) {
                    preserve[typeIndex] = true;
                } else if (fullEqual &&
                           (mode == ScanMode::Changed || mode == ScanMode::Increased || mode == ScanMode::Decreased)) {
                    // Exact byte equality proves there are no survivors for these modes.
                } else {
                    evaluate[typeIndex] = true;
                }
            }

            for (const auto& [segmentOffset, segmentSize] : readableSegments) {
                if (segmentOffset >= block.candidateBytes) continue;
                const std::uintptr_t segmentBase = block.base + segmentOffset;
                const std::size_t segmentCandidateBytes = (std::min)(
                    segmentSize, block.candidateBytes - segmentOffset);

                for (std::size_t typeIndex = 0; typeIndex < kValueTypeCount; ++typeIndex) {
                    if (!evaluate[typeIndex]) continue;
                    const ValueType type = valueTypeFromIndex(typeIndex);
                    const auto wanted = wantedFor(type);
                    auto& next = nextCandidates[typeIndex];
                    const auto& old = block.candidates[typeIndex];

                    const auto evaluateTyped = [&](auto dummy) {
                        using T = decltype(dummy);
                        const std::size_t alignment = options_.alignment == AlignmentMode::Byte ? 1u : sizeof(T);
                        const std::size_t firstOffset = alignedStartOffset(block.base, alignment);
                        visitCandidates<T>(
                            segmentBase, current.data() + segmentOffset,
                            segmentSize, segmentCandidateBytes, alignment,
                            [&](std::uintptr_t address, T now) {
                                const std::size_t blockOffset = static_cast<std::size_t>(address - block.base);
                                if (blockOffset < firstOffset || blockOffset + sizeof(T) > block.size) return true;
                                const std::size_t delta = blockOffset - firstOffset;
                                if (delta % alignment != 0) return true;
                                const std::size_t candidateIndex = delta / alignment;
                                if (!candidateActive(old, candidateIndex)) return true;

                                T previous{};
                                std::memcpy(&previous, snapshotBytes.data() + blockOffset, sizeof(T));
                                std::optional<T> typedWanted;
                                if (wanted) {
                                    if (const auto* p = std::get_if<T>(&*wanted)) typedWanted = *p;
                                    else return true;
                                }
                                if (scanMatches(mode, now, previous, typedWanted, options_.floatTolerance)) {
                                    recordCandidate(next, candidateIndex);
                                }
                                return true;
                            });
                    };

                    switch (type) {
                        case ValueType::Byte: evaluateTyped(std::uint8_t{}); break;
                        case ValueType::Int16: evaluateTyped(std::int16_t{}); break;
                        case ValueType::Int32: evaluateTyped(std::int32_t{}); break;
                        case ValueType::Int64: evaluateTyped(std::int64_t{}); break;
                        case ValueType::Float: evaluateTyped(float{}); break;
                        case ValueType::Double: evaluateTyped(double{}); break;
                    }
                }
            }

            for (std::size_t typeIndex = 0; typeIndex < kValueTypeCount; ++typeIndex) {
                if (!preserve[typeIndex]) {
                    normalizeCandidates(nextCandidates[typeIndex]);
                    block.candidates[typeIndex] = std::move(nextCandidates[typeIndex]);
                }
                saturatingAdd(survivors, block.candidates[typeIndex].activeCount);
            }
            if (!fullEqual && !writeSnapshotBytes(block.fileOffset, current.data(), block.size)) {
                storageFailed = true;
                break;
            }
            reportProgress(stats, survivors);
        }
    } catch (const std::bad_alloc&) {
        stats.truncated = true;
        clear();
        stats.resultCount = 0;
        stats.elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
        return stats;
    }

    if (storageFailed) {
        clear();
        stats.truncated = true;
        stats.resultCount = 0;
        stats.elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
        return stats;
    }

    if (stats.cancelled) {
        clear();
        stats.resultCount = 0;
        stats.elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
        return stats;
    }

    unknownCandidateCount_ = survivors;
    if (survivors <= kMaxResults) {
        try {
            results_.reserve(survivors);
            const auto materializeType = [&](const SnapshotBlock& block, const std::vector<std::byte>& blockBytes, ValueType type) {
                const std::size_t typeIndex = valueTypeIndex(type);
                const auto& candidates = block.candidates[typeIndex];
                if (candidates.activeCount == 0) return;

                const auto materializeTyped = [&](auto dummy) {
                    using T = decltype(dummy);
                    const std::size_t alignment = options_.alignment == AlignmentMode::Byte ? 1u : sizeof(T);
                    const std::size_t firstOffset = alignedStartOffset(block.base, alignment);
                    auto emit = [&](std::size_t candidateIndex) {
                        const std::size_t offset = firstOffset + candidateIndex * alignment;
                        if (offset >= block.candidateBytes || offset + sizeof(T) > block.size) return;
                        T now{};
                        std::memcpy(&now, blockBytes.data() + offset, sizeof(T));
                        results_.push_back(ScanResult{block.base + offset, packScanValue(now), type});
                    };

                    if (candidates.mode == SnapshotMaskMode::All) {
                        for (std::size_t i = 0; i < candidates.candidateCount; ++i) emit(i);
                    } else if (candidates.mode == SnapshotMaskMode::Explicit) {
                        for (std::size_t wordIndex = 0; wordIndex < candidates.bits.size(); ++wordIndex) {
                            std::uint64_t word = candidates.bits[wordIndex];
                            for (unsigned bit = 0; word != 0; ++bit, word >>= 1) {
                                if ((word & 1u) != 0) emit(wordIndex * 64 + bit);
                            }
                        }
                    }
                };

                switch (type) {
                    case ValueType::Byte: materializeTyped(std::uint8_t{}); break;
                    case ValueType::Int16: materializeTyped(std::int16_t{}); break;
                    case ValueType::Int32: materializeTyped(std::int32_t{}); break;
                    case ValueType::Int64: materializeTyped(std::int64_t{}); break;
                    case ValueType::Float: materializeTyped(float{}); break;
                    case ValueType::Double: materializeTyped(double{}); break;
                }
            };

            std::vector<std::byte> blockBytes;
            for (const auto& block : snapshot_) {
                blockBytes.resize(block.size);
                if (!readSnapshotBytes(block.fileOffset, blockBytes.data(), blockBytes.size())) {
                    storageFailed = true;
                    break;
                }
                for (std::size_t typeIndex = 0; typeIndex < kValueTypeCount; ++typeIndex) {
                    materializeType(block, blockBytes, valueTypeFromIndex(typeIndex));
                }
            }
            if (storageFailed) {
                results_.clear();
                clear();
                stats.truncated = true;
                stats.resultCount = 0;
                stats.elapsedMs = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - started).count();
                return stats;
            }
        } catch (const std::bad_alloc&) {
            results_.clear();
            stats.truncated = true;
            stats.resultCount = unknownCandidateCount_;
            stats.elapsedMs = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - started).count();
            return stats;
        }

        std::sort(results_.begin(), results_.end(), [](const ScanResult& a, const ScanResult& b) {
            if (a.address != b.address) return a.address < b.address;
            return static_cast<int>(a.type) < static_cast<int>(b.type);
        });
        clearSnapshotStorage();
        unknownSnapshotActive_ = false;
        unknownCandidateCount_ = 0;
        stats.resultCount = results_.size();
    } else {
        stats.resultCount = survivors;
    }

    stats.elapsedMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    return stats;
}

ScanStats MemoryScanner::nextScanMixedInternal(
    ScanMode mode,
    const std::vector<std::pair<ValueType, Value>>& wantedByType)
{
    ScanStats stats{};
    resetCancel();
    if (!process_) return stats;

    const auto started = std::chrono::steady_clock::now();
    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    const std::uintptr_t pageSize = (std::max)(
        static_cast<std::uintptr_t>(systemInfo.dwPageSize), std::uintptr_t{1});

    auto wantedFor = [&](ValueType type) -> std::optional<Value> {
        for (const auto& [candidateType, value] : wantedByType) {
            if (candidateType == type) return value;
        }
        return std::nullopt;
    };

    auto resultSize = [](ValueType type) -> std::size_t {
        return valueTypeSize(type);
    };

    auto evaluateBytes = [&](const ScanResult& oldEntry, const std::byte* bytes, std::size_t available,
                             ScanResult& out) -> bool {
        const auto wanted = wantedFor(oldEntry.type);
        if (scanModeNeedsValue(mode) && !wanted) return false;

        auto eval = [&](auto dummy) -> bool {
            using T = decltype(dummy);
            if (available < sizeof(T)) return false;
            T current{};
            std::memcpy(&current, bytes, sizeof(T));
            const T previous = unpackScanValue<T>(oldEntry.previousBits);
            std::optional<T> typedWanted;
            if (wanted) {
                if (const auto* p = std::get_if<T>(&*wanted)) typedWanted = *p;
                else return false;
            }
            if (!scanMatches(mode, current, previous, typedWanted, options_.floatTolerance)) return false;
            out = ScanResult{oldEntry.address, packScanValue(current), oldEntry.type};
            return true;
        };

        switch (oldEntry.type) {
            case ValueType::Byte: return eval(std::uint8_t{});
            case ValueType::Int16: return eval(std::int16_t{});
            case ValueType::Int32: return eval(std::int32_t{});
            case ValueType::Int64: return eval(std::int64_t{});
            case ValueType::Float: return eval(float{});
            case ValueType::Double: return eval(double{});
        }
        return false;
    };

    std::size_t writeIndex = 0;
    std::vector<std::byte> buffer(pageSize + 8);
    std::size_t i = 0;
    while (i < results_.size()) {
        if (cancelRequested()) {
            stats.cancelled = true;
            break;
        }

        const auto pageBase = results_[i].address - (results_[i].address % pageSize);
        std::size_t j = i + 1;
        while (j < results_.size()) {
            const auto otherPage = results_[j].address - (results_[j].address % pageSize);
            if (otherPage != pageBase) break;
            ++j;
        }

        const std::uintptr_t readBase = results_[i].address;
        std::uintptr_t readEnd = readBase;
        for (std::size_t k = i; k < j; ++k) {
            const auto size = resultSize(results_[k].type);
            if (size == 0 || results_[k].address > (std::numeric_limits<std::uintptr_t>::max)() - size) continue;
            readEnd = (std::max)(readEnd, results_[k].address + size);
        }
        const SIZE_T request = readEnd > readBase ? static_cast<SIZE_T>(readEnd - readBase) : 0;
        if (request == 0) {
            i = j;
            continue;
        }
        if (buffer.size() < request) buffer.resize(request);

        SIZE_T bytesRead = 0;
        const BOOL ok = ReadProcessMemory(
            process_, reinterpret_cast<LPCVOID>(readBase), buffer.data(), request, &bytesRead);
        ++stats.regionsRead;
        stats.bytesRead += static_cast<std::uint64_t>(bytesRead);

        for (std::size_t k = i; k < j; ++k) {
            const ScanResult oldEntry = results_[k];
            const auto size = resultSize(oldEntry.type);
            const SIZE_T offset = static_cast<SIZE_T>(oldEntry.address - readBase);
            ScanResult updated{};
            bool matched = false;
            if (size > 0 && offset + size <= bytesRead) {
                matched = evaluateBytes(oldEntry, buffer.data() + offset, bytesRead - offset, updated);
            } else if (!ok || bytesRead < request) {
                std::array<std::byte, 8> small{};
                SIZE_T individualBytes = 0;
                ReadProcessMemory(
                    process_, reinterpret_cast<LPCVOID>(oldEntry.address), small.data(), size, &individualBytes);
                ++stats.regionsRead;
                stats.bytesRead += static_cast<std::uint64_t>(individualBytes);
                if (individualBytes == size) {
                    matched = evaluateBytes(oldEntry, small.data(), individualBytes, updated);
                }
            }
            if (matched) results_[writeIndex++] = updated;
        }

        i = j;
        reportProgress(stats, writeIndex);
        if (cancelRequested()) {
            stats.cancelled = true;
            break;
        }
    }

    results_.resize(writeIndex);
    stats.resultCount = results_.size();
    stats.elapsedMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    return stats;
}

template <typename T>
ScanStats MemoryScanner::firstScanTyped(T wanted) {
    ScanStats stats{};
    results_.clear();
    clearSnapshotStorage();
    unknownSnapshotActive_ = false;
    unknownSnapshotSourceTruncated_ = false;
    mixedScanActive_ = false;
    unknownCandidateCount_ = 0;
    hasScan_ = false;
    resetCancel();
    if (!process_) return stats;

    const auto started = std::chrono::steady_clock::now();
    const std::size_t alignment = alignmentForType<T>();
    try {
        visitReadableMemory(
            process_, options_, sizeof(T) - 1, stats,
            [&] { return cancelRequested(); },
            [&] { reportProgress(stats, results_.size()); },
            [&](std::uintptr_t base, const std::byte* data, std::size_t size, std::size_t candidateBytes) {
                return visitCandidates<T>(
                    base, data, size, candidateBytes, alignment,
                    [&](std::uintptr_t address, T current) {
                        if (!scanMatches(ScanMode::Exact, current, T{}, std::optional<T>{wanted}, options_.floatTolerance)) {
                            return true;
                        }
                        if (results_.size() >= kMaxResults) {
                            stats.truncated = true;
                            return false;
                        }
                        results_.push_back(ScanResult{address, packScanValue(current), type_});
                        return true;
                    });
            });
    } catch (const std::bad_alloc&) {
        stats.truncated = true;
    }

    hasScan_ = true;
    stats.resultCount = results_.size();
    stats.elapsedMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    return stats;
}

template <typename T>
ScanStats MemoryScanner::firstScanUnknownTyped(const ScanOptions& sourceOptions) {
    ScanStats stats{};
    results_.clear();
    clearSnapshotStorage();
    unknownSnapshotActive_ = false;
    unknownSnapshotSourceTruncated_ = false;
    mixedScanActive_ = false;
    unknownCandidateCount_ = 0;
    hasScan_ = false;
    resetCancel();
    if (!process_) return stats;

    const auto started = std::chrono::steady_clock::now();
    const std::size_t alignment = sourceOptions.alignment == AlignmentMode::Byte ? 1u : sizeof(T);
    bool storageFailed = false;

    try {
        visitReadableMemory(
            process_, sourceOptions, sizeof(T) - 1, stats,
            [&] { return cancelRequested(); },
            [&] { reportProgress(stats, unknownCandidateCount_); },
            [&](std::uintptr_t base, const std::byte* data, std::size_t size, std::size_t candidateBytes) {
                SnapshotBlock block;
                block.base = base;
                block.size = size;
                block.candidateBytes = (std::min)(candidateBytes, size);
                if (!appendSnapshotBytes(data, size, block.fileOffset)) {
                    storageFailed = true;
                    return false;
                }
                const std::size_t count = alignedCandidateCount<T>(
                    base, size, block.candidateBytes, alignment);
                auto& candidates = block.candidates[valueTypeIndex(type_)];
                candidates.candidateCount = count;
                candidates.activeCount = count;
                candidates.mode = count ? SnapshotMaskMode::All : SnapshotMaskMode::None;
                unknownCandidateCount_ += count;
                snapshot_.push_back(std::move(block));
                return true;
            });
    } catch (const std::bad_alloc&) {
        storageFailed = true;
        stats.truncated = true;
    }

    if (storageFailed || stats.cancelled) {
        const bool cancelled = stats.cancelled;
        clear();
        stats.cancelled = cancelled;
        stats.truncated = storageFailed;
        stats.resultCount = 0;
        stats.elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
        return stats;
    }

    hasScan_ = true;
    unknownSnapshotActive_ = true;
    unknownSnapshotSourceTruncated_ = false;
    stats.resultCount = unknownCandidateCount_;
    stats.elapsedMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    return stats;
}

template <typename T>
ScanStats MemoryScanner::nextScanTyped(ScanMode mode, const std::optional<T>& wanted) {
    ScanStats stats{};
    resetCancel();
    if (!process_) return stats;

    const auto started = std::chrono::steady_clock::now();
    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    const std::uintptr_t pageSize = (std::max)(
        static_cast<std::uintptr_t>(systemInfo.dwPageSize), std::uintptr_t{1});

    // Compact in place to avoid allocating a second potentially very large result vector.
    std::size_t writeIndex = 0;
    auto evaluate = [&](const ScanResult& oldEntry, T current) {
        const T previous = unpackScanValue<T>(oldEntry.previousBits);
        if (scanMatches(mode, current, previous, wanted, options_.floatTolerance)) {
            results_[writeIndex++] = ScanResult{oldEntry.address, packScanValue(current), oldEntry.type};
        }
    };

    std::vector<std::byte> buffer(pageSize + sizeof(T));
    std::size_t i = 0;
    while (i < results_.size()) {
        if (cancelRequested()) {
            stats.cancelled = true;
            break;
        }

        const auto pageBase = results_[i].address - (results_[i].address % pageSize);
        std::size_t j = i + 1;
        while (j < results_.size()) {
            const auto otherPage = results_[j].address - (results_[j].address % pageSize);
            if (otherPage != pageBase) break;
            ++j;
        }

        const std::uintptr_t readBase = results_[i].address;
        const std::uintptr_t lastAddress = results_[j - 1].address;
        const SIZE_T request = static_cast<SIZE_T>((lastAddress - readBase) + sizeof(T));
        if (buffer.size() < request) buffer.resize(request);
        SIZE_T bytesRead = 0;
        const BOOL ok = ReadProcessMemory(
            process_, reinterpret_cast<LPCVOID>(readBase),
            buffer.data(), request, &bytesRead);
        ++stats.regionsRead;
        stats.bytesRead += static_cast<std::uint64_t>(bytesRead);

        for (std::size_t k = i; k < j; ++k) {
            const ScanResult oldEntry = results_[k];
            const SIZE_T offset = static_cast<SIZE_T>(oldEntry.address - readBase);
            bool handled = false;
            if (offset + sizeof(T) <= bytesRead) {
                T current{};
                std::memcpy(&current, buffer.data() + offset, sizeof(T));
                evaluate(oldEntry, current);
                handled = true;
            }

            if (!handled && (!ok || bytesRead < request)) {
                T current{};
                SIZE_T individualBytes = 0;
                const BOOL individualOk = ReadProcessMemory(
                    process_, reinterpret_cast<LPCVOID>(oldEntry.address),
                    &current, sizeof(T), &individualBytes);
                ++stats.regionsRead;
                stats.bytesRead += static_cast<std::uint64_t>(individualBytes);
                if (individualOk && individualBytes == sizeof(T)) {
                    evaluate(oldEntry, current);
                }
            }
        }
        i = j;
        reportProgress(stats, writeIndex);
        if (cancelRequested()) {
            stats.cancelled = true;
            break;
        }
    }

    results_.resize(writeIndex);
    stats.resultCount = results_.size();
    stats.elapsedMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    return stats;
}

template <typename T>
ScanStats MemoryScanner::nextScanFromSnapshotTyped(ScanMode mode, const std::optional<T>& wanted) {
    ScanStats stats{};
    resetCancel();
    if (!process_) return stats;

    const auto started = std::chrono::steady_clock::now();
    results_.clear();
    const std::size_t alignment = alignmentForType<T>();
    const std::size_t typeIndex = valueTypeIndex(type_);

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    const SIZE_T pageSize = (std::max)(static_cast<SIZE_T>(systemInfo.dwPageSize), SIZE_T{1});

    auto candidateActive = [&](const SnapshotCandidates& candidates, std::size_t index) {
        if (index >= candidates.candidateCount) return false;
        if (candidates.mode == SnapshotMaskMode::All) return true;
        return candidates.mode == SnapshotMaskMode::Explicit && snapshotBitSet(candidates.bits, index);
    };
    auto recordCandidate = [&](SnapshotCandidates& candidates, std::size_t index) {
        if (candidates.mode != SnapshotMaskMode::Explicit) {
            candidates.bits.assign((candidates.candidateCount + 63) / 64, 0);
            candidates.mode = SnapshotMaskMode::Explicit;
        }
        if (!snapshotBitSet(candidates.bits, index)) {
            setSnapshotBit(candidates.bits, index);
            ++candidates.activeCount;
        }
    };
    auto normalizeCandidates = [&](SnapshotCandidates& candidates) {
        if (candidates.activeCount == 0) {
            candidates.mode = SnapshotMaskMode::None;
            candidates.bits.clear();
        } else if (candidates.activeCount == candidates.candidateCount) {
            candidates.mode = SnapshotMaskMode::All;
            candidates.bits.clear();
        }
    };
    const auto saturatingAdd = [](std::size_t& total, std::size_t value) {
        const auto max = (std::numeric_limits<std::size_t>::max)();
        total = value > max - total ? max : total + value;
    };

    std::size_t survivors = 0;
    bool storageFailed = false;
    try {
        for (auto& block : snapshot_) {
            if (cancelRequested()) {
                stats.cancelled = true;
                break;
            }
            if (block.size == 0 || block.candidateBytes == 0) continue;

            std::vector<std::byte> snapshotBytes(block.size);
            if (!readSnapshotBytes(block.fileOffset, snapshotBytes.data(), snapshotBytes.size())) {
                storageFailed = true;
                break;
            }
            std::vector<std::byte> current = snapshotBytes;
            std::vector<std::pair<std::size_t, std::size_t>> readableSegments;

            SIZE_T bytesRead = 0;
            const BOOL ok = ReadProcessMemory(
                process_, reinterpret_cast<LPCVOID>(block.base),
                current.data(), block.size, &bytesRead);
            ++stats.regionsRead;
            stats.bytesRead += static_cast<std::uint64_t>(bytesRead);
            if (bytesRead > 0) {
                readableSegments.emplace_back(0, static_cast<std::size_t>(bytesRead));
            }

            if ((!ok || bytesRead < block.size) && bytesRead < block.size) {
                SIZE_T offset = bytesRead;
                while (offset < block.size) {
                    if (cancelRequested()) {
                        stats.cancelled = true;
                        break;
                    }
                    const SIZE_T request = (std::min)(pageSize, block.size - offset);
                    SIZE_T pageBytes = 0;
                    ReadProcessMemory(
                        process_, reinterpret_cast<LPCVOID>(block.base + offset),
                        current.data() + offset, request, &pageBytes);
                    ++stats.regionsRead;
                    stats.bytesRead += static_cast<std::uint64_t>(pageBytes);
                    if (pageBytes > 0) {
                        readableSegments.emplace_back(
                            static_cast<std::size_t>(offset), static_cast<std::size_t>(pageBytes));
                    }
                    offset += request;
                }
                if (stats.cancelled) break;
            }

            auto& old = block.candidates[typeIndex];
            SnapshotCandidates next{};
            next.candidateCount = old.candidateCount;
            const bool fullEqual = ok && bytesRead == block.size &&
                std::memcmp(current.data(), snapshotBytes.data(), block.size) == 0;
            bool preserve = false;
            bool evaluate = old.activeCount != 0;
            if (fullEqual && mode == ScanMode::Unchanged) {
                preserve = true;
                evaluate = false;
            } else if (fullEqual &&
                       (mode == ScanMode::Changed || mode == ScanMode::Increased || mode == ScanMode::Decreased)) {
                evaluate = false;
            }

            if (evaluate) {
                const std::size_t firstOffset = alignedStartOffset(block.base, alignment);
                for (const auto& [segmentOffset, segmentSize] : readableSegments) {
                    const std::uintptr_t segmentBase = block.base + segmentOffset;
                    if (segmentSize < sizeof(T) || segmentOffset >= block.candidateBytes) continue;
                    const std::size_t segmentCandidateBytes = (std::min)(
                        segmentSize, block.candidateBytes - segmentOffset);

                    visitCandidates<T>(
                        segmentBase,
                        current.data() + segmentOffset,
                        segmentSize,
                        segmentCandidateBytes,
                        alignment,
                        [&](std::uintptr_t address, T now) {
                            const std::size_t blockOffset = static_cast<std::size_t>(address - block.base);
                            if (blockOffset < firstOffset || blockOffset + sizeof(T) > block.size) return true;
                            const std::size_t delta = blockOffset - firstOffset;
                            if (delta % alignment != 0) return true;
                            const std::size_t candidateIndex = delta / alignment;
                            if (!candidateActive(old, candidateIndex)) return true;

                            T previous{};
                            std::memcpy(&previous, snapshotBytes.data() + blockOffset, sizeof(T));
                            if (scanMatches(mode, now, previous, wanted, options_.floatTolerance)) {
                                recordCandidate(next, candidateIndex);
                            }
                            return true;
                        });
                }
            }

            if (!preserve) {
                normalizeCandidates(next);
                old = std::move(next);
            }
            saturatingAdd(survivors, old.activeCount);
            if (!fullEqual && !writeSnapshotBytes(block.fileOffset, current.data(), block.size)) {
                storageFailed = true;
                break;
            }
            reportProgress(stats, survivors);
        }
    } catch (const std::bad_alloc&) {
        stats.truncated = true;
        clear();
        stats.resultCount = 0;
        stats.elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
        return stats;
    }

    if (storageFailed) {
        clear();
        stats.truncated = true;
        stats.resultCount = 0;
        stats.elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
        return stats;
    }

    if (stats.cancelled) {
        clear();
        stats.resultCount = 0;
        stats.elapsedMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started).count();
        return stats;
    }

    unknownCandidateCount_ = survivors;
    if (survivors <= kMaxResults) {
        try {
            results_.reserve(survivors);
            std::vector<std::byte> blockBytes;
            for (const auto& block : snapshot_) {
                const auto& candidates = block.candidates[typeIndex];
                if (candidates.activeCount == 0) continue;
                blockBytes.resize(block.size);
                if (!readSnapshotBytes(block.fileOffset, blockBytes.data(), blockBytes.size())) {
                    storageFailed = true;
                    break;
                }
                const std::size_t firstOffset = alignedStartOffset(block.base, alignment);
                auto emit = [&](std::size_t candidateIndex) {
                    const std::size_t offset = firstOffset + candidateIndex * alignment;
                    if (offset >= block.candidateBytes || offset + sizeof(T) > block.size) return;
                    T now{};
                    std::memcpy(&now, blockBytes.data() + offset, sizeof(T));
                    results_.push_back(ScanResult{block.base + offset, packScanValue(now), type_});
                };

                if (candidates.mode == SnapshotMaskMode::All) {
                    for (std::size_t i = 0; i < candidates.candidateCount; ++i) emit(i);
                } else if (candidates.mode == SnapshotMaskMode::Explicit) {
                    for (std::size_t wordIndex = 0; wordIndex < candidates.bits.size(); ++wordIndex) {
                        std::uint64_t word = candidates.bits[wordIndex];
                        for (unsigned bit = 0; word != 0; ++bit, word >>= 1) {
                            if ((word & 1u) != 0) emit(wordIndex * 64 + bit);
                        }
                    }
                }
            }
            if (storageFailed) {
                results_.clear();
                clear();
                stats.truncated = true;
                stats.resultCount = 0;
                stats.elapsedMs = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - started).count();
                return stats;
            }
        } catch (const std::bad_alloc&) {
            results_.clear();
            stats.truncated = true;
            stats.resultCount = unknownCandidateCount_;
            stats.elapsedMs = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - started).count();
            return stats;
        }

        clearSnapshotStorage();
        unknownSnapshotActive_ = false;
        unknownCandidateCount_ = 0;
        stats.resultCount = results_.size();
    } else {
        stats.resultCount = survivors;
    }

    stats.elapsedMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - started).count();
    return stats;
}

template <typename T>
std::optional<T> MemoryScanner::readTyped(std::uintptr_t address) const {
    if (!process_) return std::nullopt;
    T value{};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(
            process_, reinterpret_cast<LPCVOID>(address),
            &value, sizeof(T), &bytesRead) || bytesRead != sizeof(T)) {
        return std::nullopt;
    }
    return value;
}

std::optional<Value> MemoryScanner::readCurrentAs(ValueType type, std::uintptr_t address) const {
    switch (type) {
        case ValueType::Byte:   if (auto v = readTyped<std::uint8_t>(address)) return Value{*v}; break;
        case ValueType::Int16:  if (auto v = readTyped<std::int16_t>(address)) return Value{*v}; break;
        case ValueType::Int32:  if (auto v = readTyped<std::int32_t>(address)) return Value{*v}; break;
        case ValueType::Int64:  if (auto v = readTyped<std::int64_t>(address)) return Value{*v}; break;
        case ValueType::Float:  if (auto v = readTyped<float>(address)) return Value{*v}; break;
        case ValueType::Double: if (auto v = readTyped<double>(address)) return Value{*v}; break;
    }
    return std::nullopt;
}

std::optional<Value> MemoryScanner::readCurrent(std::uintptr_t address) const {
    return readCurrentAs(type_, address);
}

std::optional<Value> MemoryScanner::readCurrent(const ScanResult& result) const {
    return readCurrentAs(result.type, result.address);
}

std::optional<Value> MemoryScanner::previousValue(const ScanResult& result) const {
    switch (result.type) {
        case ValueType::Byte: return Value{unpackScanValue<std::uint8_t>(result.previousBits)};
        case ValueType::Int16: return Value{unpackScanValue<std::int16_t>(result.previousBits)};
        case ValueType::Int32: return Value{unpackScanValue<std::int32_t>(result.previousBits)};
        case ValueType::Int64: return Value{unpackScanValue<std::int64_t>(result.previousBits)};
        case ValueType::Float: return Value{unpackScanValue<float>(result.previousBits)};
        case ValueType::Double: return Value{unpackScanValue<double>(result.previousBits)};
    }
    return std::nullopt;
}

// Explicit instantiations.
template ScanStats MemoryScanner::firstScanTyped<std::uint8_t>(std::uint8_t);
template ScanStats MemoryScanner::firstScanTyped<std::int16_t>(std::int16_t);
template ScanStats MemoryScanner::firstScanTyped<std::int32_t>(std::int32_t);
template ScanStats MemoryScanner::firstScanTyped<std::int64_t>(std::int64_t);
template ScanStats MemoryScanner::firstScanTyped<float>(float);
template ScanStats MemoryScanner::firstScanTyped<double>(double);

template ScanStats MemoryScanner::firstScanUnknownTyped<std::uint8_t>(const ScanOptions&);
template ScanStats MemoryScanner::firstScanUnknownTyped<std::int16_t>(const ScanOptions&);
template ScanStats MemoryScanner::firstScanUnknownTyped<std::int32_t>(const ScanOptions&);
template ScanStats MemoryScanner::firstScanUnknownTyped<std::int64_t>(const ScanOptions&);
template ScanStats MemoryScanner::firstScanUnknownTyped<float>(const ScanOptions&);
template ScanStats MemoryScanner::firstScanUnknownTyped<double>(const ScanOptions&);

template ScanStats MemoryScanner::nextScanTyped<std::uint8_t>(ScanMode, const std::optional<std::uint8_t>&);
template ScanStats MemoryScanner::nextScanTyped<std::int16_t>(ScanMode, const std::optional<std::int16_t>&);
template ScanStats MemoryScanner::nextScanTyped<std::int32_t>(ScanMode, const std::optional<std::int32_t>&);
template ScanStats MemoryScanner::nextScanTyped<std::int64_t>(ScanMode, const std::optional<std::int64_t>&);
template ScanStats MemoryScanner::nextScanTyped<float>(ScanMode, const std::optional<float>&);
template ScanStats MemoryScanner::nextScanTyped<double>(ScanMode, const std::optional<double>&);

template ScanStats MemoryScanner::nextScanFromSnapshotTyped<std::uint8_t>(ScanMode, const std::optional<std::uint8_t>&);
template ScanStats MemoryScanner::nextScanFromSnapshotTyped<std::int16_t>(ScanMode, const std::optional<std::int16_t>&);
template ScanStats MemoryScanner::nextScanFromSnapshotTyped<std::int32_t>(ScanMode, const std::optional<std::int32_t>&);
template ScanStats MemoryScanner::nextScanFromSnapshotTyped<std::int64_t>(ScanMode, const std::optional<std::int64_t>&);
template ScanStats MemoryScanner::nextScanFromSnapshotTyped<float>(ScanMode, const std::optional<float>&);
template ScanStats MemoryScanner::nextScanFromSnapshotTyped<double>(ScanMode, const std::optional<double>&);

} // namespace cw
