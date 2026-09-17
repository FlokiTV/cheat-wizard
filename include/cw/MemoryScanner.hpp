#pragma once

#include "cw/ScanOptions.hpp"
#include "cw/ScanTypes.hpp"
#include "cw/Value.hpp"

#include <Windows.h>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace cw {

struct ScanStats {
    std::size_t resultCount{};
    std::uint64_t bytesRead{};
    std::uint64_t regionsRead{};
    double elapsedMs{};
    bool truncated{};
    bool cancelled{};
};

struct ScanProgress {
    std::uint64_t bytesRead{};
    std::uint64_t regionsRead{};
    std::size_t resultCount{};
};

enum class GuidedGoal : std::uint8_t {
    Generic,
    Money,
    Health,
    Ammo,
};

struct GuidedWizardSuggestion {
    ScanMode recommendedMode{ScanMode::Changed};
    std::size_t candidateCount{};
    std::size_t refinementDepth{};
    bool snapshotActive{};
    bool rankingAvailable{};
    bool inspectRecommended{};
};

struct ScanRefinementStep {
    ScanMode mode{ScanMode::Exact};
    std::size_t beforeCount{};
    std::size_t afterCount{};
    std::array<std::size_t, 6> beforeByType{};
    std::array<std::size_t, 6> afterByType{};
    double elapsedMs{};
};

struct RankedScanResult {
    std::size_t resultIndex{};
    std::uint32_t score{};
    bool privateMemory{};
    bool writable{};
    bool executable{};
};

class MemoryScanner {
public:
    using ProgressCallback = std::function<void(const ScanProgress&)>;

    ~MemoryScanner();
    void setProcess(HANDLE process);
    void clear();

    void setOptions(const ScanOptions& options);
    [[nodiscard]] const ScanOptions& options() const noexcept { return options_; }

    void setProgressCallback(ProgressCallback callback);
    void requestCancel() noexcept { cancelRequested_.store(true, std::memory_order_relaxed); }
    void resetCancel() noexcept { cancelRequested_.store(false, std::memory_order_relaxed); }
    [[nodiscard]] bool cancelRequested() const noexcept {
        return cancelRequested_.load(std::memory_order_relaxed);
    }

    // Backward-compatible Exact Value wrappers.
    ScanStats firstScan(ValueType type, const Value& wanted);
    ScanStats nextScan(const Value& wanted);

    ScanStats firstScanUnknown(ValueType type);
    ScanStats firstScanUnknownSmart(ValueType type);
    ScanStats firstScanAllExact(const std::string& text);
    ScanStats firstScanAllUnknown();
    ScanStats firstScanAllUnknownSmart();
    ScanStats nextScan(ScanMode mode, const std::optional<Value>& wanted = std::nullopt);
    ScanStats nextScanMixed(ScanMode mode, const std::optional<std::string>& wantedText = std::nullopt);
    [[nodiscard]] std::array<std::size_t, 6> candidateCountsByType() const noexcept;
    bool disableMixedType(ValueType type);
    [[nodiscard]] const std::vector<ScanRefinementStep>& refinementHistory() const noexcept {
        return refinementHistory_;
    }
    [[nodiscard]] std::optional<GuidedWizardSuggestion> guidedSuggestion(GuidedGoal goal) const noexcept;
    [[nodiscard]] std::vector<RankedScanResult> rankedResults(
        std::size_t limit = 100, GuidedGoal goal = GuidedGoal::Generic) const;

    [[nodiscard]] bool hasScan() const noexcept { return hasScan_; }
    [[nodiscard]] bool unknownSnapshotActive() const noexcept { return unknownSnapshotActive_; }
    [[nodiscard]] bool unknownSnapshotSourceTruncated() const noexcept {
        return unknownSnapshotSourceTruncated_;
    }
    [[nodiscard]] bool mixedScanActive() const noexcept { return mixedScanActive_; }
    [[nodiscard]] ValueType valueType() const noexcept { return type_; }
    [[nodiscard]] const std::vector<ScanResult>& results() const noexcept { return results_; }
    [[nodiscard]] std::size_t candidateCount() const noexcept;
    [[nodiscard]] std::optional<Value> readCurrent(std::uintptr_t address) const;
    [[nodiscard]] std::optional<Value> readCurrent(const ScanResult& result) const;
    [[nodiscard]] std::optional<Value> previousValue(const ScanResult& result) const;

    // Restore a previously materialized result list. Unknown-initial snapshots
    // are intentionally not restorable because they may contain hundreds of
    // MiB of raw process memory. Returns false if metadata is inconsistent.
    bool restoreMaterializedScan(
        ValueType primaryType,
        bool mixed,
        const ScanOptions& options,
        std::vector<ScanResult> results);

private:
    enum class SnapshotMaskMode : std::uint8_t {
        None,
        All,
        Explicit,
    };

    struct SnapshotCandidates {
        std::size_t candidateCount{};
        std::size_t activeCount{};
        SnapshotMaskMode mode{SnapshotMaskMode::None};
        std::vector<std::uint64_t> bits;
    };

    struct SnapshotBlock {
        std::uintptr_t base{};
        std::uint64_t fileOffset{};
        std::size_t size{};
        std::size_t candidateBytes{};
        std::array<SnapshotCandidates, 6> candidates;
    };

    template <typename T>
    ScanStats firstScanTyped(T wanted);

    template <typename T>
    ScanStats firstScanUnknownTyped(const ScanOptions& sourceOptions);

    template <typename T>
    ScanStats nextScanTyped(ScanMode mode, const std::optional<T>& wanted);

    template <typename T>
    ScanStats nextScanFromSnapshotTyped(ScanMode mode, const std::optional<T>& wanted);

    template <typename T>
    std::optional<T> readTyped(std::uintptr_t address) const;

    ScanStats firstScanAllUnknownWithOptions(const ScanOptions& sourceOptions);
    ScanStats nextScanMixedInternal(ScanMode mode, const std::vector<std::pair<ValueType, Value>>& wantedByType);
    ScanStats nextScanMixedFromSnapshot(ScanMode mode, const std::vector<std::pair<ValueType, Value>>& wantedByType);
    std::optional<Value> readCurrentAs(ValueType type, std::uintptr_t address) const;

    template <typename T>
    [[nodiscard]] std::size_t alignmentForType() const noexcept {
        return options_.alignment == AlignmentMode::Byte ? 1u : sizeof(T);
    }

    void reportProgress(const ScanStats& stats, std::size_t resultCount) const;
    bool openSnapshotBacking();
    void closeSnapshotBacking() noexcept;
    void clearSnapshotStorage() noexcept;
    bool readSnapshotBytes(std::uint64_t offset, void* data, std::size_t size) const;
    bool writeSnapshotBytes(std::uint64_t offset, const void* data, std::size_t size) const;
    bool appendSnapshotBytes(const void* data, std::size_t size, std::uint64_t& offsetOut);
    void recordRefinementStep(
        ScanMode mode,
        std::size_t beforeCount,
        const std::array<std::size_t, 6>& beforeByType,
        const ScanStats& stats);

    HANDLE process_{nullptr}; // borrowed; ProcessManager owns the handle
    ValueType type_{ValueType::Int32};
    bool hasScan_{false};
    bool unknownSnapshotActive_{false};
    bool unknownSnapshotSourceTruncated_{false};
    bool mixedScanActive_{false};
    std::size_t unknownCandidateCount_{0};
    std::vector<ScanResult> results_;
    std::vector<SnapshotBlock> snapshot_;
    HANDLE snapshotFile_{INVALID_HANDLE_VALUE};
    std::uint64_t snapshotFileBytes_{0};
    std::vector<ScanRefinementStep> refinementHistory_;
    ScanOptions options_{};
    ProgressCallback progressCallback_{};
    std::atomic_bool cancelRequested_{false};
};

} // namespace cw
