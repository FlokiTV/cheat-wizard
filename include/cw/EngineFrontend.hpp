#pragma once

#include "cw/AobScanner.hpp"
#include "cw/EngineClient.hpp"
#include "cw/FreezeManager.hpp"
#include "cw/MemoryScanner.hpp"
#include "cw/PointerProfile.hpp"
#include "cw/PointerScanner.hpp"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace cw {

class EngineClientScanner {
public:
    using ProgressCallback = std::function<void(const ScanProgress&)>;

    explicit EngineClientScanner(EngineClient& client) : client_(&client) {}

    void clear();
    void setProcess(HANDLE process);
    void setOptions(const ScanOptions& options);
    [[nodiscard]] const ScanOptions& options() const noexcept { return options_; }
    void setProgressCallback(ProgressCallback callback) { progressCallback_ = std::move(callback); }
    void requestCancel() noexcept {}
    void resetCancel() noexcept {}

    ScanStats firstScan(ValueType type, const Value& wanted);
    ScanStats firstScanUnknown(ValueType type);
    ScanStats firstScanUnknownSmart(ValueType type);
    ScanStats firstScanAllExact(const std::string& text);
    ScanStats firstScanAllUnknown();
    ScanStats firstScanAllUnknownSmart();
    ScanStats nextScan(ScanMode mode, const std::optional<Value>& wanted = std::nullopt);
    ScanStats nextScanMixed(ScanMode mode, const std::optional<std::string>& wantedText = std::nullopt);

    [[nodiscard]] std::array<std::size_t, 6> candidateCountsByType() const;
    bool disableMixedType(ValueType type);
    [[nodiscard]] const std::vector<ScanRefinementStep>& refinementHistory() const noexcept { return history_; }
    [[nodiscard]] std::optional<GuidedWizardSuggestion> guidedSuggestion(GuidedGoal goal) const noexcept;
    [[nodiscard]] std::vector<RankedScanResult> rankedResults(
        std::size_t limit = 100, GuidedGoal goal = GuidedGoal::Generic) const;

    [[nodiscard]] bool hasScan() const noexcept { return hasScan_; }
    [[nodiscard]] bool unknownSnapshotActive() const noexcept { return snapshotActive_; }
    [[nodiscard]] bool unknownSnapshotSourceTruncated() const noexcept { return truncated_; }
    [[nodiscard]] bool mixedScanActive() const noexcept { return mixed_; }
    [[nodiscard]] ValueType valueType() const noexcept { return type_; }
    [[nodiscard]] const std::vector<ScanResult>& results() const;
    [[nodiscard]] std::size_t resultCount() const noexcept { return resultCount_; }
    [[nodiscard]] std::size_t candidateCount() const noexcept { return candidateCount_; }
    [[nodiscard]] std::optional<Value> readCurrent(std::uintptr_t address) const;
    [[nodiscard]] std::optional<Value> readCurrent(const ScanResult& result) const;
    [[nodiscard]] std::optional<Value> previousValue(const ScanResult& result) const;

    bool restoreMaterializedScan(
        ValueType primaryType,
        bool mixed,
        const ScanOptions& options,
        std::vector<ScanResult> results);

private:
    ScanStats runFirstScan(std::uint8_t kind, std::uint8_t wireType, const std::string& valueText);
    ScanStats runNextScan(ScanMode mode, const std::string& valueText);
    bool parseScanSummary(const EngineFrame& response, ScanStats& stats);
    bool fetchAllResults() const;
    void resetStateLocal();

    EngineClient* client_{};
    ScanOptions options_{};
    bool hasScan_{};
    bool snapshotActive_{};
    bool mixed_{};
    bool truncated_{};
    ValueType type_{ValueType::Int32};
    std::size_t candidateCount_{};
    std::size_t resultCount_{};
    std::array<std::size_t, 6> typeCounts_{};
    mutable std::vector<ScanResult> results_;
    mutable bool resultsLoaded_{true};
    std::vector<ScanRefinementStep> history_;
    ProgressCallback progressCallback_{};
};

class EngineClientAobScanner {
public:
    using ProgressCallback = std::function<void(const ScanProgress&)>;

    explicit EngineClientAobScanner(EngineClient& client) : client_(&client) {}

    void setProcess(HANDLE process);
    void clear();
    void setOptions(const ScanOptions& options) { options_ = options; clearLocal(); }
    [[nodiscard]] const ScanOptions& options() const noexcept { return options_; }
    void setExecutableOnly(bool value) noexcept { executableOnly_ = value; }
    [[nodiscard]] bool executableOnly() const noexcept { return executableOnly_; }
    void setProgressCallback(ProgressCallback callback) { progressCallback_ = std::move(callback); }
    void requestCancel() noexcept {}
    void resetCancel() noexcept {}

    ScanStats scan(const AobPattern& pattern);
    [[nodiscard]] const std::vector<std::uintptr_t>& results() const noexcept { return results_; }
    [[nodiscard]] const AobPattern& pattern() const noexcept { return pattern_; }
    void restore(const AobPattern& pattern, std::vector<std::uintptr_t> results);

private:
    void clearLocal();
    bool fetchAllResults();

    EngineClient* client_{};
    ScanOptions options_{};
    bool executableOnly_{};
    AobPattern pattern_{};
    std::vector<std::uintptr_t> results_;
    ProgressCallback progressCallback_{};
};

class EngineClientFreezeManager {
public:
    explicit EngineClientFreezeManager(EngineClient& client) : client_(&client) {}

    bool setProcess(HANDLE process);
    std::optional<std::uint64_t> add(
        std::uintptr_t address, ValueType type, const Value& value, std::uint32_t intervalMs = 50);
    bool remove(std::uint64_t id);
    void clear();
    [[nodiscard]] std::vector<FreezeSnapshot> list() const;
    [[nodiscard]] std::size_t size() const;

private:
    EngineClient* client_{};
};

class EngineClientPointerScanner {
public:
    using ProgressCallback = std::function<void(const PointerProgress&)>;

    explicit EngineClientPointerScanner(EngineClient& client) : client_(&client) {}

    void setProcess(HANDLE process, std::size_t pointerSize, std::vector<ModuleInfo> modules);
    void setContext(std::size_t pointerSize, std::vector<ModuleInfo> modules);
    void clearIndex();
    void clearChains();
    void setChains(std::vector<PointerChain> chains, std::size_t sourcePointerSize);
    void setProgressCallback(ProgressCallback callback) { progressCallback_ = std::move(callback); }
    void requestCancel() noexcept {}
    void resetCancel() noexcept {}

    PointerScanStats captureIndex(const PointerScanOptions& options = {});
    PointerScanStats scan(std::uintptr_t target, const PointerScanOptions& options = {});
    std::size_t rescan(std::uintptr_t target);
    [[nodiscard]] std::optional<std::uintptr_t> resolve(std::size_t chainIndex) const;

    [[nodiscard]] const std::vector<PointerChain>& chains() const noexcept { return chains_; }
    [[nodiscard]] const std::vector<PointerEntry>& index() const noexcept { return index_; }
    [[nodiscard]] std::size_t pointerSize() const noexcept { return pointerSize_; }
    [[nodiscard]] std::size_t chainPointerSize() const noexcept { return chainPointerSize_; }
    [[nodiscard]] const std::vector<ModuleInfo>& modules() const noexcept { return modules_; }

private:
    bool writeOptions(EngineBufferWriter& payload, const PointerScanOptions& options) const;
    bool parseStats(const EngineFrame& response, PointerScanStats& stats);
    bool fetchChains();
    bool fetchIndex();

    EngineClient* client_{};
    std::size_t pointerSize_{};
    std::size_t chainPointerSize_{};
    std::vector<ModuleInfo> modules_;
    std::vector<PointerChain> chains_;
    std::vector<std::optional<std::uintptr_t>> resolved_;
    std::vector<PointerEntry> index_;
    ProgressCallback progressCallback_{};
};

class EngineFrontendSession {
public:
    EngineFrontendSession();
    ~EngineFrontendSession();

    bool start(std::string& error);
    void shutdown() noexcept;

    [[nodiscard]] std::vector<ProcessInfo> listProcesses() const;
    [[nodiscard]] std::vector<ModuleInfo> listModules(std::string& error) const;
    bool attach(DWORD pid, std::string& error);
    bool attachByName(const std::wstring& name, std::string& error);
    void detach();

    [[nodiscard]] bool attached() const noexcept { return client_.attached(); }
    [[nodiscard]] DWORD pid() const noexcept { return client_.pid(); }
    [[nodiscard]] std::size_t targetPointerSize(std::string& error) const;
    bool refreshPointerContext(std::string& error);
    void clearScans();

    bool readBytes(std::uintptr_t address, void* buffer, std::size_t size, std::size_t& bytesRead, DWORD& error) const;
    [[nodiscard]] std::optional<Value> readValue(std::uintptr_t address, ValueType type) const;
    [[nodiscard]] WriteResult writeValue(std::uintptr_t address, const Value& value) const;

    [[nodiscard]] EngineClientScanner& scanner() noexcept { return scanner_; }
    [[nodiscard]] const EngineClientScanner& scanner() const noexcept { return scanner_; }
    [[nodiscard]] EngineClientAobScanner& aobScanner() noexcept { return aobScanner_; }
    [[nodiscard]] const EngineClientAobScanner& aobScanner() const noexcept { return aobScanner_; }
    [[nodiscard]] EngineClientFreezeManager& freezer() noexcept { return freezer_; }
    [[nodiscard]] const EngineClientFreezeManager& freezer() const noexcept { return freezer_; }
    [[nodiscard]] EngineClientPointerScanner& pointerScanner() noexcept { return pointerScanner_; }
    [[nodiscard]] const EngineClientPointerScanner& pointerScanner() const noexcept { return pointerScanner_; }

private:
    mutable EngineClient client_;
    EngineClientScanner scanner_;
    EngineClientAobScanner aobScanner_;
    EngineClientFreezeManager freezer_;
    EngineClientPointerScanner pointerScanner_;
};

} // namespace cw
