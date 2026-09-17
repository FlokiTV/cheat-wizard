#pragma once

#include "cw/PointerTypes.hpp"
#include "cw/ProcessManager.hpp"

#include <Windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

namespace cw {

struct PointerProgress {
    std::uint64_t bytesRead{};
    std::uint64_t regionsRead{};
    std::size_t indexEntries{};
};

class PointerScanner {
public:
    using ProgressCallback = std::function<void(const PointerProgress&)>;

    void setProcess(HANDLE process, std::size_t pointerSize, std::vector<ModuleInfo> modules);
    void clearIndex();
    void clearChains();
    void setChains(std::vector<PointerChain> chains, std::size_t sourcePointerSize) {
        chains_ = std::move(chains);
        chainPointerSize_ = sourcePointerSize;
    }

    void setProgressCallback(ProgressCallback callback) { progressCallback_ = std::move(callback); }
    void requestCancel() noexcept { cancelRequested_.store(true, std::memory_order_relaxed); }
    void resetCancel() noexcept { cancelRequested_.store(false, std::memory_order_relaxed); }

    PointerScanStats captureIndex(const PointerScanOptions& options = {});
    PointerScanStats scan(std::uintptr_t target, const PointerScanOptions& options = {});
    std::size_t rescan(std::uintptr_t target);

    [[nodiscard]] std::optional<std::uintptr_t> resolve(const PointerChain& chain) const;
    [[nodiscard]] std::optional<std::uintptr_t> resolve(std::size_t chainIndex) const;

    [[nodiscard]] const std::vector<PointerChain>& chains() const noexcept { return chains_; }
    [[nodiscard]] const std::vector<PointerEntry>& index() const noexcept { return index_; }
    [[nodiscard]] std::size_t pointerSize() const noexcept { return pointerSize_; }
    [[nodiscard]] std::size_t chainPointerSize() const noexcept { return chainPointerSize_; }
    [[nodiscard]] const std::vector<ModuleInfo>& modules() const noexcept { return modules_; }

private:
    bool buildIndex(const PointerScanOptions& options, PointerScanStats& stats);
    std::optional<std::uintptr_t> readPointer(std::uintptr_t address) const;
    const ModuleInfo* findModule(const std::wstring& name) const;
    void reportProgress(const PointerScanStats& stats) const;

    HANDLE process_{nullptr}; // borrowed
    std::size_t pointerSize_{0};
    std::size_t chainPointerSize_{0};
    std::vector<ModuleInfo> modules_;
    std::vector<PointerEntry> index_;
    std::vector<PointerChain> chains_;
    ProgressCallback progressCallback_{};
    std::atomic_bool cancelRequested_{false};
};

} // namespace cw
