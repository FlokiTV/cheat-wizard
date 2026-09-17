#pragma once

#include "cw/AobPattern.hpp"
#include "cw/MemoryScanner.hpp"
#include "cw/ScanOptions.hpp"

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>

namespace cw {

class AobScanner {
public:
    using ProgressCallback = std::function<void(const ScanProgress&)>;

    void setProcess(HANDLE process) noexcept { process_ = process; clear(); }
    void clear();
    void setOptions(const ScanOptions& options) { options_ = options; }
    [[nodiscard]] const ScanOptions& options() const noexcept { return options_; }
    void setExecutableOnly(bool value) noexcept { executableOnly_ = value; }
    [[nodiscard]] bool executableOnly() const noexcept { return executableOnly_; }
    void setProgressCallback(ProgressCallback callback) { progressCallback_ = std::move(callback); }
    void requestCancel() noexcept { cancelRequested_.store(true, std::memory_order_relaxed); }
    void resetCancel() noexcept { cancelRequested_.store(false, std::memory_order_relaxed); }

    ScanStats scan(const AobPattern& pattern);

    [[nodiscard]] const std::vector<std::uintptr_t>& results() const noexcept { return results_; }
    [[nodiscard]] const AobPattern& pattern() const noexcept { return pattern_; }
    void restore(const AobPattern& pattern, std::vector<std::uintptr_t> results) {
        clear();
        pattern_ = pattern;
        results_ = std::move(results);
    }

private:
    void reportProgress(const ScanStats& stats) const;

    HANDLE process_{nullptr};
    ScanOptions options_{};
    bool executableOnly_{false};
    std::vector<std::uintptr_t> results_;
    AobPattern pattern_{};
    ProgressCallback progressCallback_{};
    std::atomic_bool cancelRequested_{false};
};

} // namespace cw
