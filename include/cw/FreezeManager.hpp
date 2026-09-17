#pragma once

#include "cw/Value.hpp"

#include <Windows.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace cw {

struct FreezeSnapshot {
    std::uint64_t id{};
    std::uintptr_t address{};
    ValueType type{ValueType::Int32};
    Value value{std::int32_t{0}};
    std::uint32_t intervalMs{50};
    std::uint64_t writes{};
    std::uint64_t failures{};
    DWORD lastError{};
};

class FreezeManager {
public:
    FreezeManager();
    ~FreezeManager();

    FreezeManager(const FreezeManager&) = delete;
    FreezeManager& operator=(const FreezeManager&) = delete;

    // Duplicates the process handle so the worker owns a stable handle lifetime.
    bool setProcess(HANDLE process);

    std::optional<std::uint64_t> add(
        std::uintptr_t address,
        ValueType type,
        const Value& value,
        std::uint32_t intervalMs = 50);

    bool remove(std::uint64_t id);
    void clear();
    [[nodiscard]] std::vector<FreezeSnapshot> list() const;
    [[nodiscard]] std::size_t size() const;

private:
    struct Entry {
        FreezeSnapshot state;
        std::chrono::steady_clock::time_point nextWrite;
    };

    void workerLoop();
    void closeProcessLocked();

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool stopping_{false};
    HANDLE process_{nullptr}; // duplicated handle owned here
    std::uint64_t nextId_{1};
    std::vector<Entry> entries_;
    std::thread worker_;
};

} // namespace cw
