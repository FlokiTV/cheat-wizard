#include "cw/FreezeManager.hpp"
#include "cw/MemoryWriter.hpp"

#include <algorithm>

namespace cw {

FreezeManager::FreezeManager()
    : worker_(&FreezeManager::workerLoop, this) {}

FreezeManager::~FreezeManager() {
    {
        std::lock_guard lock(mutex_);
        stopping_ = true;
        entries_.clear();
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();

    std::lock_guard lock(mutex_);
    closeProcessLocked();
}

void FreezeManager::closeProcessLocked() {
    if (process_) {
        CloseHandle(process_);
        process_ = nullptr;
    }
}

bool FreezeManager::setProcess(HANDLE process) {
    std::lock_guard lock(mutex_);
    entries_.clear();
    closeProcessLocked();

    if (!process) {
        cv_.notify_all();
        return true;
    }

    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(
            GetCurrentProcess(), process,
            GetCurrentProcess(), &duplicate,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
        cv_.notify_all();
        return false;
    }

    process_ = duplicate;
    cv_.notify_all();
    return true;
}

std::optional<std::uint64_t> FreezeManager::add(
    std::uintptr_t address,
    ValueType type,
    const Value& value,
    std::uint32_t intervalMs)
{
    if (!valueMatchesType(type, value)) return std::nullopt;
    intervalMs = (std::max)(10u, (std::min)(intervalMs, 60'000u));

    std::lock_guard lock(mutex_);
    if (!process_) return std::nullopt;
    const auto duplicate = std::find_if(entries_.begin(), entries_.end(),
        [&](const Entry& entry) { return entry.state.address == address; });
    if (duplicate != entries_.end()) return std::nullopt;

    const std::uint64_t id = nextId_++;
    FreezeSnapshot snapshot{};
    snapshot.id = id;
    snapshot.address = address;
    snapshot.type = type;
    snapshot.value = value;
    snapshot.intervalMs = intervalMs;

    entries_.push_back(Entry{snapshot, std::chrono::steady_clock::now()});
    cv_.notify_all();
    return id;
}

bool FreezeManager::remove(std::uint64_t id) {
    std::lock_guard lock(mutex_);
    const auto oldSize = entries_.size();
    std::erase_if(entries_, [&](const Entry& e) { return e.state.id == id; });
    cv_.notify_all();
    return entries_.size() != oldSize;
}

void FreezeManager::clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
    cv_.notify_all();
}

std::vector<FreezeSnapshot> FreezeManager::list() const {
    std::lock_guard lock(mutex_);
    std::vector<FreezeSnapshot> out;
    out.reserve(entries_.size());
    for (const auto& entry : entries_) out.push_back(entry.state);
    return out;
}

std::size_t FreezeManager::size() const {
    std::lock_guard lock(mutex_);
    return entries_.size();
}

void FreezeManager::workerLoop() {
    std::unique_lock lock(mutex_);
    while (!stopping_) {
        if (!process_ || entries_.empty()) {
            cv_.wait(lock, [&] { return stopping_ || (process_ && !entries_.empty()); });
            continue;
        }

        auto now = std::chrono::steady_clock::now();
        auto nextDue = entries_.front().nextWrite;
        for (const auto& entry : entries_) {
            if (entry.nextWrite < nextDue) nextDue = entry.nextWrite;
        }

        if (now < nextDue) {
            cv_.wait_until(lock, nextDue);
            continue;
        }

        now = std::chrono::steady_clock::now();
        for (auto& entry : entries_) {
            if (entry.nextWrite > now) continue;

            // Keep the lock while writing. Writes are tiny (1-8 bytes), and this guarantees
            // setProcess() cannot close the duplicated handle while the worker is using it.
            const WriteResult result = writeValue(process_, entry.state.address, entry.state.value);
            if (result.ok) {
                ++entry.state.writes;
                entry.state.lastError = ERROR_SUCCESS;
            } else {
                ++entry.state.failures;
                entry.state.lastError = result.error;
            }
            entry.nextWrite = now + std::chrono::milliseconds(entry.state.intervalMs);
        }
    }
}

} // namespace cw
