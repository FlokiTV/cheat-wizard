#pragma once

#include "cw/AobScanner.hpp"
#include "cw/FreezeManager.hpp"
#include "cw/MemoryScanner.hpp"
#include "cw/MemoryWriter.hpp"
#include "cw/PointerScanner.hpp"
#include "cw/ProcessManager.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cw {

class EngineSession {
public:
    EngineSession() = default;
    ~EngineSession() = default;

    EngineSession(const EngineSession&) = delete;
    EngineSession& operator=(const EngineSession&) = delete;

    [[nodiscard]] std::vector<ProcessInfo> listProcesses() const;
    [[nodiscard]] std::vector<ModuleInfo> listModules(std::string& error) const;

    bool attach(DWORD pid, std::string& error);
    bool attachByName(const std::wstring& name, std::string& error);
    void detach();

    [[nodiscard]] bool attached() const noexcept { return processManager_.attached(); }
    [[nodiscard]] DWORD pid() const noexcept { return processManager_.pid(); }
    [[nodiscard]] std::size_t targetPointerSize(std::string& error) const;

    bool refreshPointerContext(std::string& error);
    void clearScans();

    [[nodiscard]] std::optional<Value> readValue(std::uintptr_t address, ValueType type) const;
    bool readBytes(std::uintptr_t address, void* buffer, std::size_t size, std::size_t& bytesRead, DWORD& error) const;
    [[nodiscard]] WriteResult writeValue(std::uintptr_t address, const Value& value) const;

    [[nodiscard]] MemoryScanner& scanner() noexcept { return scanner_; }
    [[nodiscard]] const MemoryScanner& scanner() const noexcept { return scanner_; }
    [[nodiscard]] AobScanner& aobScanner() noexcept { return aobScanner_; }
    [[nodiscard]] const AobScanner& aobScanner() const noexcept { return aobScanner_; }
    [[nodiscard]] FreezeManager& freezer() noexcept { return freezer_; }
    [[nodiscard]] const FreezeManager& freezer() const noexcept { return freezer_; }
    [[nodiscard]] PointerScanner& pointerScanner() noexcept { return pointerScanner_; }
    [[nodiscard]] const PointerScanner& pointerScanner() const noexcept { return pointerScanner_; }

private:
    bool bindAttachedProcess(std::string& error);

    ProcessManager processManager_;
    MemoryScanner scanner_;
    AobScanner aobScanner_;
    FreezeManager freezer_;
    PointerScanner pointerScanner_;
};

} // namespace cw
