#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cw {

struct ProcessInfo {
    DWORD pid{};
    std::wstring name;
};

struct ModuleInfo {
    std::uintptr_t base{};
    std::size_t size{};
    std::wstring name;
    std::wstring path;

    [[nodiscard]] bool contains(std::uintptr_t address) const noexcept {
        if (size == 0 || address < base) return false;
        const auto offset = address - base;
        return offset < size;
    }
};

class ProcessManager {
public:
    ProcessManager() = default;
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    std::vector<ProcessInfo> listProcesses() const;
    std::vector<ModuleInfo> listModules(std::string& error) const;
    bool attach(DWORD pid, std::string& error);
    bool attachByName(const std::wstring& name, std::string& error);
    void detach();

    [[nodiscard]] std::size_t targetPointerSize(std::string& error) const;

    [[nodiscard]] HANDLE handle() const noexcept { return process_; }
    [[nodiscard]] DWORD pid() const noexcept { return pid_; }
    [[nodiscard]] bool attached() const noexcept { return process_ != nullptr; }

private:
    HANDLE process_{nullptr};
    DWORD pid_{0};
};

std::string win32ErrorMessage(DWORD errorCode);

} // namespace cw
