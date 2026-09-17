#include "cw/ProcessManager.hpp"

#include <TlHelp32.h>

#include <algorithm>
#include <cwctype>
#include <sstream>

namespace cw {

ProcessManager::~ProcessManager() {
    detach();
}

std::vector<ProcessInfo> ProcessManager::listProcesses() const {
    std::vector<ProcessInfo> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            processes.push_back(ProcessInfo{entry.th32ProcessID, entry.szExeFile});
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    std::sort(processes.begin(), processes.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
        if (a.name == b.name) return a.pid < b.pid;
        return a.name < b.name;
    });
    return processes;
}

std::vector<ModuleInfo> ProcessManager::listModules(std::string& error) const {
    std::vector<ModuleInfo> modules;
    if (!attached()) {
        error = "No process attached";
        return modules;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = win32ErrorMessage(GetLastError());
        return modules;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot, &entry)) {
        error = win32ErrorMessage(GetLastError());
        CloseHandle(snapshot);
        return modules;
    }

    do {
        ModuleInfo module;
        module.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        module.size = static_cast<std::size_t>(entry.modBaseSize);
        module.name = entry.szModule;
        module.path = entry.szExePath;
        modules.push_back(std::move(module));
    } while (Module32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    std::sort(modules.begin(), modules.end(), [](const ModuleInfo& a, const ModuleInfo& b) {
        return a.base < b.base;
    });
    error.clear();
    return modules;
}

bool ProcessManager::attach(DWORD pid, std::string& error) {
    detach();
    constexpr DWORD access = PROCESS_QUERY_INFORMATION |
                             PROCESS_VM_READ |
                             PROCESS_VM_WRITE |
                             PROCESS_VM_OPERATION;
    HANDLE process = OpenProcess(access, FALSE, pid);
    if (!process) {
        error = win32ErrorMessage(GetLastError());
        return false;
    }

    process_ = process;
    pid_ = pid;
    error.clear();
    return true;
}

bool ProcessManager::attachByName(const std::wstring& name, std::string& error) {
    const auto processes = listProcesses();
    auto lower = [](std::wstring text) {
        std::transform(text.begin(), text.end(), text.begin(), [](wchar_t c) {
            return static_cast<wchar_t>(std::towlower(c));
        });
        return text;
    };
    const auto wanted = lower(name);
    for (const auto& process : processes) {
        if (lower(process.name) == wanted) {
            return attach(process.pid, error);
        }
    }
    error = "Process name not found";
    return false;
}

std::size_t ProcessManager::targetPointerSize(std::string& error) const {
    if (!attached()) {
        error = "No process attached";
        return 0;
    }

#if defined(_WIN64)
    BOOL wow64 = FALSE;
    if (!IsWow64Process(process_, &wow64)) {
        error = win32ErrorMessage(GetLastError());
        return 0;
    }
    error.clear();
    return wow64 ? 4u : 8u;
#else
    // A 32-bit Cheat Wizard build can reliably address only 32-bit targets. The project
    // recommends the x64 build; keep this path explicit rather than guessing.
    error.clear();
    return 4u;
#endif
}

void ProcessManager::detach() {
    if (process_) {
        CloseHandle(process_);
        process_ = nullptr;
    }
    pid_ = 0;
}

std::string win32ErrorMessage(DWORD errorCode) {
    LPSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD size = FormatMessageA(
        flags, nullptr, errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer), 0, nullptr);

    if (size == 0 || !buffer) {
        std::ostringstream out;
        out << "Win32 error " << errorCode;
        return out.str();
    }

    std::string message(buffer, size);
    LocalFree(buffer);
    while (!message.empty() && (message.back() == '\r' || message.back() == '\n')) {
        message.pop_back();
    }
    return message;
}

} // namespace cw
