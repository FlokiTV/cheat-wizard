#include "cw/EnginePipe.hpp"

#include <Windows.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::wstring quote(const std::wstring& value) { return L"\"" + value + L"\""; }

bool writePidFile(const std::wstring& path, DWORD pid) {
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const std::string text = std::to_string(pid);
    DWORD written = 0;
    const BOOL ok = WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    CloseHandle(file);
    return ok && written == text.size();
}

bool readPidFile(const std::wstring& path, DWORD& pid) {
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    char buffer[64]{};
    DWORD read = 0;
    const BOOL ok = ReadFile(file, buffer, sizeof(buffer) - 1, &read, nullptr);
    CloseHandle(file);
    if (!ok || read == 0) return false;
    try {
        const auto parsed = std::stoul(std::string(buffer, read));
        if (parsed == 0 || parsed > 0xFFFFFFFFul) return false;
        pid = static_cast<DWORD>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

int runChild(const std::wstring& enginePath, const std::wstring& pidFile) {
    const DWORD ownerPid = GetCurrentProcessId();
    const std::wstring pipeName = L"\\\\.\\pipe\\CheatWizard.Engine.OwnerDeath." +
        std::to_wstring(ownerPid) + L"." + std::to_wstring(GetTickCount64());
    std::wstring command = quote(enginePath) + L" --pipe " + quote(pipeName) +
        L" --owner-pid " + std::to_wstring(ownerPid);
    std::vector<wchar_t> commandLine(command.begin(), command.end());
    commandLine.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION engine{};
    if (!CreateProcessW(enginePath.c_str(), commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &engine)) return 10;
    CloseHandle(engine.hThread);

    cw::EnginePipeClient client;
    std::string error;
    if (!client.connect(pipeName, 5000, error)) {
        TerminateProcess(engine.hProcess, 99);
        CloseHandle(engine.hProcess);
        return 11;
    }

    cw::EngineBufferWriter helloPayload;
    helloPayload.writeString("owner-death-child");
    cw::EngineFrame hello;
    hello.header.kind = cw::EngineMessageKind::Hello;
    hello.header.requestId = 1;
    hello.payload = helloPayload.take();
    if (!client.send(hello, error)) {
        TerminateProcess(engine.hProcess, 98);
        CloseHandle(engine.hProcess);
        return 12;
    }
    cw::EngineFrame ack;
    if (!client.receive(ack, error) || ack.header.kind != cw::EngineMessageKind::HelloAck) {
        TerminateProcess(engine.hProcess, 97);
        CloseHandle(engine.hProcess);
        return 13;
    }

    if (!writePidFile(pidFile, engine.dwProcessId)) {
        TerminateProcess(engine.hProcess, 96);
        CloseHandle(engine.hProcess);
        return 14;
    }

    // Deliberately do not send Shutdown and do not explicitly close the pipe.
    // Process teardown closes the owner-side pipe handle; the engine must observe
    // the broken pipe and terminate on its own.
    CloseHandle(engine.hProcess);
    ExitProcess(0);
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring_view(argv[1]) == L"--child") {
        return runChild(argv[2], argv[3]);
    }
    if (argc != 2) {
        std::cerr << "EngineOwnerDeathTests requires path to cw-engine.exe\n";
        return 2;
    }

    wchar_t selfPath[MAX_PATH]{};
    const DWORD selfLength = GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    if (selfLength == 0 || selfLength >= MAX_PATH) return 3;

    wchar_t tempDir[MAX_PATH]{};
    const DWORD tempLength = GetTempPathW(MAX_PATH, tempDir);
    if (tempLength == 0 || tempLength >= MAX_PATH) return 4;
    const std::wstring pidFile = std::wstring(tempDir) + L"cw-engine-owner-death-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L".txt";
    DeleteFileW(pidFile.c_str());

    std::wstring command = quote(selfPath) + L" --child " + quote(argv[1]) + L" " + quote(pidFile);
    std::vector<wchar_t> commandLine(command.begin(), command.end());
    commandLine.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(selfPath, commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &child)) {
        std::cerr << "Could not start owner child: " << GetLastError() << '\n';
        return 5;
    }
    CloseHandle(child.hThread);

    const DWORD childWait = WaitForSingleObject(child.hProcess, 10000);
    DWORD childExit = 99;
    if (childWait == WAIT_OBJECT_0) GetExitCodeProcess(child.hProcess, &childExit);
    CloseHandle(child.hProcess);
    if (childWait != WAIT_OBJECT_0 || childExit != 0) {
        DeleteFileW(pidFile.c_str());
        std::cerr << "Owner child failed: " << childExit << '\n';
        return 6;
    }

    DWORD enginePid = 0;
    if (!readPidFile(pidFile, enginePid)) {
        DeleteFileW(pidFile.c_str());
        std::cerr << "Could not read engine PID file\n";
        return 7;
    }
    DeleteFileW(pidFile.c_str());

    HANDLE engine = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, enginePid);
    if (!engine) {
        if (GetLastError() == ERROR_INVALID_PARAMETER) {
            std::cout << "Engine owner-death test PASS (engine already exited)\n";
            return 0;
        }
        std::cerr << "Could not open engine after owner exit: " << GetLastError() << '\n';
        return 8;
    }

    const DWORD wait = WaitForSingleObject(engine, 5000);
    DWORD exitCode = 999;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(engine, &exitCode);
    CloseHandle(engine);
    if (wait != WAIT_OBJECT_0 || exitCode != 0) {
        std::cerr << "Engine did not terminate cleanly after owner death\n";
        return 9;
    }

    std::cout << "Engine owner-death test PASS\n";
    return 0;
}
