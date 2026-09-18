#include <Windows.h>

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::wstring quote(const std::wstring& value) { return L"\"" + value + L"\""; }

bool contains(const std::string& text, std::string_view needle) {
    return text.find(needle) != std::string::npos;
}

std::wstring makeTempPath(const wchar_t* stem, DWORD pid, ULONGLONG nonce) {
    wchar_t temp[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temp);
    if (length == 0 || length >= MAX_PATH) return {};
    return std::wstring(temp) + stem + L"-" + std::to_wstring(pid) + L"-" +
        std::to_wstring(nonce) + L".txt";
}

bool waitForFile(const std::wstring& path, DWORD timeoutMs) {
    const ULONGLONG start = GetTickCount64();
    while (GetTickCount64() - start < timeoutMs) {
        const DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) return true;
        Sleep(10);
    }
    return false;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        std::cerr << "CliFrontendTests requires paths to cw.exe and cw_cli_target.exe\n";
        return 2;
    }

    const DWORD selfPid = GetCurrentProcessId();
    const ULONGLONG nonce = GetTickCount64();
    const std::wstring metadataPath = makeTempPath(L"cw-cli-target", selfPid, nonce);
    const std::wstring inputPath = makeTempPath(L"cw-cli-input", selfPid, nonce);
    const std::wstring outputPath = makeTempPath(L"cw-cli-output", selfPid, nonce);
    if (metadataPath.empty() || inputPath.empty() || outputPath.empty()) return 3;
    DeleteFileW(metadataPath.c_str());
    DeleteFileW(inputPath.c_str());
    DeleteFileW(outputPath.c_str());

    const std::wstring eventName = L"Local\\CheatWizard.CliFrontendTest." +
        std::to_wstring(selfPid) + L"." + std::to_wstring(nonce);
    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, eventName.c_str());
    if (!stopEvent) return 4;

    std::wstring targetCommand = quote(argv[2]) + L" " + quote(metadataPath) + L" " + quote(eventName);
    std::vector<wchar_t> targetLine(targetCommand.begin(), targetCommand.end());
    targetLine.push_back(L'\0');
    STARTUPINFOW targetStartup{};
    targetStartup.cb = sizeof(targetStartup);
    PROCESS_INFORMATION target{};
    if (!CreateProcessW(argv[2], targetLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &targetStartup, &target)) {
        CloseHandle(stopEvent);
        return 5;
    }
    CloseHandle(target.hThread);

    auto cleanup = [&] {
        SetEvent(stopEvent);
        WaitForSingleObject(target.hProcess, 3000);
        CloseHandle(target.hProcess);
        CloseHandle(stopEvent);
        DeleteFileW(metadataPath.c_str());
        DeleteFileW(inputPath.c_str());
        DeleteFileW(outputPath.c_str());
    };

    if (!waitForFile(metadataPath, 5000)) {
        std::cerr << "Target metadata was not created\n";
        cleanup();
        return 6;
    }

    DWORD targetPid = 0;
    std::uintptr_t probeAddress = 0;
    std::uintptr_t pointerSlot = 0;
    {
        std::ifstream metadata(metadataPath);
        std::string pidText, probeText, slotText;
        if (!std::getline(metadata, pidText) || !std::getline(metadata, probeText) || !std::getline(metadata, slotText)) {
            cleanup();
            return 7;
        }
        try {
            targetPid = static_cast<DWORD>(std::stoul(pidText, nullptr, 10));
            probeAddress = static_cast<std::uintptr_t>(std::stoull(probeText, nullptr, 0));
            pointerSlot = static_cast<std::uintptr_t>(std::stoull(slotText, nullptr, 0));
        } catch (...) {
            cleanup();
            return 8;
        }
    }
    if (targetPid == 0 || probeAddress == 0 || pointerSlot == 0) { cleanup(); return 9; }

    std::ostringstream address;
    address << "0x" << std::hex << std::uppercase << probeAddress;
    const auto addressText = address.str();
    std::ostringstream rangeMin;
    rangeMin << "0x" << std::hex << std::uppercase << (probeAddress - 64);
    std::ostringstream rangeMax;
    rangeMax << "0x" << std::hex << std::uppercase << (probeAddress + 64);

    {
        std::ofstream input(inputPath, std::ios::binary | std::ios::trunc);
        input << "attach " << targetPid << "\n";
        input << "modules\n";
        input << "read-at " << addressText << " int32\n";
        input << "settings alignment byte\n";
        input << "settings range " << rangeMin.str() << ' ' << rangeMax.str() << "\n";
        input << "scan int32 305441741\n";
        input << "results 20\n";
        input << "aob CD AB 34 12\n";
        input << "aob-results 20\n";
        input << "write-at " << addressText << " int32 777777\n";
        input << "read-at " << addressText << " int32\n";
        input << "freeze-at " << addressText << " int32 888888 10\n";
        input << "watch " << addressText << " 2 50\n";
        input << "freezes\n";
        input << "unfreeze all\n";
        input << "pointer-scan " << addressText << " 1 0 64 0\n";
        input << "pointer-results 10\n";
        input << "status\n";
        input << "detach\n";
        input << "quit\n";
    }

    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE inputHandle = CreateFileW(inputPath.c_str(), GENERIC_READ, FILE_SHARE_READ, &security,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    HANDLE outputHandle = CreateFileW(outputPath.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, &security,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (inputHandle == INVALID_HANDLE_VALUE || outputHandle == INVALID_HANDLE_VALUE) {
        if (inputHandle != INVALID_HANDLE_VALUE) CloseHandle(inputHandle);
        if (outputHandle != INVALID_HANDLE_VALUE) CloseHandle(outputHandle);
        cleanup();
        return 10;
    }

    STARTUPINFOW cliStartup{};
    cliStartup.cb = sizeof(cliStartup);
    cliStartup.dwFlags = STARTF_USESTDHANDLES;
    cliStartup.hStdInput = inputHandle;
    cliStartup.hStdOutput = outputHandle;
    cliStartup.hStdError = outputHandle;
    PROCESS_INFORMATION cli{};
    std::wstring cliCommand = quote(argv[1]);
    std::vector<wchar_t> cliLine(cliCommand.begin(), cliCommand.end());
    cliLine.push_back(L'\0');
    const BOOL started = CreateProcessW(argv[1], cliLine.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &cliStartup, &cli);
    CloseHandle(inputHandle);
    CloseHandle(outputHandle);
    if (!started) {
        cleanup();
        return 11;
    }
    CloseHandle(cli.hThread);

    const DWORD cliWait = WaitForSingleObject(cli.hProcess, 30000);
    DWORD cliExit = 999;
    if (cliWait == WAIT_OBJECT_0) GetExitCodeProcess(cli.hProcess, &cliExit);
    if (cliWait != WAIT_OBJECT_0) TerminateProcess(cli.hProcess, 93);
    CloseHandle(cli.hProcess);

    std::ifstream outputFile(outputPath, std::ios::binary);
    std::string output((std::istreambuf_iterator<char>(outputFile)), std::istreambuf_iterator<char>());

    bool ok = cliWait == WAIT_OBJECT_0 && cliExit == 0;
    const std::string attachNeedle = "Attached to PID " + std::to_string(targetPid);
    ok = ok && contains(output, attachNeedle);
    ok = ok && contains(output, "[4 Bytes (int32)] = 305441741");
    ok = ok && contains(output, "Scanning 4 Bytes (int32) for exact value 305441741");
    ok = ok && contains(output, addressText);
    ok = ok && contains(output, "AOB scan (4 bytes): CD AB 34 12");
    ok = ok && contains(output, "Wrote 777777 as 4 Bytes (int32)");
    ok = ok && contains(output, "[4 Bytes (int32)] = 777777");
    ok = ok && contains(output, "Freeze #");
    ok = ok && contains(output, "888888");
    ok = ok && contains(output, "All freeze jobs stopped.");
    ok = ok && contains(output, "Pointer size: 64-bit");
    ok = ok && contains(output, "Total pointer chains:");
    ok = ok && !contains(output, "Total pointer chains: 0");
    ok = ok && contains(output, "Process PID: " + std::to_string(targetPid));
    ok = ok && contains(output, "Detached. Freeze jobs cleared; stored pointer chains were kept for rescan.");

    if (!ok) {
        std::cerr << "CLI E2E failed. Exit=" << cliExit << "\n--- output ---\n" << output << "\n--- end ---\n";
    }

    cleanup();
    if (!ok) return 1;
    std::cout << "CLI frontend IPC tests PASS\n";
    return 0;
}
