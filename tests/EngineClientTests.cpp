#include "cw/EngineClient.hpp"

#include <Windows.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool expect(bool condition, const char* message) {
    if (condition) return true;
    std::cerr << "FAIL: " << message << '\n';
    return false;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::cerr << "EngineClientTests requires path to cw-engine.exe\n";
        return 2;
    }

    bool ok = true;
    std::string error;
    cw::EngineClient client;
    ok &= expect(client.start(error, argv[1]), "client start/handshake");
    if (!ok) { std::cerr << error << '\n'; return 1; }
    ok &= expect(client.connected(), "client connected");
    ok &= expect(!client.engineVersion().empty(), "engine version available");

    std::vector<cw::ProcessInfo> processes;
    ok &= expect(client.listProcesses(processes, error) && !processes.empty(), "list processes");

    const DWORD selfPid = GetCurrentProcessId();
    ok &= expect(client.attach(selfPid, error), "attach self");
    ok &= expect(client.attached() && client.pid() == selfPid, "attach state");
    ok &= expect(client.targetPointerSize() == sizeof(void*), "pointer width");

    std::vector<cw::ModuleInfo> modules;
    ok &= expect(client.listModules(modules, error) && !modules.empty(), "list modules");

    volatile std::int32_t probe = 31415926;
    const auto address = reinterpret_cast<std::uintptr_t>(const_cast<std::int32_t*>(&probe));
    const auto read = client.readValue(address, cw::ValueType::Int32, error);
    ok &= expect(read && std::get<std::int32_t>(*read) == probe, "typed read over client");

    const std::int32_t wanted = 27182818;
    const auto write = client.writeValue(address, cw::Value{wanted}, error);
    ok &= expect(write.ok && probe == wanted, "typed write over client");

    std::int32_t raw{};
    std::size_t bytesRead = 0;
    DWORD readError = ERROR_SUCCESS;
    ok &= expect(client.readBytes(address, &raw, sizeof(raw), bytesRead, readError, error), "raw read over client");
    ok &= expect(bytesRead == sizeof(raw) && raw == wanted, "raw read value");

    ok &= expect(client.detach(error), "detach");
    ok &= expect(!client.attached(), "detached state");
    client.shutdown();
    ok &= expect(!client.connected(), "shutdown closes client");

    if (!ok) {
        if (!error.empty()) std::cerr << "Last error: " << error << '\n';
        return 1;
    }
    std::cout << "EngineClient tests PASS\n";
    return 0;
}
