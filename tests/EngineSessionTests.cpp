#include "cw/EngineSession.hpp"

#include <iostream>
#include <string>

namespace {

bool expect(bool condition, const char* message) {
    if (condition) return true;
    std::cerr << "FAIL: " << message << '\n';
    return false;
}

} // namespace

int main() {
    cw::EngineSession engine;
    bool ok = true;

    ok &= expect(!engine.attached(), "new EngineSession must start detached");
    ok &= expect(engine.pid() == 0, "detached EngineSession PID must be zero");

    std::string error;
    const auto modules = engine.listModules(error);
    ok &= expect(modules.empty(), "detached EngineSession must not expose modules");
    ok &= expect(!error.empty(), "detached module listing must report an error");

    error.clear();
    ok &= expect(engine.targetPointerSize(error) == 0, "detached target pointer size must be zero");
    ok &= expect(!error.empty(), "detached pointer-size query must report an error");

    error.clear();
    ok &= expect(!engine.refreshPointerContext(error), "detached pointer refresh must fail");
    ok &= expect(!error.empty(), "detached pointer refresh must report an error");

    ok &= expect(!engine.readValue(0, cw::ValueType::Int32).has_value(),
                 "detached typed read must fail");

    const auto write = engine.writeValue(0, cw::Value{std::int32_t{123}});
    ok &= expect(!write.ok, "detached write must fail");
    ok &= expect(write.error == ERROR_INVALID_HANDLE, "detached write must report invalid handle");

    std::size_t bytesRead = 99;
    DWORD readError = ERROR_SUCCESS;
    std::uint32_t raw{};
    ok &= expect(!engine.readBytes(0, &raw, sizeof(raw), bytesRead, readError),
                 "detached raw read must fail");
    ok &= expect(bytesRead == 0, "failed raw read must report zero bytes");

    engine.clearScans();
    engine.detach();
    ok &= expect(!engine.attached(), "detach must be idempotent");

    if (!ok) return 1;
    std::cout << "EngineSession tests PASS\n";
    return 0;
}
