#pragma once

#include "cw/EnginePipe.hpp"
#include "cw/MemoryWriter.hpp"
#include "cw/ProcessManager.hpp"
#include "cw/Value.hpp"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace cw {

class EngineClient {
public:
    EngineClient() = default;
    ~EngineClient();

    EngineClient(const EngineClient&) = delete;
    EngineClient& operator=(const EngineClient&) = delete;

    bool start(std::string& error, std::wstring enginePath = {});
    void shutdown() noexcept;

    [[nodiscard]] bool connected() const noexcept { return pipe_.connected(); }
    [[nodiscard]] bool attached() const noexcept { return attached_; }
    [[nodiscard]] DWORD pid() const noexcept { return pid_; }
    [[nodiscard]] std::size_t targetPointerSize() const noexcept { return pointerSize_; }
    [[nodiscard]] const std::string& engineVersion() const noexcept { return engineVersion_; }

    bool listProcesses(std::vector<ProcessInfo>& processes, std::string& error);
    bool listModules(std::vector<ModuleInfo>& modules, std::string& error);
    bool attach(DWORD pid, std::string& error);
    bool attachByName(const std::wstring& name, std::string& error);
    bool detach(std::string& error);

    bool readBytes(
        std::uintptr_t address, void* buffer, std::size_t size, std::size_t& bytesRead, DWORD& readError, std::string& error);
    [[nodiscard]] std::optional<Value> readValue(std::uintptr_t address, ValueType type, std::string& error);
    [[nodiscard]] WriteResult writeValue(std::uintptr_t address, const Value& value, std::string& error);

    bool transact(
        EngineMessageKind kind,
        std::vector<std::byte> payload,
        EngineFrame& response,
        std::string& error);

private:
    static std::wstring defaultEnginePath();
    static std::wstring makePipeName();
    bool spawnEngine(const std::wstring& enginePath, const std::wstring& pipeName, std::string& error);
    bool handshake(std::string& error);
    void closeProcessHandle() noexcept;

    EnginePipeClient pipe_;
    HANDLE engineProcess_{nullptr};
    DWORD engineProcessId_{};
    std::uint64_t nextRequestId_{1};
    bool attached_{};
    DWORD pid_{};
    std::size_t pointerSize_{};
    std::string engineVersion_;
};

} // namespace cw
