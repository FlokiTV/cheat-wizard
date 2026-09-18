#pragma once

#include "cw/EngineProtocol.hpp"

#include <Windows.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace cw {

struct EngineFrame {
    EngineFrameHeader header;
    std::vector<std::byte> payload;
};

[[nodiscard]] bool isValidEnginePipeName(std::wstring_view name) noexcept;

class EnginePipeServer {
public:
    EnginePipeServer() = default;
    ~EnginePipeServer();

    EnginePipeServer(const EnginePipeServer&) = delete;
    EnginePipeServer& operator=(const EnginePipeServer&) = delete;

    bool create(const std::wstring& pipeName, DWORD ownerPid, std::string& error);
    bool accept(std::string& error);
    bool receive(EngineFrame& frame, std::string& error);
    bool send(const EngineFrame& frame, std::string& error);
    void disconnect() noexcept;
    void close() noexcept;

    [[nodiscard]] bool connected() const noexcept { return connected_; }
    [[nodiscard]] DWORD ownerPid() const noexcept { return ownerPid_; }

private:
    HANDLE pipe_{INVALID_HANDLE_VALUE};
    DWORD ownerPid_{};
    bool connected_{};
};

class EnginePipeClient {
public:
    EnginePipeClient() = default;
    ~EnginePipeClient();

    EnginePipeClient(const EnginePipeClient&) = delete;
    EnginePipeClient& operator=(const EnginePipeClient&) = delete;

    bool connect(const std::wstring& pipeName, std::uint32_t timeoutMs, std::string& error);
    bool receive(EngineFrame& frame, std::string& error);
    bool send(const EngineFrame& frame, std::string& error);
    void close() noexcept;

    [[nodiscard]] bool connected() const noexcept { return pipe_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE pipe_{INVALID_HANDLE_VALUE};
};

} // namespace cw
