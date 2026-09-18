#include "cw/EnginePipe.hpp"

#include <sddl.h>

#include <algorithm>
#include <array>
#include <sstream>
#include <utility>
#include <vector>

namespace cw {
namespace {

std::string formatWin32Error(DWORD code) {
    LPSTR buffer = nullptr;
    const DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer), 0, nullptr);
    if (!size || !buffer) {
        std::ostringstream out;
        out << "Win32 error " << code;
        return out.str();
    }
    std::string text(buffer, size);
    LocalFree(buffer);
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n')) text.pop_back();
    return text;
}

bool buildCurrentUserSecurityDescriptor(PSECURITY_DESCRIPTOR& descriptor, std::string& error) {
    descriptor = nullptr;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error = "OpenProcessToken failed: " + formatWin32Error(GetLastError());
        return false;
    }

    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0) {
        const auto code = GetLastError();
        CloseHandle(token);
        error = "GetTokenInformation size failed: " + formatWin32Error(code);
        return false;
    }

    std::vector<std::byte> storage(bytes);
    if (!GetTokenInformation(token, TokenUser, storage.data(), bytes, &bytes)) {
        const auto code = GetLastError();
        CloseHandle(token);
        error = "GetTokenInformation failed: " + formatWin32Error(code);
        return false;
    }
    CloseHandle(token);

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(storage.data());
    LPWSTR sidText = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidText) || !sidText) {
        error = "ConvertSidToStringSid failed: " + formatWin32Error(GetLastError());
        return false;
    }

    std::wstring sddl = L"D:P(A;;GA;;;";
    sddl += sidText;
    sddl += L")";
    LocalFree(sidText);

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        error = "Security descriptor conversion failed: " + formatWin32Error(GetLastError());
        descriptor = nullptr;
        return false;
    }
    error.clear();
    return true;
}

bool readExact(HANDLE pipe, void* destination, std::size_t size, std::string& error) {
    auto* cursor = static_cast<std::byte*>(destination);
    std::size_t offset = 0;
    while (offset < size) {
        const auto chunk = static_cast<DWORD>((std::min)(size - offset, std::size_t{64 * 1024}));
        DWORD read = 0;
        if (!ReadFile(pipe, cursor + offset, chunk, &read, nullptr)) {
            error = "Named Pipe read failed: " + formatWin32Error(GetLastError());
            return false;
        }
        if (read == 0) {
            error = "Named Pipe closed during read";
            return false;
        }
        offset += read;
    }
    return true;
}

bool writeExact(HANDLE pipe, const void* source, std::size_t size, std::string& error) {
    const auto* cursor = static_cast<const std::byte*>(source);
    std::size_t offset = 0;
    while (offset < size) {
        const auto chunk = static_cast<DWORD>((std::min)(size - offset, std::size_t{64 * 1024}));
        DWORD written = 0;
        if (!WriteFile(pipe, cursor + offset, chunk, &written, nullptr)) {
            error = "Named Pipe write failed: " + formatWin32Error(GetLastError());
            return false;
        }
        if (written == 0) {
            error = "Named Pipe closed during write";
            return false;
        }
        offset += written;
    }
    return true;
}

bool receiveFrame(HANDLE pipe, EngineFrame& frame, std::string& error) {
    std::array<std::byte, kEngineFrameHeaderSize> rawHeader{};
    if (!readExact(pipe, rawHeader.data(), rawHeader.size(), error)) return false;

    EngineFrameHeader header;
    if (!decodeEngineFrameHeader(rawHeader, header, error)) return false;

    std::vector<std::byte> payload(header.payloadSize);
    if (!payload.empty() && !readExact(pipe, payload.data(), payload.size(), error)) return false;

    frame.header = header;
    frame.payload = std::move(payload);
    error.clear();
    return true;
}

bool sendFrame(HANDLE pipe, const EngineFrame& frame, std::string& error) {
    if (frame.payload.size() > kEngineMaxPayloadSize) {
        error = "Engine frame payload exceeds limit";
        return false;
    }

    EngineFrameHeader header = frame.header;
    header.payloadSize = static_cast<std::uint32_t>(frame.payload.size());
    std::array<std::byte, kEngineFrameHeaderSize> rawHeader{};
    if (!encodeEngineFrameHeader(header, rawHeader)) {
        error = "Could not encode engine frame header";
        return false;
    }

    if (!writeExact(pipe, rawHeader.data(), rawHeader.size(), error)) return false;
    if (!frame.payload.empty() && !writeExact(pipe, frame.payload.data(), frame.payload.size(), error)) return false;
    error.clear();
    return true;
}

} // namespace

bool isValidEnginePipeName(std::wstring_view name) noexcept {
    constexpr std::wstring_view prefix = L"\\\\.\\pipe\\CheatWizard.Engine.";
    if (!name.starts_with(prefix) || name.size() <= prefix.size()) return false;
    if (name.size() > 240) return false;
    for (std::size_t i = prefix.size(); i < name.size(); ++i) {
        const wchar_t c = name[i];
        const bool allowed = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                             (c >= L'0' && c <= L'9') || c == L'.' || c == L'-' || c == L'_';
        if (!allowed) return false;
    }
    return true;
}

EnginePipeServer::~EnginePipeServer() { close(); }

bool EnginePipeServer::create(const std::wstring& pipeName, DWORD ownerPid, std::string& error) {
    close();
    if (!isValidEnginePipeName(pipeName) || ownerPid == 0) {
        error = "Invalid engine pipe name or owner PID";
        return false;
    }

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!buildCurrentUserSecurityDescriptor(descriptor, error)) return false;

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;

    pipe_ = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 64 * 1024, 64 * 1024, 5000, &attributes);

    const DWORD createError = pipe_ == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    LocalFree(descriptor);
    if (pipe_ == INVALID_HANDLE_VALUE) {
        error = "CreateNamedPipe failed: " + formatWin32Error(createError);
        return false;
    }

    ownerPid_ = ownerPid;
    connected_ = false;
    error.clear();
    return true;
}

bool EnginePipeServer::accept(std::string& error) {
    if (pipe_ == INVALID_HANDLE_VALUE) { error = "Engine pipe server is not created"; return false; }
    if (connected_) return true;

    if (!ConnectNamedPipe(pipe_, nullptr)) {
        const DWORD code = GetLastError();
        if (code != ERROR_PIPE_CONNECTED) {
            error = "ConnectNamedPipe failed: " + formatWin32Error(code);
            return false;
        }
    }

    ULONG clientPid = 0;
    if (!GetNamedPipeClientProcessId(pipe_, &clientPid)) {
        error = "Could not identify Named Pipe client: " + formatWin32Error(GetLastError());
        DisconnectNamedPipe(pipe_);
        return false;
    }
    if (clientPid != ownerPid_) {
        std::ostringstream out;
        out << "Named Pipe client PID " << clientPid << " does not match owner PID " << ownerPid_;
        error = out.str();
        DisconnectNamedPipe(pipe_);
        return false;
    }

    connected_ = true;
    error.clear();
    return true;
}

bool EnginePipeServer::receive(EngineFrame& frame, std::string& error) {
    if (!connected_) { error = "Engine pipe client is not connected"; return false; }
    return receiveFrame(pipe_, frame, error);
}

bool EnginePipeServer::send(const EngineFrame& frame, std::string& error) {
    if (!connected_) { error = "Engine pipe client is not connected"; return false; }
    return sendFrame(pipe_, frame, error);
}

void EnginePipeServer::disconnect() noexcept {
    if (pipe_ != INVALID_HANDLE_VALUE && connected_) {
        FlushFileBuffers(pipe_);
        DisconnectNamedPipe(pipe_);
    }
    connected_ = false;
}

void EnginePipeServer::close() noexcept {
    disconnect();
    if (pipe_ != INVALID_HANDLE_VALUE) { CloseHandle(pipe_); pipe_ = INVALID_HANDLE_VALUE; }
    ownerPid_ = 0;
}

EnginePipeClient::~EnginePipeClient() { close(); }

bool EnginePipeClient::connect(const std::wstring& pipeName, std::uint32_t timeoutMs, std::string& error) {
    close();
    if (!isValidEnginePipeName(pipeName)) { error = "Invalid engine pipe name"; return false; }

    const ULONGLONG started = GetTickCount64();
    for (;;) {
        pipe_ = CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe_ != INVALID_HANDLE_VALUE) break;

        const DWORD code = GetLastError();
        const ULONGLONG elapsed = GetTickCount64() - started;
        if (elapsed >= timeoutMs || (code != ERROR_PIPE_BUSY && code != ERROR_FILE_NOT_FOUND)) {
            error = "Could not connect to engine pipe: " + formatWin32Error(code);
            return false;
        }
        const DWORD remaining = static_cast<DWORD>((std::min<ULONGLONG>)(timeoutMs - elapsed, 100));
        if (remaining == 0) { error = "Timed out waiting for engine pipe"; return false; }
        WaitNamedPipeW(pipeName.c_str(), remaining);
        Sleep(1);
    }

    error.clear();
    return true;
}

bool EnginePipeClient::receive(EngineFrame& frame, std::string& error) {
    if (pipe_ == INVALID_HANDLE_VALUE) { error = "Engine pipe client is not connected"; return false; }
    return receiveFrame(pipe_, frame, error);
}

bool EnginePipeClient::send(const EngineFrame& frame, std::string& error) {
    if (pipe_ == INVALID_HANDLE_VALUE) { error = "Engine pipe client is not connected"; return false; }
    return sendFrame(pipe_, frame, error);
}

void EnginePipeClient::close() noexcept {
    if (pipe_ != INVALID_HANDLE_VALUE) { CloseHandle(pipe_); pipe_ = INVALID_HANDLE_VALUE; }
}

} // namespace cw
