#include "cw/EngineClient.hpp"

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <cstring>
#include <limits>
#include <sstream>
#include <span>
#include <utility>

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

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), required, nullptr, nullptr) != required) return {};
    return result;
}

std::wstring utf8ToWide(std::string_view value) {
    if (value.empty()) return {};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) return {};
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), required) != required) return {};
    return result;
}

std::optional<std::uint8_t> toWireType(ValueType type) {
    switch (type) {
        case ValueType::Byte: return std::uint8_t{1};
        case ValueType::Int16: return std::uint8_t{2};
        case ValueType::Int32: return std::uint8_t{3};
        case ValueType::Int64: return std::uint8_t{4};
        case ValueType::Float: return std::uint8_t{5};
        case ValueType::Double: return std::uint8_t{6};
    }
    return std::nullopt;
}

std::size_t wireValueSize(std::uint8_t wireType) {
    switch (wireType) {
        case 1: return sizeof(std::uint8_t);
        case 2: return sizeof(std::int16_t);
        case 3: return sizeof(std::int32_t);
        case 4: return sizeof(std::int64_t);
        case 5: return sizeof(float);
        case 6: return sizeof(double);
        default: return 0;
    }
}

template <typename T>
Value decodeValue(std::span<const std::byte> bytes) {
    T value{};
    std::memcpy(&value, bytes.data(), sizeof(value));
    return Value{value};
}

std::optional<Value> decodeWireValue(std::uint8_t wireType, std::span<const std::byte> bytes) {
    if (bytes.size() != wireValueSize(wireType)) return std::nullopt;
    switch (wireType) {
        case 1: return decodeValue<std::uint8_t>(bytes);
        case 2: return decodeValue<std::int16_t>(bytes);
        case 3: return decodeValue<std::int32_t>(bytes);
        case 4: return decodeValue<std::int64_t>(bytes);
        case 5: return decodeValue<float>(bytes);
        case 6: return decodeValue<double>(bytes);
        default: return std::nullopt;
    }
}

ValueType valueTypeForValue(const Value& value) {
    switch (value.index()) {
        case 0: return ValueType::Byte;
        case 1: return ValueType::Int16;
        case 2: return ValueType::Int32;
        case 3: return ValueType::Int64;
        case 4: return ValueType::Float;
        case 5: return ValueType::Double;
        default: return ValueType::Int32;
    }
}

std::vector<std::byte> encodeValue(const Value& value) {
    return std::visit([](const auto& typed) {
        std::vector<std::byte> bytes(sizeof(typed));
        std::memcpy(bytes.data(), &typed, sizeof(typed));
        return bytes;
    }, value);
}

bool decodeErrorFrame(const EngineFrame& frame, std::string& error) {
    EngineBufferReader reader(frame.payload);
    std::uint32_t code = 0;
    std::string message;
    if (!reader.readU32(code) || !reader.readString(message) || !reader.empty()) {
        error = "Engine returned a malformed error frame";
        return false;
    }
    std::ostringstream out;
    out << message;
    if (code != 0) out << " (code " << code << ')';
    error = out.str();
    return true;
}

} // namespace

EngineClient::~EngineClient() {
    shutdown();
}

std::wstring EngineClient::defaultEnginePath() {
    std::array<wchar_t, 32768> buffer{};
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return L"cw-engine.exe";
    std::wstring path(buffer.data(), length);
    const auto slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L"cw-engine.exe";
    path.resize(slash + 1);
    path += L"cw-engine.exe";
    return path;
}

std::wstring EngineClient::makePipeName() {
    std::uint64_t randomValue = 0;
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&randomValue), sizeof(randomValue),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        randomValue = (static_cast<std::uint64_t>(GetTickCount64()) << 32u) ^ GetCurrentProcessId();
    }
    std::wostringstream out;
    out << L"\\\\.\\pipe\\CheatWizard.Engine." << kEngineProtocolMajor << L'.'
        << GetCurrentProcessId() << L'.' << std::hex << randomValue;
    return out.str();
}

bool EngineClient::spawnEngine(const std::wstring& enginePath, const std::wstring& pipeName, std::string& error) {
    std::wstring command = L"\"" + enginePath + L"\" --pipe \"" + pipeName +
        L"\" --owner-pid " + std::to_wstring(GetCurrentProcessId());
    std::vector<wchar_t> commandLine(command.begin(), command.end());
    commandLine.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(enginePath.c_str(), commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &process)) {
        error = "Could not start cw-engine.exe: " + formatWin32Error(GetLastError());
        return false;
    }
    CloseHandle(process.hThread);
    engineProcess_ = process.hProcess;
    engineProcessId_ = process.dwProcessId;
    error.clear();
    return true;
}

bool EngineClient::handshake(std::string& error) {
    EngineBufferWriter payload;
    payload.writeString("cw-frontend");
    EngineFrame response;
    if (!transact(EngineMessageKind::Hello, payload.take(), response, error)) return false;
    if (response.header.kind != EngineMessageKind::HelloAck) {
        error = "Unexpected engine handshake response";
        return false;
    }
    EngineBufferReader reader(response.payload);
    std::uint16_t major = 0;
    std::uint16_t minor = 0;
    std::string version;
    if (!reader.readU16(major) || !reader.readU16(minor) || !reader.readString(version) || !reader.empty()) {
        error = "Malformed engine handshake response";
        return false;
    }
    if (major != kEngineProtocolMajor) {
        error = "Engine protocol major mismatch";
        return false;
    }
    engineVersion_ = std::move(version);
    error.clear();
    return true;
}

bool EngineClient::start(std::string& error, std::wstring enginePath) {
    shutdown();
    if (enginePath.empty()) enginePath = defaultEnginePath();
    const auto pipeName = makePipeName();
    if (!spawnEngine(enginePath, pipeName, error)) return false;
    if (!pipe_.connect(pipeName, 5000, error)) {
        if (engineProcess_) TerminateProcess(engineProcess_, 90);
        closeProcessHandle();
        return false;
    }
    nextRequestId_ = 1;
    if (!handshake(error)) {
        pipe_.close();
        if (engineProcess_) TerminateProcess(engineProcess_, 91);
        closeProcessHandle();
        return false;
    }
    return true;
}

bool EngineClient::transact(
    EngineMessageKind kind, std::vector<std::byte> payload, EngineFrame& response, std::string& error)
{
    if (!pipe_.connected()) { error = "Engine client is not connected"; return false; }
    EngineFrame request;
    request.header.kind = kind;
    request.header.requestId = nextRequestId_++;
    if (request.header.requestId == 0) request.header.requestId = nextRequestId_++;
    request.payload = std::move(payload);
    if (!pipe_.send(request, error) || !pipe_.receive(response, error)) return false;
    if (response.header.requestId != request.header.requestId) {
        error = "Engine response request id mismatch";
        return false;
    }
    if (response.header.kind == EngineMessageKind::Error) {
        decodeErrorFrame(response, error);
        return false;
    }
    error.clear();
    return true;
}

bool EngineClient::listProcesses(std::vector<ProcessInfo>& processes, std::string& error) {
    EngineFrame response;
    if (!transact(EngineMessageKind::ListProcesses, {}, response, error)) return false;
    if (response.header.kind != EngineMessageKind::ListProcessesResult) { error = "Unexpected ListProcesses response"; return false; }
    EngineBufferReader reader(response.payload);
    std::uint32_t count = 0;
    if (!reader.readU32(count) || count > 1'000'000) { error = "Malformed process list"; return false; }
    std::vector<ProcessInfo> decoded;
    decoded.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t pid = 0;
        std::string name;
        if (!reader.readU32(pid) || !reader.readString(name)) { error = "Truncated process list"; return false; }
        const auto wideName = utf8ToWide(name);
        if (!name.empty() && wideName.empty()) { error = "Invalid UTF-8 process name"; return false; }
        decoded.push_back(ProcessInfo{pid, wideName});
    }
    if (!reader.empty()) { error = "Process list has trailing bytes"; return false; }
    processes = std::move(decoded);
    return true;
}

bool EngineClient::listModules(std::vector<ModuleInfo>& modules, std::string& error) {
    EngineFrame response;
    if (!transact(EngineMessageKind::ListModules, {}, response, error)) return false;
    if (response.header.kind != EngineMessageKind::ListModulesResult) { error = "Unexpected ListModules response"; return false; }
    EngineBufferReader reader(response.payload);
    std::uint32_t count = 0;
    if (!reader.readU32(count) || count > 100'000) { error = "Malformed module list"; return false; }
    std::vector<ModuleInfo> decoded;
    decoded.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        std::string name;
        std::string path;
        if (!reader.readU64(base) || !reader.readU64(size) || !reader.readString(name) || !reader.readString(path)) {
            error = "Truncated module list";
            return false;
        }
        const auto wideName = utf8ToWide(name);
        const auto widePath = utf8ToWide(path);
        if ((!name.empty() && wideName.empty()) || (!path.empty() && widePath.empty())) {
            error = "Invalid UTF-8 module metadata";
            return false;
        }
        decoded.push_back(ModuleInfo{static_cast<std::uintptr_t>(base), static_cast<std::size_t>(size), wideName, widePath});
    }
    if (!reader.empty()) { error = "Module list has trailing bytes"; return false; }
    modules = std::move(decoded);
    return true;
}

bool EngineClient::attach(DWORD pid, std::string& error) {
    EngineBufferWriter payload;
    payload.writeU32(pid);
    EngineFrame response;
    if (!transact(EngineMessageKind::AttachProcess, payload.take(), response, error)) return false;
    if (response.header.kind != EngineMessageKind::AttachProcessResult) { error = "Unexpected AttachProcess response"; return false; }
    EngineBufferReader reader(response.payload);
    std::uint8_t ok = 0;
    std::uint32_t attachedPid = 0;
    std::uint16_t pointerSize = 0;
    std::string attachError;
    if (!reader.readU8(ok) || !reader.readU32(attachedPid) || !reader.readU16(pointerSize) ||
        !reader.readString(attachError) || !reader.empty()) {
        error = "Malformed AttachProcess response";
        return false;
    }
    if (!ok) { error = attachError.empty() ? "Attach failed" : attachError; return false; }
    attached_ = true;
    pid_ = attachedPid;
    pointerSize_ = pointerSize;
    error.clear();
    return true;
}

bool EngineClient::attachByName(const std::wstring& name, std::string& error) {
    std::vector<ProcessInfo> processes;
    if (!listProcesses(processes, error)) return false;
    auto lower = [](std::wstring text) {
        std::transform(text.begin(), text.end(), text.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
        return text;
    };
    const auto wanted = lower(name);
    for (const auto& process : processes) {
        if (lower(process.name) == wanted) return attach(process.pid, error);
    }
    error = "Process name not found";
    return false;
}

bool EngineClient::detach(std::string& error) {
    if (!pipe_.connected()) { attached_ = false; pid_ = 0; pointerSize_ = 0; error.clear(); return true; }
    EngineFrame response;
    if (!transact(EngineMessageKind::DetachProcess, {}, response, error)) return false;
    if (response.header.kind != EngineMessageKind::DetachProcessResult) { error = "Unexpected DetachProcess response"; return false; }
    attached_ = false;
    pid_ = 0;
    pointerSize_ = 0;
    error.clear();
    return true;
}

bool EngineClient::readBytes(
    std::uintptr_t address, void* buffer, std::size_t size, std::size_t& bytesRead, DWORD& readError, std::string& error)
{
    bytesRead = 0;
    readError = ERROR_SUCCESS;
    if (!buffer || size == 0 || size > 1024u * 1024u) { error = "Read size is invalid"; return false; }
    EngineBufferWriter payload;
    payload.writeU64(static_cast<std::uint64_t>(address));
    payload.writeU32(static_cast<std::uint32_t>(size));
    EngineFrame response;
    if (!transact(EngineMessageKind::ReadBytes, payload.take(), response, error)) return false;
    if (response.header.kind != EngineMessageKind::ReadBytesResult) { error = "Unexpected ReadBytes response"; return false; }
    EngineBufferReader reader(response.payload);
    std::uint8_t ok = 0;
    std::uint32_t wireReadError = 0;
    std::uint32_t count = 0;
    if (!reader.readU8(ok) || !reader.readU32(wireReadError) || !reader.readU32(count) ||
        count > size || reader.remaining() != count) {
        error = "Malformed ReadBytes response";
        return false;
    }
    readError = static_cast<DWORD>(wireReadError);
    if (count != 0) {
        if (!reader.readBytes(std::span(static_cast<std::byte*>(buffer), count))) { error = "Truncated ReadBytes response"; return false; }
    }
    bytesRead = count;
    if (!ok) { error = "Engine could not read requested bytes"; return false; }
    error.clear();
    return true;
}

std::optional<Value> EngineClient::readValue(std::uintptr_t address, ValueType type, std::string& error) {
    const auto wireType = toWireType(type);
    if (!wireType) { error = "Invalid value type"; return std::nullopt; }
    EngineBufferWriter payload;
    payload.writeU64(static_cast<std::uint64_t>(address));
    payload.writeU8(*wireType);
    EngineFrame response;
    if (!transact(EngineMessageKind::ReadValue, payload.take(), response, error)) return std::nullopt;
    if (response.header.kind != EngineMessageKind::ReadValueResult) { error = "Unexpected ReadValue response"; return std::nullopt; }
    EngineBufferReader reader(response.payload);
    std::uint8_t ok = 0;
    std::uint8_t responseType = 0;
    std::uint32_t readError = 0;
    std::uint8_t size = 0;
    if (!reader.readU8(ok) || !reader.readU8(responseType) || !reader.readU32(readError) || !reader.readU8(size)) {
        error = "Malformed ReadValue response";
        return std::nullopt;
    }
    if (!ok || responseType != *wireType || size != wireValueSize(responseType) || reader.remaining() != size) {
        error = "Engine could not read value";
        return std::nullopt;
    }
    std::array<std::byte, 8> bytes{};
    if (!reader.readBytes(std::span(bytes.data(), size)) || !reader.empty()) { error = "Truncated ReadValue response"; return std::nullopt; }
    auto value = decodeWireValue(responseType, std::span(bytes.data(), size));
    if (!value) { error = "Invalid ReadValue payload"; return std::nullopt; }
    error.clear();
    return value;
}

WriteResult EngineClient::writeValue(std::uintptr_t address, const Value& value, std::string& error) {
    WriteResult result{};
    const auto type = valueTypeForValue(value);
    const auto wireType = toWireType(type);
    const auto bytes = encodeValue(value);
    if (!wireType || bytes.empty()) { error = "Invalid write value"; result.error = ERROR_INVALID_DATA; return result; }

    EngineBufferWriter payload;
    payload.writeU64(static_cast<std::uint64_t>(address));
    payload.writeU8(*wireType);
    payload.writeU8(static_cast<std::uint8_t>(bytes.size()));
    payload.writeBytes(bytes);
    EngineFrame response;
    if (!transact(EngineMessageKind::WriteValue, payload.take(), response, error)) { result.error = ERROR_GEN_FAILURE; return result; }
    if (response.header.kind != EngineMessageKind::WriteValueResult) { error = "Unexpected WriteValue response"; result.error = ERROR_INVALID_DATA; return result; }
    EngineBufferReader reader(response.payload);
    std::uint8_t ok = 0;
    std::uint32_t written = 0;
    std::uint32_t writeError = 0;
    if (!reader.readU8(ok) || !reader.readU32(written) || !reader.readU32(writeError) || !reader.empty()) {
        error = "Malformed WriteValue response";
        result.error = ERROR_INVALID_DATA;
        return result;
    }
    result.ok = ok != 0;
    result.bytesWritten = written;
    result.error = writeError;
    error.clear();
    return result;
}

void EngineClient::closeProcessHandle() noexcept {
    if (engineProcess_) { CloseHandle(engineProcess_); engineProcess_ = nullptr; }
    engineProcessId_ = 0;
}

void EngineClient::shutdown() noexcept {
    if (pipe_.connected()) {
        EngineFrame response;
        std::string ignored;
        transact(EngineMessageKind::Shutdown, {}, response, ignored);
        pipe_.close();
    }
    if (engineProcess_) {
        const DWORD wait = WaitForSingleObject(engineProcess_, 3000);
        if (wait != WAIT_OBJECT_0) {
            TerminateProcess(engineProcess_, 92);
            WaitForSingleObject(engineProcess_, 1000);
        }
    }
    closeProcessHandle();
    attached_ = false;
    pid_ = 0;
    pointerSize_ = 0;
    engineVersion_.clear();
}

} // namespace cw
