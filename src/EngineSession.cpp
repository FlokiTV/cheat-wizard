#include "cw/EngineSession.hpp"

#include <Windows.h>

#include <utility>

namespace cw {

namespace {

template <typename T>
std::optional<Value> readTyped(HANDLE process, std::uintptr_t address) {
    T value{};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(
            process,
            reinterpret_cast<LPCVOID>(address),
            &value,
            sizeof(value),
            &bytesRead) ||
        bytesRead != sizeof(value)) {
        return std::nullopt;
    }
    return Value{value};
}

} // namespace

std::vector<ProcessInfo> EngineSession::listProcesses() const {
    return processManager_.listProcesses();
}

std::vector<ModuleInfo> EngineSession::listModules(std::string& error) const {
    return processManager_.listModules(error);
}

bool EngineSession::attach(DWORD pid, std::string& error) {
    detach();
    if (!processManager_.attach(pid, error)) return false;
    return bindAttachedProcess(error);
}

bool EngineSession::attachByName(const std::wstring& name, std::string& error) {
    detach();
    if (!processManager_.attachByName(name, error)) return false;
    return bindAttachedProcess(error);
}

bool EngineSession::bindAttachedProcess(std::string& error) {
    scanner_.setProcess(processManager_.handle());
    aobScanner_.setProcess(processManager_.handle());
    aobScanner_.setOptions(scanner_.options());

    if (!freezer_.setProcess(processManager_.handle())) {
        scanner_.setProcess(nullptr);
        aobScanner_.setProcess(nullptr);
        pointerScanner_.setProcess(nullptr, 0, {});
        processManager_.detach();
        error = "Could not duplicate process handle for freeze worker";
        return false;
    }

    std::string pointerError;
    refreshPointerContext(pointerError);
    error.clear();
    return true;
}

void EngineSession::detach() {
    freezer_.setProcess(nullptr);
    scanner_.setProcess(nullptr);
    aobScanner_.setProcess(nullptr);
    pointerScanner_.setProcess(nullptr, 0, {});
    processManager_.detach();
}

std::size_t EngineSession::targetPointerSize(std::string& error) const {
    return processManager_.targetPointerSize(error);
}

bool EngineSession::refreshPointerContext(std::string& error) {
    if (!processManager_.attached()) {
        error = "No process attached";
        pointerScanner_.setProcess(nullptr, 0, {});
        return false;
    }

    const auto pointerSize = processManager_.targetPointerSize(error);
    if (pointerSize == 0) {
        pointerScanner_.setProcess(nullptr, 0, {});
        return false;
    }

    auto modules = processManager_.listModules(error);
    if (modules.empty() && !error.empty()) {
        pointerScanner_.setProcess(nullptr, 0, {});
        return false;
    }

    pointerScanner_.setProcess(processManager_.handle(), pointerSize, std::move(modules));
    error.clear();
    return true;
}

void EngineSession::clearScans() {
    scanner_.clear();
    aobScanner_.clear();
}

std::optional<Value> EngineSession::readValue(std::uintptr_t address, ValueType type) const {
    if (!processManager_.attached()) return std::nullopt;
    switch (type) {
        case ValueType::Byte: return readTyped<std::uint8_t>(processManager_.handle(), address);
        case ValueType::Int16: return readTyped<std::int16_t>(processManager_.handle(), address);
        case ValueType::Int32: return readTyped<std::int32_t>(processManager_.handle(), address);
        case ValueType::Int64: return readTyped<std::int64_t>(processManager_.handle(), address);
        case ValueType::Float: return readTyped<float>(processManager_.handle(), address);
        case ValueType::Double: return readTyped<double>(processManager_.handle(), address);
    }
    return std::nullopt;
}

bool EngineSession::readBytes(
    std::uintptr_t address,
    void* buffer,
    std::size_t size,
    std::size_t& bytesRead,
    DWORD& error) const
{
    bytesRead = 0;
    error = ERROR_SUCCESS;
    if (!processManager_.attached() || !buffer || size == 0) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }

    SIZE_T nativeBytesRead = 0;
    const BOOL ok = ReadProcessMemory(
        processManager_.handle(),
        reinterpret_cast<LPCVOID>(address),
        buffer,
        size,
        &nativeBytesRead);
    bytesRead = static_cast<std::size_t>(nativeBytesRead);
    if (!ok) {
        error = GetLastError();
        return false;
    }
    return true;
}

WriteResult EngineSession::writeValue(std::uintptr_t address, const Value& value) const {
    return cw::writeValue(processManager_.handle(), address, value);
}

} // namespace cw
