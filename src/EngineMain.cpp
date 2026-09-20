#include "cw/EnginePipe.hpp"
#include "cw/EngineSession.hpp"
#include "cw/PointerProfile.hpp"
#include "cw/Value.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr const char* kEngineVersion = "1.7.3";

enum class WireValueType : std::uint8_t {
    Byte = 1,
    Int16 = 2,
    Int32 = 3,
    Int64 = 4,
    Float = 5,
    Double = 6,
};

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), required, nullptr, nullptr) != required) {
        return {};
    }
    return result;
}

std::wstring utf8ToWide(std::string_view value) {
    if (value.empty()) return {};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) return {};
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), required) != required) {
        return {};
    }
    return result;
}

std::optional<std::uint8_t> toWireType(cw::ValueType type) {
    switch (type) {
        case cw::ValueType::Byte: return static_cast<std::uint8_t>(WireValueType::Byte);
        case cw::ValueType::Int16: return static_cast<std::uint8_t>(WireValueType::Int16);
        case cw::ValueType::Int32: return static_cast<std::uint8_t>(WireValueType::Int32);
        case cw::ValueType::Int64: return static_cast<std::uint8_t>(WireValueType::Int64);
        case cw::ValueType::Float: return static_cast<std::uint8_t>(WireValueType::Float);
        case cw::ValueType::Double: return static_cast<std::uint8_t>(WireValueType::Double);
    }
    return std::nullopt;
}

std::optional<cw::ScanMode> fromWireScanMode(std::uint8_t raw) {
    switch (raw) {
        case 0: return cw::ScanMode::Exact;
        case 1: return cw::ScanMode::Changed;
        case 2: return cw::ScanMode::Unchanged;
        case 3: return cw::ScanMode::Increased;
        case 4: return cw::ScanMode::Decreased;
        case 5: return cw::ScanMode::BiggerThan;
        case 6: return cw::ScanMode::SmallerThan;
        default: return std::nullopt;
    }
}

std::vector<std::byte> encodeWireValue(const cw::Value& value) {
    return std::visit([](const auto& typed) {
        std::vector<std::byte> bytes(sizeof(typed));
        std::memcpy(bytes.data(), &typed, sizeof(typed));
        return bytes;
    }, value);
}

std::optional<std::uint32_t> parseU32(std::wstring_view text) {
    try {
        std::size_t consumed = 0;
        const auto value = std::stoull(std::wstring(text), &consumed, 10);
        if (consumed != text.size() || value > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
        return static_cast<std::uint32_t>(value);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<cw::ValueType> fromWireType(std::uint8_t raw) {
    switch (static_cast<WireValueType>(raw)) {
        case WireValueType::Byte: return cw::ValueType::Byte;
        case WireValueType::Int16: return cw::ValueType::Int16;
        case WireValueType::Int32: return cw::ValueType::Int32;
        case WireValueType::Int64: return cw::ValueType::Int64;
        case WireValueType::Float: return cw::ValueType::Float;
        case WireValueType::Double: return cw::ValueType::Double;
    }
    return std::nullopt;
}

std::size_t wireValueSize(std::uint8_t raw) {
    const auto type = fromWireType(raw);
    if (!type) return 0;
    switch (*type) {
        case cw::ValueType::Byte: return sizeof(std::uint8_t);
        case cw::ValueType::Int16: return sizeof(std::int16_t);
        case cw::ValueType::Int32: return sizeof(std::int32_t);
        case cw::ValueType::Int64: return sizeof(std::int64_t);
        case cw::ValueType::Float: return sizeof(float);
        case cw::ValueType::Double: return sizeof(double);
    }
    return 0;
}

template <typename T>
cw::Value valueFromBytes(std::span<const std::byte> bytes) {
    T value{};
    std::memcpy(&value, bytes.data(), sizeof(value));
    return cw::Value{value};
}

std::optional<cw::Value> decodeWireValue(std::uint8_t rawType, std::span<const std::byte> bytes) {
    const auto type = fromWireType(rawType);
    if (!type || bytes.size() != wireValueSize(rawType)) return std::nullopt;
    switch (*type) {
        case cw::ValueType::Byte: return valueFromBytes<std::uint8_t>(bytes);
        case cw::ValueType::Int16: return valueFromBytes<std::int16_t>(bytes);
        case cw::ValueType::Int32: return valueFromBytes<std::int32_t>(bytes);
        case cw::ValueType::Int64: return valueFromBytes<std::int64_t>(bytes);
        case cw::ValueType::Float: return valueFromBytes<float>(bytes);
        case cw::ValueType::Double: return valueFromBytes<double>(bytes);
    }
    return std::nullopt;
}

cw::EngineFrame makeResponse(const cw::EngineFrame& request, cw::EngineMessageKind kind) {
    cw::EngineFrame response;
    response.header.protocolMajor = cw::kEngineProtocolMajor;
    response.header.protocolMinor = cw::kEngineProtocolMinor;
    response.header.kind = kind;
    response.header.flags = cw::EngineFrameFlagResponse;
    response.header.requestId = request.header.requestId;
    return response;
}

cw::EngineFrame makeError(const cw::EngineFrame& request, std::uint32_t code, std::string_view message) {
    auto response = makeResponse(request, cw::EngineMessageKind::Error);
    cw::EngineBufferWriter payload;
    payload.writeU32(code);
    payload.writeString(message);
    response.payload = payload.take();
    return response;
}

bool sendOrReport(cw::EnginePipeServer& server, const cw::EngineFrame& response) {
    std::string error;
    if (server.send(response, error)) return true;
    std::cerr << "Engine response failed: " << error << '\n';
    return false;
}

cw::EngineFrame handleListProcesses(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!request.payload.empty()) return makeError(request, ERROR_INVALID_DATA, "ListProcesses payload must be empty");
    const auto processes = engine.listProcesses();
    if (processes.size() > std::numeric_limits<std::uint32_t>::max()) {
        return makeError(request, ERROR_BUFFER_OVERFLOW, "Process list is too large");
    }

    cw::EngineBufferWriter payload;
    payload.writeU32(static_cast<std::uint32_t>(processes.size()));
    for (const auto& process : processes) {
        payload.writeU32(process.pid);
        if (!payload.writeString(wideToUtf8(process.name))) {
            return makeError(request, ERROR_INVALID_DATA, "Process name is too large");
        }
    }
    auto response = makeResponse(request, cw::EngineMessageKind::ListProcessesResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleListModules(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!request.payload.empty()) return makeError(request, ERROR_INVALID_DATA, "ListModules payload must be empty");
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before listing modules");

    std::string error;
    const auto modules = engine.listModules(error);
    if (!error.empty()) return makeError(request, ERROR_GEN_FAILURE, error);
    if (modules.size() > std::numeric_limits<std::uint32_t>::max()) {
        return makeError(request, ERROR_BUFFER_OVERFLOW, "Module list is too large");
    }

    cw::EngineBufferWriter payload;
    payload.writeU32(static_cast<std::uint32_t>(modules.size()));
    for (const auto& module : modules) {
        payload.writeU64(static_cast<std::uint64_t>(module.base));
        payload.writeU64(static_cast<std::uint64_t>(module.size));
        if (!payload.writeString(wideToUtf8(module.name)) || !payload.writeString(wideToUtf8(module.path))) {
            return makeError(request, ERROR_INVALID_DATA, "Module metadata is too large");
        }
    }
    auto response = makeResponse(request, cw::EngineMessageKind::ListModulesResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleAttach(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint32_t pid = 0;
    if (!reader.readU32(pid) || !reader.empty() || pid == 0) {
        return makeError(request, ERROR_INVALID_DATA, "AttachProcess requires one non-zero PID");
    }

    std::string error;
    const bool attached = engine.attach(pid, error);
    std::uint16_t pointerSize = 0;
    if (attached) {
        std::string pointerError;
        pointerSize = static_cast<std::uint16_t>(engine.targetPointerSize(pointerError));
        if (pointerSize == 0 && error.empty()) error = pointerError;
    }

    cw::EngineBufferWriter payload;
    payload.writeU8(attached ? 1u : 0u);
    payload.writeU32(attached ? engine.pid() : 0u);
    payload.writeU16(pointerSize);
    payload.writeString(error);
    auto response = makeResponse(request, cw::EngineMessageKind::AttachProcessResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleDetach(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!request.payload.empty()) return makeError(request, ERROR_INVALID_DATA, "DetachProcess payload must be empty");
    engine.detach();
    cw::EngineBufferWriter payload;
    payload.writeU8(1);
    auto response = makeResponse(request, cw::EngineMessageKind::DetachProcessResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleReadValue(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint64_t address = 0;
    std::uint8_t wireType = 0;
    if (!reader.readU64(address) || !reader.readU8(wireType) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "ReadValue requires address and type");
    }
    const auto size = wireValueSize(wireType);
    if (size == 0) return makeError(request, ERROR_INVALID_DATA, "ReadValue type is invalid");

    std::array<std::byte, 8> bytes{};
    std::size_t bytesRead = 0;
    DWORD error = ERROR_SUCCESS;
    const bool readOk = engine.readBytes(static_cast<std::uintptr_t>(address), bytes.data(), size, bytesRead, error) && bytesRead == size;

    cw::EngineBufferWriter payload;
    payload.writeU8(readOk ? 1u : 0u);
    payload.writeU8(wireType);
    payload.writeU32(error);
    payload.writeU8(readOk ? static_cast<std::uint8_t>(size) : 0u);
    if (readOk) payload.writeBytes(std::span(bytes.data(), size));
    auto response = makeResponse(request, cw::EngineMessageKind::ReadValueResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleWriteValue(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint64_t address = 0;
    std::uint8_t wireType = 0;
    std::uint8_t byteCount = 0;
    if (!reader.readU64(address) || !reader.readU8(wireType) || !reader.readU8(byteCount)) {
        return makeError(request, ERROR_INVALID_DATA, "WriteValue header is invalid");
    }
    const auto expected = wireValueSize(wireType);
    if (expected == 0 || byteCount != expected || reader.remaining() != expected) {
        return makeError(request, ERROR_INVALID_DATA, "WriteValue type/size is invalid");
    }

    std::array<std::byte, 8> bytes{};
    if (!reader.readBytes(std::span(bytes.data(), expected)) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "WriteValue payload is truncated");
    }
    const auto value = decodeWireValue(wireType, std::span(bytes.data(), expected));
    if (!value) return makeError(request, ERROR_INVALID_DATA, "WriteValue value is invalid");

    const auto result = engine.writeValue(static_cast<std::uintptr_t>(address), *value);
    cw::EngineBufferWriter payload;
    payload.writeU8(result.ok ? 1u : 0u);
    payload.writeU32(static_cast<std::uint32_t>(result.bytesWritten));
    payload.writeU32(result.error);
    auto response = makeResponse(request, cw::EngineMessageKind::WriteValueResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleReadBytes(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before reading bytes");

    cw::EngineBufferReader reader(request.payload);
    std::uint64_t address = 0;
    std::uint32_t size = 0;
    if (!reader.readU64(address) || !reader.readU32(size) || !reader.empty() || size == 0 || size > 1024u * 1024u) {
        return makeError(request, ERROR_INVALID_DATA, "ReadBytes requires address and size 1..1048576");
    }

    std::vector<std::byte> bytes(size);
    std::size_t bytesRead = 0;
    DWORD readError = ERROR_SUCCESS;
    const bool ok = engine.readBytes(static_cast<std::uintptr_t>(address), bytes.data(), bytes.size(), bytesRead, readError);

    cw::EngineBufferWriter payload;
    payload.writeU8(ok ? 1u : 0u);
    payload.writeU32(readError);
    payload.writeU32(static_cast<std::uint32_t>(bytesRead));
    if (bytesRead != 0) payload.writeBytes(std::span(bytes.data(), bytesRead));
    auto response = makeResponse(request, cw::EngineMessageKind::ReadBytesResult);
    response.payload = payload.take();
    return response;
}

std::uint64_t doubleToBits(double value) {
    std::uint64_t bits{};
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

double bitsToDouble(std::uint64_t bits) {
    double value{};
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

void writeScanSummary(cw::EngineBufferWriter& payload, const cw::MemoryScanner& scanner, const cw::ScanStats& stats) {
    const auto wireType = toWireType(scanner.valueType()).value_or(0);
    payload.writeU8(scanner.hasScan() ? 1u : 0u);
    payload.writeU8(scanner.unknownSnapshotActive() ? 1u : 0u);
    payload.writeU8(scanner.mixedScanActive() ? 1u : 0u);
    payload.writeU8(wireType);
    payload.writeU64(static_cast<std::uint64_t>(scanner.candidateCount()));
    payload.writeU64(static_cast<std::uint64_t>(stats.resultCount));
    payload.writeU64(stats.bytesRead);
    payload.writeU64(stats.regionsRead);
    payload.writeU64(doubleToBits(stats.elapsedMs));
    payload.writeU8(stats.truncated ? 1u : 0u);
    payload.writeU8(stats.cancelled ? 1u : 0u);
    const auto counts = scanner.candidateCountsByType();
    for (const auto count : counts) payload.writeU64(static_cast<std::uint64_t>(count));
}

cw::EngineFrame handleFirstScan(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before scanning");

    cw::EngineBufferReader reader(request.payload);
    std::uint8_t firstKind = 0;
    std::uint8_t wireType = 0;
    std::uint8_t alignment = 0;
    std::uint8_t flags = 0;
    std::uint64_t minAddress = 0;
    std::uint64_t maxAddress = 0;
    std::uint64_t toleranceBits = 0;
    std::string valueText;
    if (!reader.readU8(firstKind) || !reader.readU8(wireType) ||
        !reader.readU8(alignment) || !reader.readU8(flags) ||
        !reader.readU64(minAddress) || !reader.readU64(maxAddress) ||
        !reader.readU64(toleranceBits) || !reader.readString(valueText) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "FirstScan payload is invalid");
    }
    if (firstKind > 2 || alignment > 1 || (flags & ~0x3u) != 0 || minAddress > maxAddress) {
        return makeError(request, ERROR_INVALID_DATA, "FirstScan options are invalid");
    }
    if (wireType != 0 && !fromWireType(wireType)) {
        return makeError(request, ERROR_INVALID_DATA, "FirstScan value type is invalid");
    }

    cw::ScanOptions options;
    options.alignment = alignment == 0 ? cw::AlignmentMode::Natural : cw::AlignmentMode::Byte;
    options.writableOnly = (flags & 0x1u) != 0;
    options.privateOnly = (flags & 0x2u) != 0;
    options.minAddress = static_cast<std::uintptr_t>(minAddress);
    options.maxAddress = static_cast<std::uintptr_t>(maxAddress);
    options.floatTolerance = bitsToDouble(toleranceBits);
    engine.scanner().setOptions(options);
    engine.aobScanner().setOptions(options);

    cw::ScanStats stats{};
    if (firstKind == 0) {
        if (valueText.empty()) return makeError(request, ERROR_INVALID_DATA, "Exact FirstScan requires a value");
        if (wireType == 0) {
            stats = engine.scanner().firstScanAllExact(valueText);
        } else {
            const auto type = fromWireType(wireType);
            const auto value = type ? cw::parseValue(*type, valueText) : std::nullopt;
            if (!type || !value) return makeError(request, ERROR_INVALID_DATA, "Exact FirstScan value is invalid");
            stats = engine.scanner().firstScan(*type, *value);
        }
    } else if (wireType == 0) {
        stats = firstKind == 1
            ? engine.scanner().firstScanAllUnknown()
            : engine.scanner().firstScanAllUnknownSmart();
    } else {
        const auto type = fromWireType(wireType);
        if (!type) return makeError(request, ERROR_INVALID_DATA, "FirstScan value type is invalid");
        stats = firstKind == 1
            ? engine.scanner().firstScanUnknown(*type)
            : engine.scanner().firstScanUnknownSmart(*type);
    }

    cw::EngineBufferWriter payload;
    writeScanSummary(payload, engine.scanner(), stats);
    auto response = makeResponse(request, cw::EngineMessageKind::FirstScanResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleNextScan(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before scanning");
    if (!engine.scanner().hasScan()) return makeError(request, ERROR_INVALID_STATE, "No active scan");

    cw::EngineBufferReader reader(request.payload);
    std::uint8_t rawMode = 0;
    std::string valueText;
    if (!reader.readU8(rawMode) || !reader.readString(valueText) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "NextScan payload is invalid");
    }
    const auto mode = fromWireScanMode(rawMode);
    if (!mode) return makeError(request, ERROR_INVALID_DATA, "NextScan mode is invalid");

    cw::ScanStats stats{};
    if (engine.scanner().mixedScanActive()) {
        std::optional<std::string> wanted;
        if (cw::scanModeNeedsValue(*mode)) {
            if (valueText.empty()) return makeError(request, ERROR_INVALID_DATA, "NextScan mode requires a value");
            wanted = valueText;
        }
        stats = engine.scanner().nextScanMixed(*mode, wanted);
    } else {
        std::optional<cw::Value> wanted;
        if (cw::scanModeNeedsValue(*mode)) {
            if (valueText.empty()) return makeError(request, ERROR_INVALID_DATA, "NextScan mode requires a value");
            wanted = cw::parseValue(engine.scanner().valueType(), valueText);
            if (!wanted) return makeError(request, ERROR_INVALID_DATA, "NextScan value is invalid");
        }
        stats = engine.scanner().nextScan(*mode, wanted);
    }

    cw::EngineBufferWriter payload;
    writeScanSummary(payload, engine.scanner(), stats);
    auto response = makeResponse(request, cw::EngineMessageKind::NextScanResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleNewScan(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!request.payload.empty()) return makeError(request, ERROR_INVALID_DATA, "NewScan payload must be empty");
    engine.clearScans();
    cw::EngineBufferWriter payload;
    payload.writeU8(1);
    auto response = makeResponse(request, cw::EngineMessageKind::NewScanResult);
    response.payload = payload.take();
    return response;
}

void writeOptionalValue(cw::EngineBufferWriter& payload, const std::optional<cw::Value>& value) {
    if (!value) {
        payload.writeU8(0);
        payload.writeU8(0);
        return;
    }
    const auto bytes = encodeWireValue(*value);
    payload.writeU8(1);
    payload.writeU8(static_cast<std::uint8_t>(bytes.size()));
    payload.writeBytes(bytes);
}

cw::EngineFrame handleGetScanResults(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint32_t offset = 0;
    std::uint32_t limit = 0;
    if (!reader.readU32(offset) || !reader.readU32(limit) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "GetScanResults payload is invalid");
    }
    limit = (std::min)(limit, 2000u);

    const auto& scanner = engine.scanner();
    const auto& results = scanner.results();
    const std::size_t begin = (std::min)(static_cast<std::size_t>(offset), results.size());
    const std::size_t end = (std::min)(results.size(), begin + static_cast<std::size_t>(limit));

    cw::EngineBufferWriter payload;
    payload.writeU8(scanner.hasScan() ? 1u : 0u);
    payload.writeU8(scanner.unknownSnapshotActive() ? 1u : 0u);
    payload.writeU8(scanner.mixedScanActive() ? 1u : 0u);
    payload.writeU64(static_cast<std::uint64_t>(scanner.candidateCount()));
    payload.writeU64(static_cast<std::uint64_t>(results.size()));
    payload.writeU32(static_cast<std::uint32_t>(end - begin));
    for (std::size_t i = begin; i < end; ++i) {
        const auto& result = results[i];
        const auto wireType = toWireType(result.type);
        if (!wireType) return makeError(request, ERROR_INVALID_DATA, "Scan result has invalid type");
        payload.writeU64(static_cast<std::uint64_t>(i));
        payload.writeU64(static_cast<std::uint64_t>(result.address));
        payload.writeU8(*wireType);
        writeOptionalValue(payload, scanner.previousValue(result));
        writeOptionalValue(payload, scanner.readCurrent(result));
    }

    auto response = makeResponse(request, cw::EngineMessageKind::GetScanResultsResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleDisableMixedType(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint8_t wireType = 0;
    if (!reader.readU8(wireType) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "DisableMixedType requires one value type");
    }
    const auto type = fromWireType(wireType);
    if (!type || !engine.scanner().hasScan() || !engine.scanner().mixedScanActive()) {
        return makeError(request, ERROR_INVALID_STATE, "No compatible mixed scan is active");
    }

    const bool changed = engine.scanner().disableMixedType(*type);
    cw::EngineBufferWriter payload;
    payload.writeU8(changed ? 1u : 0u);
    payload.writeU64(static_cast<std::uint64_t>(engine.scanner().candidateCount()));
    const auto counts = engine.scanner().candidateCountsByType();
    for (const auto count : counts) payload.writeU64(static_cast<std::uint64_t>(count));
    auto response = makeResponse(request, cw::EngineMessageKind::DisableMixedTypeResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleRestoreScan(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before restoring a scan");

    cw::EngineBufferReader reader(request.payload);
    std::uint8_t primaryWireType = 0;
    std::uint8_t mixed = 0;
    std::uint8_t alignment = 0;
    std::uint8_t flags = 0;
    std::uint64_t minAddress = 0;
    std::uint64_t maxAddress = 0;
    std::uint64_t toleranceBits = 0;
    std::uint32_t count = 0;
    if (!reader.readU8(primaryWireType) || !reader.readU8(mixed) ||
        !reader.readU8(alignment) || !reader.readU8(flags) ||
        !reader.readU64(minAddress) || !reader.readU64(maxAddress) ||
        !reader.readU64(toleranceBits) || !reader.readU32(count)) {
        return makeError(request, ERROR_INVALID_DATA, "RestoreScan header is invalid");
    }
    const auto primaryType = fromWireType(primaryWireType);
    if (!primaryType || mixed > 1 || alignment > 1 || (flags & ~0x3u) != 0 ||
        minAddress > maxAddress || count > 900'000) {
        return makeError(request, ERROR_INVALID_DATA, "RestoreScan metadata is invalid");
    }

    cw::ScanOptions options;
    options.alignment = alignment == 0 ? cw::AlignmentMode::Natural : cw::AlignmentMode::Byte;
    options.writableOnly = (flags & 0x1u) != 0;
    options.privateOnly = (flags & 0x2u) != 0;
    options.minAddress = static_cast<std::uintptr_t>(minAddress);
    options.maxAddress = static_cast<std::uintptr_t>(maxAddress);
    options.floatTolerance = bitsToDouble(toleranceBits);

    std::vector<cw::ScanResult> results;
    results.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint64_t address = 0;
        std::uint64_t previousBits = 0;
        std::uint8_t resultWireType = 0;
        if (!reader.readU64(address) || !reader.readU64(previousBits) || !reader.readU8(resultWireType)) {
            return makeError(request, ERROR_INVALID_DATA, "RestoreScan results are truncated");
        }
        const auto resultType = fromWireType(resultWireType);
        if (!resultType || (!mixed && *resultType != *primaryType)) {
            return makeError(request, ERROR_INVALID_DATA, "RestoreScan result type is inconsistent");
        }
        results.push_back(cw::ScanResult{
            static_cast<std::uintptr_t>(address),
            previousBits,
            *resultType
        });
    }
    if (!reader.empty()) return makeError(request, ERROR_INVALID_DATA, "RestoreScan has trailing bytes");

    const bool restored = engine.scanner().restoreMaterializedScan(*primaryType, mixed != 0, options, std::move(results));
    if (restored) {
        engine.aobScanner().setOptions(options);
        engine.aobScanner().clear();
    }

    cw::EngineBufferWriter payload;
    payload.writeU8(restored ? 1u : 0u);
    payload.writeU64(static_cast<std::uint64_t>(engine.scanner().results().size()));
    auto response = makeResponse(request, cw::EngineMessageKind::RestoreScanResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleSetFreeze(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before freezing");

    cw::EngineBufferReader reader(request.payload);
    std::uint64_t address = 0;
    std::uint8_t wireType = 0;
    std::uint8_t byteCount = 0;
    std::uint32_t intervalMs = 0;
    if (!reader.readU64(address) || !reader.readU8(wireType) || !reader.readU8(byteCount)) {
        return makeError(request, ERROR_INVALID_DATA, "SetFreeze header is invalid");
    }
    const auto expected = wireValueSize(wireType);
    if (expected == 0 || byteCount != expected || reader.remaining() < expected + sizeof(std::uint32_t)) {
        return makeError(request, ERROR_INVALID_DATA, "SetFreeze type/size is invalid");
    }

    std::array<std::byte, 8> bytes{};
    if (!reader.readBytes(std::span(bytes.data(), expected)) || !reader.readU32(intervalMs) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "SetFreeze payload is invalid");
    }
    intervalMs = (std::max)(10u, (std::min)(intervalMs, 60'000u));

    const auto type = fromWireType(wireType);
    const auto value = decodeWireValue(wireType, std::span(bytes.data(), expected));
    if (!type || !value) return makeError(request, ERROR_INVALID_DATA, "SetFreeze value is invalid");

    const auto existing = engine.freezer().list();
    const auto duplicate = std::find_if(existing.begin(), existing.end(),
        [&](const cw::FreezeSnapshot& item) { return item.address == static_cast<std::uintptr_t>(address); });
    if (duplicate != existing.end()) {
        return makeError(request, ERROR_ALREADY_EXISTS, "Address is already frozen");
    }

    const auto id = engine.freezer().add(static_cast<std::uintptr_t>(address), *type, *value, intervalMs);
    cw::EngineBufferWriter payload;
    payload.writeU8(id ? 1u : 0u);
    payload.writeU64(id.value_or(0));
    auto response = makeResponse(request, cw::EngineMessageKind::SetFreezeResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleRemoveFreeze(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint64_t id = 0;
    if (!reader.readU64(id) || !reader.empty() || id == 0) {
        return makeError(request, ERROR_INVALID_DATA, "RemoveFreeze requires one non-zero id");
    }
    const bool removed = engine.freezer().remove(id);
    cw::EngineBufferWriter payload;
    payload.writeU8(removed ? 1u : 0u);
    auto response = makeResponse(request, cw::EngineMessageKind::RemoveFreezeResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleClearFreezes(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!request.payload.empty()) return makeError(request, ERROR_INVALID_DATA, "ClearFreezes payload must be empty");
    engine.freezer().clear();
    cw::EngineBufferWriter payload;
    payload.writeU8(1);
    auto response = makeResponse(request, cw::EngineMessageKind::ClearFreezesResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleListFreezes(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!request.payload.empty()) return makeError(request, ERROR_INVALID_DATA, "ListFreezes payload must be empty");
    const auto items = engine.freezer().list();
    if (items.size() > std::numeric_limits<std::uint32_t>::max()) {
        return makeError(request, ERROR_BUFFER_OVERFLOW, "Freeze list is too large");
    }

    cw::EngineBufferWriter payload;
    payload.writeU32(static_cast<std::uint32_t>(items.size()));
    for (const auto& item : items) {
        const auto wireType = toWireType(item.type);
        if (!wireType) return makeError(request, ERROR_INVALID_DATA, "Freeze entry has invalid type");
        const auto bytes = encodeWireValue(item.value);
        payload.writeU64(item.id);
        payload.writeU64(static_cast<std::uint64_t>(item.address));
        payload.writeU8(*wireType);
        payload.writeU8(static_cast<std::uint8_t>(bytes.size()));
        payload.writeBytes(bytes);
        payload.writeU32(item.intervalMs);
        payload.writeU64(item.writes);
        payload.writeU64(item.failures);
        payload.writeU32(item.lastError);
    }

    auto response = makeResponse(request, cw::EngineMessageKind::ListFreezesResult);
    response.payload = payload.take();
    return response;
}

bool readAobPattern(cw::EngineBufferReader& reader, cw::AobPattern& pattern, std::string& error) {
    std::uint32_t count = 0;
    if (!reader.readU32(count) || count == 0 || count > 1'000'000) {
        error = "AOB pattern length is invalid";
        return false;
    }
    pattern.bytes.clear();
    pattern.bytes.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint8_t value = 0;
        std::uint8_t mask = 0;
        if (!reader.readU8(value) || !reader.readU8(mask)) {
            error = "AOB pattern is truncated";
            return false;
        }
        if (mask != 0 && mask != 0x0Fu && mask != 0xF0u && mask != 0xFFu) {
            error = "AOB mask is invalid";
            return false;
        }
        pattern.bytes.push_back(cw::AobByte{value, mask});
    }
    error.clear();
    return true;
}

void writeAobStats(cw::EngineBufferWriter& payload, const cw::ScanStats& stats, std::size_t resultCount) {
    payload.writeU64(static_cast<std::uint64_t>(resultCount));
    payload.writeU64(stats.bytesRead);
    payload.writeU64(stats.regionsRead);
    payload.writeU64(doubleToBits(stats.elapsedMs));
    payload.writeU8(stats.truncated ? 1u : 0u);
    payload.writeU8(stats.cancelled ? 1u : 0u);
}

cw::EngineFrame handleAobScan(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before AOB scan");

    cw::EngineBufferReader reader(request.payload);
    std::uint8_t executableOnly = 0;
    std::uint8_t alignment = 0;
    std::uint8_t flags = 0;
    std::uint64_t minAddress = 0;
    std::uint64_t maxAddress = 0;
    if (!reader.readU8(executableOnly) || !reader.readU8(alignment) || !reader.readU8(flags) ||
        !reader.readU64(minAddress) || !reader.readU64(maxAddress)) {
        return makeError(request, ERROR_INVALID_DATA, "AobScan options are invalid");
    }
    if (executableOnly > 1 || alignment > 1 || (flags & ~0x3u) != 0 || minAddress > maxAddress) {
        return makeError(request, ERROR_INVALID_DATA, "AobScan options exceed limits");
    }

    cw::AobPattern pattern;
    std::string parseError;
    if (!readAobPattern(reader, pattern, parseError) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, parseError.empty() ? "AobScan payload is invalid" : parseError);
    }

    cw::ScanOptions options;
    options.alignment = alignment == 0 ? cw::AlignmentMode::Natural : cw::AlignmentMode::Byte;
    options.writableOnly = (flags & 0x1u) != 0;
    options.privateOnly = (flags & 0x2u) != 0;
    options.minAddress = static_cast<std::uintptr_t>(minAddress);
    options.maxAddress = static_cast<std::uintptr_t>(maxAddress);
    engine.aobScanner().setOptions(options);
    engine.aobScanner().setExecutableOnly(executableOnly != 0);

    const auto stats = engine.aobScanner().scan(pattern);
    cw::EngineBufferWriter payload;
    writeAobStats(payload, stats, engine.aobScanner().results().size());
    auto response = makeResponse(request, cw::EngineMessageKind::AobScanResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleAobResults(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint32_t offset = 0;
    std::uint32_t limit = 0;
    if (!reader.readU32(offset) || !reader.readU32(limit) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "AobResults payload is invalid");
    }
    limit = (std::min)(limit, 5000u);

    const auto& results = engine.aobScanner().results();
    const std::size_t begin = (std::min)(static_cast<std::size_t>(offset), results.size());
    const std::size_t end = (std::min)(results.size(), begin + static_cast<std::size_t>(limit));

    cw::EngineBufferWriter payload;
    const auto& pattern = engine.aobScanner().pattern();
    payload.writeU32(static_cast<std::uint32_t>(pattern.bytes.size()));
    for (const auto& byte : pattern.bytes) {
        payload.writeU8(byte.value);
        payload.writeU8(byte.mask);
    }
    payload.writeU64(static_cast<std::uint64_t>(results.size()));
    payload.writeU32(static_cast<std::uint32_t>(end - begin));
    for (std::size_t i = begin; i < end; ++i) payload.writeU64(static_cast<std::uint64_t>(results[i]));
    auto response = makeResponse(request, cw::EngineMessageKind::AobResultsResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleAobRestore(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    cw::AobPattern pattern;
    std::string parseError;
    if (!readAobPattern(reader, pattern, parseError)) {
        return makeError(request, ERROR_INVALID_DATA, parseError);
    }
    std::uint32_t count = 0;
    if (!reader.readU32(count) || count > 1'000'000) {
        return makeError(request, ERROR_INVALID_DATA, "AobRestore result count is invalid");
    }
    std::vector<std::uintptr_t> results;
    results.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint64_t address = 0;
        if (!reader.readU64(address)) return makeError(request, ERROR_INVALID_DATA, "AobRestore results are truncated");
        results.push_back(static_cast<std::uintptr_t>(address));
    }
    if (!reader.empty()) return makeError(request, ERROR_INVALID_DATA, "AobRestore has trailing bytes");

    engine.aobScanner().restore(pattern, std::move(results));
    cw::EngineBufferWriter payload;
    payload.writeU8(1);
    payload.writeU64(static_cast<std::uint64_t>(engine.aobScanner().results().size()));
    auto response = makeResponse(request, cw::EngineMessageKind::AobRestoreResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleAobClear(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!request.payload.empty()) return makeError(request, ERROR_INVALID_DATA, "AobClear payload must be empty");
    engine.aobScanner().clear();
    cw::EngineBufferWriter payload;
    payload.writeU8(1);
    auto response = makeResponse(request, cw::EngineMessageKind::AobClearResult);
    response.payload = payload.take();
    return response;
}

void writePointerStats(cw::EngineBufferWriter& payload, const cw::PointerScanStats& stats) {
    payload.writeU16(static_cast<std::uint16_t>(stats.pointerSize));
    payload.writeU64(static_cast<std::uint64_t>(stats.indexEntries));
    payload.writeU64(static_cast<std::uint64_t>(stats.chains));
    payload.writeU64(stats.bytesRead);
    payload.writeU64(stats.regionsRead);
    payload.writeU64(doubleToBits(stats.indexMs));
    payload.writeU64(doubleToBits(stats.searchMs));
    payload.writeU64(static_cast<std::uint64_t>(stats.directCandidates));
    payload.writeU64(static_cast<std::uint64_t>(stats.searchCandidates));
    payload.writeU64(static_cast<std::uint64_t>(stats.targetedDepth));
    payload.writeU64(static_cast<std::uint64_t>(stats.targetedFrontier));
    payload.writeU64(stats.targetedSlots);
    payload.writeU64(stats.targetedMatches);
    payload.writeU8(stats.indexTruncated ? 1u : 0u);
    payload.writeU8(stats.chainsTruncated ? 1u : 0u);
    payload.writeU8(stats.searchBudgetHit ? 1u : 0u);
    payload.writeU8(stats.branchLimitHit ? 1u : 0u);
    payload.writeU8(stats.targetedTruncated ? 1u : 0u);
    payload.writeU8(stats.targetedUsed ? 1u : 0u);
    payload.writeU8(stats.targetedFallbackUsed ? 1u : 0u);
    payload.writeU8(stats.cancelled ? 1u : 0u);
}

bool readPointerOptions(cw::EngineBufferReader& reader, cw::PointerScanOptions& options, std::string& error) {
    std::uint16_t maxDepth = 0;
    std::uint64_t maxOffset = 0;
    std::uint64_t maxNegativeOffset = 0;
    std::uint32_t maxChains = 0;
    std::uint32_t maxIndexEntries = 0;
    std::uint32_t maxCandidatesPerNode = 0;
    std::uint32_t maxSearchCandidates = 0;
    std::uint16_t alignment = 0;
    std::uint8_t flags = 0;
    std::uint8_t searchMode = 0;
    std::string rootModule;
    if (!reader.readU16(maxDepth) || !reader.readU64(maxOffset) ||
        !reader.readU64(maxNegativeOffset) || !reader.readU32(maxChains) ||
        !reader.readU32(maxIndexEntries) || !reader.readU32(maxCandidatesPerNode) ||
        !reader.readU32(maxSearchCandidates) || !reader.readU16(alignment) ||
        !reader.readU8(flags) || !reader.readU8(searchMode) || !reader.readString(rootModule)) {
        error = "Pointer options are truncated";
        return false;
    }
    if (maxDepth == 0 || maxDepth > 64 || maxChains == 0 || maxChains > 100'000 ||
        maxIndexEntries == 0 || maxIndexEntries > 20'000'000 ||
        maxCandidatesPerNode == 0 || maxCandidatesPerNode > 100'000 ||
        maxSearchCandidates == 0 || maxSearchCandidates > 20'000'000 ||
        (alignment != 0 && alignment != 1 && alignment != 2 && alignment != 4 && alignment != 8) ||
        (flags & ~0x3u) != 0 ||
        searchMode > static_cast<std::uint8_t>(cw::PointerSearchMode::Targeted)) {
        error = "Pointer options exceed allowed limits";
        return false;
    }

    std::wstring rootModuleWide;
    if (!rootModule.empty()) {
        rootModuleWide = utf8ToWide(rootModule);
        if (rootModuleWide.empty()) {
            error = "Pointer root module is not valid UTF-8";
            return false;
        }
    }

    options.maxDepth = maxDepth;
    options.maxOffset = static_cast<std::uintptr_t>(maxOffset);
    options.maxNegativeOffset = static_cast<std::uintptr_t>(maxNegativeOffset);
    options.maxChains = maxChains;
    options.maxIndexEntries = maxIndexEntries;
    options.maxCandidatesPerNode = maxCandidatesPerNode;
    options.maxSearchCandidates = maxSearchCandidates;
    options.alignment = alignment;
    options.writableOnly = (flags & 0x1u) != 0;
    options.privateOnly = (flags & 0x2u) != 0;
    options.searchMode = static_cast<cw::PointerSearchMode>(searchMode);
    options.rootModuleName = std::move(rootModuleWide);
    error.clear();
    return true;
}

cw::EngineFrame handlePointerCaptureIndex(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before pointer indexing");

    cw::EngineBufferReader reader(request.payload);
    cw::PointerScanOptions options;
    std::string parseError;
    if (!readPointerOptions(reader, options, parseError) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, parseError.empty() ? "PointerCaptureIndex payload is invalid" : parseError);
    }

    std::string contextError;
    if (!engine.refreshPointerContext(contextError)) {
        return makeError(request, ERROR_INVALID_STATE, contextError);
    }

    const auto stats = engine.pointerScanner().captureIndex(options);
    cw::EngineBufferWriter payload;
    writePointerStats(payload, stats);
    auto response = makeResponse(request, cw::EngineMessageKind::PointerCaptureIndexResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handlePointerIndexResults(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint32_t offset = 0;
    std::uint32_t limit = 0;
    if (!reader.readU32(offset) || !reader.readU32(limit) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "PointerIndexResults payload is invalid");
    }
    limit = (std::min)(limit, 5000u);

    const auto& index = engine.pointerScanner().index();
    const std::size_t begin = (std::min)(static_cast<std::size_t>(offset), index.size());
    const std::size_t end = (std::min)(index.size(), begin + static_cast<std::size_t>(limit));

    cw::EngineBufferWriter payload;
    payload.writeU64(static_cast<std::uint64_t>(index.size()));
    payload.writeU32(static_cast<std::uint32_t>(end - begin));
    for (std::size_t i = begin; i < end; ++i) {
        payload.writeU64(static_cast<std::uint64_t>(index[i].value));
        payload.writeU64(static_cast<std::uint64_t>(index[i].address));
    }
    auto response = makeResponse(request, cw::EngineMessageKind::PointerIndexResultsResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handlePointerClear(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint8_t flags = 0;
    if (!reader.readU8(flags) || !reader.empty() || flags == 0 || (flags & ~0x3u) != 0) {
        return makeError(request, ERROR_INVALID_DATA, "PointerClear flags are invalid");
    }
    if ((flags & 0x1u) != 0) engine.pointerScanner().clearIndex();
    if ((flags & 0x2u) != 0) engine.pointerScanner().clearChains();

    cw::EngineBufferWriter payload;
    payload.writeU8(1);
    auto response = makeResponse(request, cw::EngineMessageKind::PointerClearResult);
    response.payload = payload.take();
    return response;
}

bool readPointerChains(
    cw::EngineBufferReader& reader,
    std::uint16_t pointerSize,
    std::uint32_t chainCount,
    std::vector<cw::PointerChain>& chains,
    std::string& error)
{
    if ((pointerSize != 4 && pointerSize != 8) || chainCount > 100'000) {
        error = "Pointer chain metadata is invalid";
        return false;
    }
    chains.clear();
    chains.reserve(chainCount);
    for (std::uint32_t i = 0; i < chainCount; ++i) {
        std::string moduleName;
        std::uint64_t rootOffset = 0;
        std::uint16_t depth = 0;
        if (!reader.readString(moduleName) || !reader.readU64(rootOffset) || !reader.readU16(depth) ||
            moduleName.empty() || depth > 64) {
            error = "Pointer chain metadata is invalid";
            return false;
        }
        auto moduleWide = utf8ToWide(moduleName);
        if (moduleWide.empty()) {
            error = "Pointer chain module is invalid UTF-8";
            return false;
        }
        cw::PointerChain chain;
        chain.moduleName = std::move(moduleWide);
        chain.rootOffset = static_cast<std::uintptr_t>(rootOffset);
        chain.offsets.reserve(depth);
        for (std::uint16_t step = 0; step < depth; ++step) {
            std::int64_t offsetValue = 0;
            if (!reader.readI64(offsetValue)) {
                error = "Pointer chain is truncated";
                return false;
            }
            chain.offsets.push_back(offsetValue);
        }
        chains.push_back(std::move(chain));
    }
    error.clear();
    return true;
}

cw::EngineFrame handleSetPointerChains(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint16_t pointerSize = 0;
    std::uint32_t chainCount = 0;
    if (!reader.readU16(pointerSize) || !reader.readU32(chainCount)) {
        return makeError(request, ERROR_INVALID_DATA, "SetPointerChains header is invalid");
    }

    std::vector<cw::PointerChain> chains;
    std::string parseError;
    if (!readPointerChains(reader, pointerSize, chainCount, chains, parseError) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, parseError.empty() ? "SetPointerChains payload is invalid" : parseError);
    }

    engine.pointerScanner().setChains(std::move(chains), pointerSize);
    cw::EngineBufferWriter payload;
    payload.writeU8(1);
    payload.writeU16(pointerSize);
    payload.writeU64(static_cast<std::uint64_t>(engine.pointerScanner().chains().size()));
    auto response = makeResponse(request, cw::EngineMessageKind::SetPointerChainsResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handlePointerDiscover(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before pointer scanning");

    cw::EngineBufferReader reader(request.payload);
    std::uint64_t target = 0;
    cw::PointerScanOptions options;
    std::string parseError;
    if (!reader.readU64(target) || !readPointerOptions(reader, options, parseError) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, parseError.empty() ? "PointerDiscover payload is invalid" : parseError);
    }

    std::string contextError;
    if (!engine.refreshPointerContext(contextError)) {
        return makeError(request, ERROR_INVALID_STATE, contextError);
    }

    const auto stats = engine.pointerScanner().scan(static_cast<std::uintptr_t>(target), options);
    cw::EngineBufferWriter payload;
    writePointerStats(payload, stats);
    auto response = makeResponse(request, cw::EngineMessageKind::PointerDiscoverResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handlePointerRescan(const cw::EngineFrame& request, cw::EngineSession& engine) {
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before pointer rescan");

    cw::EngineBufferReader reader(request.payload);
    std::uint64_t target = 0;
    if (!reader.readU64(target) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "PointerRescan requires one target address");
    }
    if (engine.pointerScanner().chains().empty()) {
        return makeError(request, ERROR_INVALID_STATE, "No stored pointer chains");
    }

    std::string contextError;
    if (!engine.refreshPointerContext(contextError)) {
        return makeError(request, ERROR_INVALID_STATE, contextError);
    }
    if (engine.pointerScanner().chainPointerSize() != 0 &&
        engine.pointerScanner().chainPointerSize() != engine.pointerScanner().pointerSize()) {
        return makeError(request, ERROR_REVISION_MISMATCH, "Pointer chain width does not match target");
    }

    const auto before = engine.pointerScanner().chains().size();
    const auto after = engine.pointerScanner().rescan(static_cast<std::uintptr_t>(target));
    cw::EngineBufferWriter payload;
    payload.writeU64(static_cast<std::uint64_t>(before));
    payload.writeU64(static_cast<std::uint64_t>(after));
    auto response = makeResponse(request, cw::EngineMessageKind::PointerRescanResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handlePointerResults(const cw::EngineFrame& request, cw::EngineSession& engine) {
    cw::EngineBufferReader reader(request.payload);
    std::uint32_t offset = 0;
    std::uint32_t limit = 0;
    if (!reader.readU32(offset) || !reader.readU32(limit) || !reader.empty()) {
        return makeError(request, ERROR_INVALID_DATA, "PointerResults payload is invalid");
    }
    limit = (std::min)(limit, 1000u);

    const auto& scanner = engine.pointerScanner();
    const auto& chains = scanner.chains();
    const std::size_t begin = (std::min)(static_cast<std::size_t>(offset), chains.size());
    const std::size_t end = (std::min)(chains.size(), begin + static_cast<std::size_t>(limit));

    cw::EngineBufferWriter payload;
    payload.writeU16(static_cast<std::uint16_t>(scanner.pointerSize()));
    payload.writeU16(static_cast<std::uint16_t>(scanner.chainPointerSize()));
    payload.writeU64(static_cast<std::uint64_t>(chains.size()));
    payload.writeU32(static_cast<std::uint32_t>(end - begin));
    for (std::size_t i = begin; i < end; ++i) {
        const auto& chain = chains[i];
        if (!payload.writeString(wideToUtf8(chain.moduleName))) {
            return makeError(request, ERROR_INVALID_DATA, "Pointer module name is too large");
        }
        payload.writeU64(static_cast<std::uint64_t>(chain.rootOffset));
        if (chain.offsets.size() > 64) {
            return makeError(request, ERROR_INVALID_DATA, "Pointer chain depth exceeds protocol limit");
        }
        payload.writeU16(static_cast<std::uint16_t>(chain.offsets.size()));
        for (const auto offsetValue : chain.offsets) payload.writeI64(offsetValue);
        const auto resolved = scanner.resolve(i);
        payload.writeU8(resolved ? 1u : 0u);
        payload.writeU64(resolved ? static_cast<std::uint64_t>(*resolved) : 0u);
    }

    auto response = makeResponse(request, cw::EngineMessageKind::PointerResultsResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleSetPointerProfile(
    const cw::EngineFrame& request,
    cw::EngineSession& engine,
    std::optional<cw::PointerProfileData>& activeProfile)
{
    cw::EngineBufferReader reader(request.payload);
    std::uint16_t pointerSize = 0;
    std::uint8_t wireType = 0;
    std::string processName;
    std::uint32_t chainCount = 0;
    if (!reader.readU16(pointerSize) || !reader.readU8(wireType) ||
        !reader.readString(processName) || !reader.readU32(chainCount)) {
        return makeError(request, ERROR_INVALID_DATA, "SetPointerProfile header is invalid");
    }
    const auto type = fromWireType(wireType);
    if (!type || (pointerSize != 4 && pointerSize != 8) || chainCount == 0 || chainCount > 100'000) {
        return makeError(request, ERROR_INVALID_DATA, "SetPointerProfile metadata is invalid");
    }

    cw::PointerProfileData profile;
    profile.pointerSize = pointerSize;
    profile.type = *type;
    profile.processName = std::move(processName);
    profile.chains.reserve(chainCount);
    for (std::uint32_t i = 0; i < chainCount; ++i) {
        std::string moduleName;
        std::uint64_t rootOffset = 0;
        std::uint16_t depth = 0;
        if (!reader.readString(moduleName) || !reader.readU64(rootOffset) || !reader.readU16(depth) ||
            moduleName.empty() || depth > 64) {
            return makeError(request, ERROR_INVALID_DATA, "Pointer profile chain metadata is invalid");
        }
        auto moduleWide = utf8ToWide(moduleName);
        if (moduleWide.empty()) return makeError(request, ERROR_INVALID_DATA, "Pointer profile module name is invalid UTF-8");

        cw::PointerChain chain;
        chain.moduleName = std::move(moduleWide);
        chain.rootOffset = static_cast<std::uintptr_t>(rootOffset);
        chain.offsets.reserve(depth);
        for (std::uint16_t step = 0; step < depth; ++step) {
            std::int64_t offsetValue = 0;
            if (!reader.readI64(offsetValue)) {
                return makeError(request, ERROR_INVALID_DATA, "Pointer profile chain is truncated");
            }
            chain.offsets.push_back(offsetValue);
        }
        profile.chains.push_back(std::move(chain));
    }
    if (!reader.empty()) return makeError(request, ERROR_INVALID_DATA, "Pointer profile has trailing bytes");

    engine.pointerScanner().setChains(profile.chains, profile.pointerSize);
    activeProfile = std::move(profile);

    cw::EngineBufferWriter payload;
    payload.writeU8(1);
    payload.writeU16(static_cast<std::uint16_t>(activeProfile->pointerSize));
    payload.writeU8(wireType);
    payload.writeU64(static_cast<std::uint64_t>(activeProfile->chains.size()));
    auto response = makeResponse(request, cw::EngineMessageKind::SetPointerProfileResult);
    response.payload = payload.take();
    return response;
}

cw::EngineFrame handleResolvePointerProfile(
    const cw::EngineFrame& request,
    cw::EngineSession& engine,
    const std::optional<cw::PointerProfileData>& activeProfile)
{
    if (!request.payload.empty()) return makeError(request, ERROR_INVALID_DATA, "ResolvePointerProfile payload must be empty");
    if (!engine.attached()) return makeError(request, ERROR_INVALID_HANDLE, "Attach to a process before resolving profile");
    if (!activeProfile || engine.pointerScanner().chains().empty()) {
        return makeError(request, ERROR_INVALID_STATE, "No active pointer profile");
    }

    std::string contextError;
    if (!engine.refreshPointerContext(contextError)) {
        return makeError(request, ERROR_INVALID_STATE, contextError);
    }
    if (activeProfile->pointerSize != engine.pointerScanner().pointerSize()) {
        return makeError(request, ERROR_REVISION_MISMATCH, "Pointer profile width does not match target");
    }

    std::vector<std::uintptr_t> resolved;
    resolved.reserve(engine.pointerScanner().chains().size());
    for (std::size_t i = 0; i < engine.pointerScanner().chains().size(); ++i) {
        if (const auto address = engine.pointerScanner().resolve(i)) resolved.push_back(*address);
    }
    if (resolved.empty()) {
        cw::EngineBufferWriter payload;
        payload.writeU8(0);
        payload.writeU8(toWireType(activeProfile->type).value_or(0));
        payload.writeU64(0);
        payload.writeU64(0);
        payload.writeU64(0);
        auto response = makeResponse(request, cw::EngineMessageKind::ResolvePointerProfileResult);
        response.payload = payload.take();
        return response;
    }

    std::sort(resolved.begin(), resolved.end());
    std::uintptr_t bestAddress = resolved.front();
    std::size_t bestCount = 1;
    std::size_t run = 1;
    for (std::size_t i = 1; i < resolved.size(); ++i) {
        if (resolved[i] == resolved[i - 1]) {
            ++run;
        } else {
            if (run > bestCount) {
                bestCount = run;
                bestAddress = resolved[i - 1];
            }
            run = 1;
        }
    }
    if (run > bestCount) {
        bestCount = run;
        bestAddress = resolved.back();
    }

    cw::EngineBufferWriter payload;
    payload.writeU8(1);
    payload.writeU8(toWireType(activeProfile->type).value_or(0));
    payload.writeU64(static_cast<std::uint64_t>(bestAddress));
    payload.writeU64(static_cast<std::uint64_t>(bestCount));
    payload.writeU64(static_cast<std::uint64_t>(resolved.size()));
    auto response = makeResponse(request, cw::EngineMessageKind::ResolvePointerProfileResult);
    response.payload = payload.take();
    return response;
}

int runEngine(const std::wstring& pipeName, DWORD ownerPid) {
    cw::EnginePipeServer server;
    std::string error;
    if (!server.create(pipeName, ownerPid, error)) {
        std::cerr << "Engine pipe create failed: " << error << '\n';
        return 2;
    }
    if (!server.accept(error)) {
        std::cerr << "Engine pipe accept failed: " << error << '\n';
        return 3;
    }

    cw::EngineFrame hello;
    if (!server.receive(hello, error)) {
        std::cerr << "Engine handshake receive failed: " << error << '\n';
        return 4;
    }
    if (hello.header.kind != cw::EngineMessageKind::Hello ||
        hello.header.protocolMajor != cw::kEngineProtocolMajor ||
        hello.header.protocolMinor != cw::kEngineProtocolMinor ||
        hello.header.requestId == 0) {
        sendOrReport(server, makeError(hello, ERROR_REVISION_MISMATCH, "Invalid engine Hello/protocol"));
        return 5;
    }

    cw::EngineBufferReader helloReader(hello.payload);
    std::string clientName;
    if (!helloReader.readString(clientName) || !helloReader.empty() || clientName.empty() || clientName.size() > 128) {
        sendOrReport(server, makeError(hello, ERROR_INVALID_DATA, "Invalid engine Hello payload"));
        return 6;
    }

    cw::EngineBufferWriter ackPayload;
    ackPayload.writeU16(cw::kEngineProtocolMajor);
    ackPayload.writeU16(cw::kEngineProtocolMinor);
    ackPayload.writeString(kEngineVersion);
    auto ack = makeResponse(hello, cw::EngineMessageKind::HelloAck);
    ack.payload = ackPayload.take();
    if (!sendOrReport(server, ack)) return 7;

    cw::EngineSession engine;
    std::optional<cw::PointerProfileData> activePointerProfile;
    bool running = true;
    while (running) {
        cw::EngineFrame request;
        if (!server.receive(request, error)) {
            std::cerr << "Engine request receive ended: " << error << '\n';
            break;
        }

        if (request.header.protocolMajor != cw::kEngineProtocolMajor ||
            request.header.protocolMinor != cw::kEngineProtocolMinor ||
            request.header.requestId == 0 ||
            (request.header.flags & (cw::EngineFrameFlagResponse | cw::EngineFrameFlagEvent)) != 0) {
            if (!sendOrReport(server, makeError(request, ERROR_INVALID_DATA, "Invalid request header"))) break;
            continue;
        }

        cw::EngineFrame response;
        switch (request.header.kind) {
            case cw::EngineMessageKind::Ping:
                if (!request.payload.empty()) response = makeError(request, ERROR_INVALID_DATA, "Ping payload must be empty");
                else response = makeResponse(request, cw::EngineMessageKind::Pong);
                break;
            case cw::EngineMessageKind::ListProcesses:
                response = handleListProcesses(request, engine);
                break;
            case cw::EngineMessageKind::ListModules:
                response = handleListModules(request, engine);
                break;
            case cw::EngineMessageKind::AttachProcess:
                response = handleAttach(request, engine);
                break;
            case cw::EngineMessageKind::DetachProcess:
                response = handleDetach(request, engine);
                break;
            case cw::EngineMessageKind::ReadValue:
                response = handleReadValue(request, engine);
                break;
            case cw::EngineMessageKind::WriteValue:
                response = handleWriteValue(request, engine);
                break;
            case cw::EngineMessageKind::ReadBytes:
                response = handleReadBytes(request, engine);
                break;
            case cw::EngineMessageKind::FirstScan:
                response = handleFirstScan(request, engine);
                break;
            case cw::EngineMessageKind::NextScan:
                response = handleNextScan(request, engine);
                break;
            case cw::EngineMessageKind::NewScan:
                response = handleNewScan(request, engine);
                break;
            case cw::EngineMessageKind::GetScanResults:
                response = handleGetScanResults(request, engine);
                break;
            case cw::EngineMessageKind::DisableMixedType:
                response = handleDisableMixedType(request, engine);
                break;
            case cw::EngineMessageKind::RestoreScan:
                response = handleRestoreScan(request, engine);
                break;
            case cw::EngineMessageKind::SetFreeze:
                response = handleSetFreeze(request, engine);
                break;
            case cw::EngineMessageKind::RemoveFreeze:
                response = handleRemoveFreeze(request, engine);
                break;
            case cw::EngineMessageKind::ClearFreezes:
                response = handleClearFreezes(request, engine);
                break;
            case cw::EngineMessageKind::ListFreezes:
                response = handleListFreezes(request, engine);
                break;
            case cw::EngineMessageKind::PointerCaptureIndex:
                response = handlePointerCaptureIndex(request, engine);
                break;
            case cw::EngineMessageKind::PointerIndexResults:
                response = handlePointerIndexResults(request, engine);
                break;
            case cw::EngineMessageKind::PointerClear:
                response = handlePointerClear(request, engine);
                if (!request.payload.empty() && (std::to_integer<std::uint8_t>(request.payload[0]) & 0x2u) != 0) {
                    activePointerProfile.reset();
                }
                break;
            case cw::EngineMessageKind::SetPointerChains:
                activePointerProfile.reset();
                response = handleSetPointerChains(request, engine);
                break;
            case cw::EngineMessageKind::PointerDiscover:
                activePointerProfile.reset();
                response = handlePointerDiscover(request, engine);
                break;
            case cw::EngineMessageKind::PointerRescan:
                response = handlePointerRescan(request, engine);
                break;
            case cw::EngineMessageKind::PointerResults:
                response = handlePointerResults(request, engine);
                break;
            case cw::EngineMessageKind::SetPointerProfile:
                response = handleSetPointerProfile(request, engine, activePointerProfile);
                break;
            case cw::EngineMessageKind::ResolvePointerProfile:
                response = handleResolvePointerProfile(request, engine, activePointerProfile);
                break;
            case cw::EngineMessageKind::AobScan:
                response = handleAobScan(request, engine);
                break;
            case cw::EngineMessageKind::AobResults:
                response = handleAobResults(request, engine);
                break;
            case cw::EngineMessageKind::AobRestore:
                response = handleAobRestore(request, engine);
                break;
            case cw::EngineMessageKind::AobClear:
                response = handleAobClear(request, engine);
                break;
            case cw::EngineMessageKind::Shutdown:
                if (!request.payload.empty()) response = makeError(request, ERROR_INVALID_DATA, "Shutdown payload must be empty");
                else { response = makeResponse(request, cw::EngineMessageKind::Shutdown); running = false; }
                break;
            default:
                response = makeError(request, ERROR_NOT_SUPPORTED, "Unsupported engine message");
                break;
        }

        if (!sendOrReport(server, response)) break;
    }

    engine.detach();
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring pipeName;
    DWORD ownerPid = 0;

    for (int i = 1; i < argc; ++i) {
        const std::wstring_view arg(argv[i]);
        if (arg == L"--pipe" && i + 1 < argc) {
            pipeName = argv[++i];
        } else if (arg == L"--owner-pid" && i + 1 < argc) {
            const auto parsed = parseU32(argv[++i]);
            if (!parsed) { std::cerr << "Invalid --owner-pid\n"; return 1; }
            ownerPid = *parsed;
        } else if (arg == L"--version") {
            std::cout << "Cheat Wizard Engine v" << kEngineVersion
                      << " protocol " << cw::kEngineProtocolMajor << '.' << cw::kEngineProtocolMinor << '\n';
            return 0;
        } else {
            std::cerr << "Usage: cw-engine.exe --pipe <local-pipe> --owner-pid <pid>\n";
            return 1;
        }
    }

    if (!cw::isValidEnginePipeName(pipeName) || ownerPid == 0) {
        std::cerr << "Usage: cw-engine.exe --pipe <local-pipe> --owner-pid <pid>\n";
        return 1;
    }
    return runEngine(pipeName, ownerPid);
}
