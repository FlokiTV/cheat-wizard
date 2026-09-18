#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cw {

inline constexpr std::uint16_t kEngineProtocolMajor = 1;
inline constexpr std::uint16_t kEngineProtocolMinor = 0;
inline constexpr std::size_t kEngineFrameHeaderSize = 28;
inline constexpr std::uint32_t kEngineMaxPayloadSize = 16u * 1024u * 1024u;

enum class EngineMessageKind : std::uint16_t {
    Hello = 1,
    HelloAck = 2,
    Ping = 3,
    Pong = 4,
    Shutdown = 5,
    Error = 6,

    ListProcesses = 100,
    ListProcessesResult = 101,
    ListModules = 102,
    ListModulesResult = 103,
    AttachProcess = 110,
    AttachProcessResult = 111,
    DetachProcess = 112,
    DetachProcessResult = 113,
    ReadValue = 120,
    ReadValueResult = 121,
    WriteValue = 122,
    WriteValueResult = 123,
    ReadBytes = 124,
    ReadBytesResult = 125,

    FirstScan = 130,
    FirstScanResult = 131,
    NextScan = 132,
    NextScanResult = 133,
    NewScan = 134,
    NewScanResult = 135,
    GetScanResults = 136,
    GetScanResultsResult = 137,
    DisableMixedType = 138,
    DisableMixedTypeResult = 139,

    SetFreeze = 140,
    SetFreezeResult = 141,
    RemoveFreeze = 142,
    RemoveFreezeResult = 143,
    ClearFreezes = 144,
    ClearFreezesResult = 145,
    ListFreezes = 146,
    ListFreezesResult = 147,
    RestoreScan = 150,
    RestoreScanResult = 151,

    PointerDiscover = 160,
    PointerDiscoverResult = 161,
    PointerRescan = 162,
    PointerRescanResult = 163,
    PointerResults = 164,
    PointerResultsResult = 165,
    SetPointerProfile = 166,
    SetPointerProfileResult = 167,
    ResolvePointerProfile = 168,
    ResolvePointerProfileResult = 169,
    PointerCaptureIndex = 170,
    PointerCaptureIndexResult = 171,
    PointerIndexResults = 172,
    PointerIndexResultsResult = 173,
    PointerClear = 174,
    PointerClearResult = 175,
    SetPointerChains = 176,
    SetPointerChainsResult = 177,

    AobScan = 180,
    AobScanResult = 181,
    AobResults = 182,
    AobResultsResult = 183,
    AobRestore = 184,
    AobRestoreResult = 185,
    AobClear = 186,
    AobClearResult = 187,
};

enum EngineFrameFlags : std::uint16_t {
    EngineFrameFlagNone = 0,
    EngineFrameFlagResponse = 1u << 0,
    EngineFrameFlagEvent = 1u << 1,
};

struct EngineFrameHeader {
    std::uint16_t protocolMajor{kEngineProtocolMajor};
    std::uint16_t protocolMinor{kEngineProtocolMinor};
    EngineMessageKind kind{EngineMessageKind::Error};
    std::uint16_t flags{EngineFrameFlagNone};
    std::uint64_t requestId{};
    std::uint32_t payloadSize{};
};

bool encodeEngineFrameHeader(
    const EngineFrameHeader& header,
    std::array<std::byte, kEngineFrameHeaderSize>& out) noexcept;

bool decodeEngineFrameHeader(
    std::span<const std::byte> bytes,
    EngineFrameHeader& out,
    std::string& error) noexcept;

class EngineBufferWriter {
public:
    void writeU8(std::uint8_t value);
    void writeU16(std::uint16_t value);
    void writeU32(std::uint32_t value);
    void writeU64(std::uint64_t value);
    void writeI64(std::int64_t value);
    void writeBytes(std::span<const std::byte> bytes);
    bool writeString(std::string_view value);

    [[nodiscard]] const std::vector<std::byte>& data() const noexcept { return data_; }
    [[nodiscard]] std::vector<std::byte> take() noexcept { return std::move(data_); }

private:
    std::vector<std::byte> data_;
};

class EngineBufferReader {
public:
    explicit EngineBufferReader(std::span<const std::byte> data) noexcept : data_(data) {}

    bool readU8(std::uint8_t& value) noexcept;
    bool readU16(std::uint16_t& value) noexcept;
    bool readU32(std::uint32_t& value) noexcept;
    bool readU64(std::uint64_t& value) noexcept;
    bool readI64(std::int64_t& value) noexcept;
    bool readBytes(std::span<std::byte> out) noexcept;
    bool readString(std::string& value);

    [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
    [[nodiscard]] bool empty() const noexcept { return remaining() == 0; }

private:
    std::span<const std::byte> data_;
    std::size_t offset_{};
};

} // namespace cw
