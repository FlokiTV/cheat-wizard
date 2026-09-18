#include "cw/EngineProtocol.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
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
    bool ok = true;

    cw::EngineFrameHeader header;
    header.kind = cw::EngineMessageKind::Ping;
    header.flags = cw::EngineFrameFlagResponse;
    header.requestId = 0x1122334455667788ull;
    header.payloadSize = 1234;

    std::array<std::byte, cw::kEngineFrameHeaderSize> encoded{};
    ok &= expect(cw::encodeEngineFrameHeader(header, encoded), "encode header");

    cw::EngineFrameHeader decoded;
    std::string error;
    ok &= expect(cw::decodeEngineFrameHeader(encoded, decoded, error), "decode header");
    ok &= expect(decoded.protocolMajor == cw::kEngineProtocolMajor, "protocol major roundtrip");
    ok &= expect(decoded.protocolMinor == cw::kEngineProtocolMinor, "protocol minor roundtrip");
    ok &= expect(decoded.kind == cw::EngineMessageKind::Ping, "message kind roundtrip");
    ok &= expect(decoded.flags == cw::EngineFrameFlagResponse, "flags roundtrip");
    ok &= expect(decoded.requestId == header.requestId, "request id roundtrip");
    ok &= expect(decoded.payloadSize == header.payloadSize, "payload size roundtrip");

    auto badMagic = encoded;
    badMagic[0] = std::byte{'X'};
    ok &= expect(!cw::decodeEngineFrameHeader(badMagic, decoded, error), "bad magic rejected");

    cw::EngineFrameHeader oversized;
    oversized.payloadSize = cw::kEngineMaxPayloadSize + 1u;
    ok &= expect(!cw::encodeEngineFrameHeader(oversized, encoded), "oversized payload rejected");

    cw::EngineBufferWriter writer;
    writer.writeU8(0xAB);
    writer.writeU16(0xCDEF);
    writer.writeU32(0x89ABCDEFu);
    writer.writeU64(0x0123456789ABCDEFull);
    writer.writeI64(-123456789);
    ok &= expect(writer.writeString("Cheat Wizard"), "write string");
    const std::array<std::byte, 3> raw{std::byte{1}, std::byte{2}, std::byte{3}};
    writer.writeBytes(raw);

    cw::EngineBufferReader reader(writer.data());
    std::uint8_t u8{};
    std::uint16_t u16{};
    std::uint32_t u32{};
    std::uint64_t u64{};
    std::int64_t i64{};
    std::string text;
    std::array<std::byte, 3> decodedRaw{};
    ok &= expect(reader.readU8(u8) && u8 == 0xAB, "read u8");
    ok &= expect(reader.readU16(u16) && u16 == 0xCDEF, "read u16");
    ok &= expect(reader.readU32(u32) && u32 == 0x89ABCDEFu, "read u32");
    ok &= expect(reader.readU64(u64) && u64 == 0x0123456789ABCDEFull, "read u64");
    ok &= expect(reader.readI64(i64) && i64 == -123456789, "read i64");
    ok &= expect(reader.readString(text) && text == "Cheat Wizard", "read string");
    ok &= expect(reader.readBytes(decodedRaw) && decodedRaw == raw, "read raw bytes");
    ok &= expect(reader.empty(), "reader consumed full payload");

    const std::array<std::byte, 3> shortPayload{std::byte{5}, std::byte{0}, std::byte{0}};
    cw::EngineBufferReader shortReader(shortPayload);
    ok &= expect(!shortReader.readString(text), "truncated string rejected");

    if (!ok) return 1;
    std::cout << "EngineProtocol tests PASS\n";
    return 0;
}
