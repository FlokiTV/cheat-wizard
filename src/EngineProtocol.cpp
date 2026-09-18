#include "cw/EngineProtocol.hpp"

#include <limits>
#include <utility>

namespace cw {
namespace {

constexpr std::array<std::byte, 4> kMagic{
    std::byte{'C'}, std::byte{'W'}, std::byte{'E'}, std::byte{'P'}
};

void putU16(std::byte* dst, std::uint16_t value) noexcept {
    dst[0] = std::byte(value & 0xFFu);
    dst[1] = std::byte((value >> 8u) & 0xFFu);
}

void putU32(std::byte* dst, std::uint32_t value) noexcept {
    for (unsigned i = 0; i < 4; ++i) dst[i] = std::byte((value >> (i * 8u)) & 0xFFu);
}

void putU64(std::byte* dst, std::uint64_t value) noexcept {
    for (unsigned i = 0; i < 8; ++i) dst[i] = std::byte((value >> (i * 8u)) & 0xFFu);
}

std::uint16_t getU16(const std::byte* src) noexcept {
    return std::uint16_t(std::to_integer<std::uint8_t>(src[0])) |
           (std::uint16_t(std::to_integer<std::uint8_t>(src[1])) << 8u);
}

std::uint32_t getU32(const std::byte* src) noexcept {
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value |= std::uint32_t(std::to_integer<std::uint8_t>(src[i])) << (i * 8u);
    return value;
}

std::uint64_t getU64(const std::byte* src) noexcept {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= std::uint64_t(std::to_integer<std::uint8_t>(src[i])) << (i * 8u);
    return value;
}

} // namespace

bool encodeEngineFrameHeader(
    const EngineFrameHeader& header,
    std::array<std::byte, kEngineFrameHeaderSize>& out) noexcept
{
    if (header.payloadSize > kEngineMaxPayloadSize) return false;
    out.fill(std::byte{0});
    for (std::size_t i = 0; i < kMagic.size(); ++i) out[i] = kMagic[i];
    putU16(out.data() + 4, header.protocolMajor);
    putU16(out.data() + 6, header.protocolMinor);
    putU16(out.data() + 8, static_cast<std::uint16_t>(header.kind));
    putU16(out.data() + 10, header.flags);
    putU64(out.data() + 12, header.requestId);
    putU32(out.data() + 20, header.payloadSize);
    putU32(out.data() + 24, 0);
    return true;
}

bool decodeEngineFrameHeader(
    std::span<const std::byte> bytes,
    EngineFrameHeader& out,
    std::string& error) noexcept
{
    if (bytes.size() != kEngineFrameHeaderSize) { error = "Invalid engine frame header size"; return false; }
    for (std::size_t i = 0; i < kMagic.size(); ++i) {
        if (bytes[i] != kMagic[i]) { error = "Invalid engine frame magic"; return false; }
    }
    const auto payloadSize = getU32(bytes.data() + 20);
    if (payloadSize > kEngineMaxPayloadSize) { error = "Engine frame payload exceeds limit"; return false; }
    if (getU32(bytes.data() + 24) != 0) { error = "Engine frame reserved field is non-zero"; return false; }

    out.protocolMajor = getU16(bytes.data() + 4);
    out.protocolMinor = getU16(bytes.data() + 6);
    out.kind = static_cast<EngineMessageKind>(getU16(bytes.data() + 8));
    out.flags = getU16(bytes.data() + 10);
    out.requestId = getU64(bytes.data() + 12);
    out.payloadSize = payloadSize;
    error.clear();
    return true;
}

void EngineBufferWriter::writeU8(std::uint8_t value) { data_.push_back(std::byte{value}); }

void EngineBufferWriter::writeU16(std::uint16_t value) {
    const auto pos = data_.size(); data_.resize(pos + 2); putU16(data_.data() + pos, value);
}

void EngineBufferWriter::writeU32(std::uint32_t value) {
    const auto pos = data_.size(); data_.resize(pos + 4); putU32(data_.data() + pos, value);
}

void EngineBufferWriter::writeU64(std::uint64_t value) {
    const auto pos = data_.size(); data_.resize(pos + 8); putU64(data_.data() + pos, value);
}

void EngineBufferWriter::writeI64(std::int64_t value) { writeU64(static_cast<std::uint64_t>(value)); }

void EngineBufferWriter::writeBytes(std::span<const std::byte> bytes) {
    data_.insert(data_.end(), bytes.begin(), bytes.end());
}

bool EngineBufferWriter::writeString(std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) return false;
    writeU32(static_cast<std::uint32_t>(value.size()));
    writeBytes(std::as_bytes(std::span(value.data(), value.size())));
    return true;
}

bool EngineBufferReader::readU8(std::uint8_t& value) noexcept {
    if (remaining() < 1) return false; value = std::to_integer<std::uint8_t>(data_[offset_++]); return true;
}

bool EngineBufferReader::readU16(std::uint16_t& value) noexcept {
    if (remaining() < 2) return false; value = getU16(data_.data() + offset_); offset_ += 2; return true;
}

bool EngineBufferReader::readU32(std::uint32_t& value) noexcept {
    if (remaining() < 4) return false; value = getU32(data_.data() + offset_); offset_ += 4; return true;
}

bool EngineBufferReader::readU64(std::uint64_t& value) noexcept {
    if (remaining() < 8) return false; value = getU64(data_.data() + offset_); offset_ += 8; return true;
}

bool EngineBufferReader::readI64(std::int64_t& value) noexcept {
    std::uint64_t raw{}; if (!readU64(raw)) return false; value = static_cast<std::int64_t>(raw); return true;
}

bool EngineBufferReader::readBytes(std::span<std::byte> out) noexcept {
    if (remaining() < out.size()) return false;
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = data_[offset_ + i];
    offset_ += out.size();
    return true;
}

bool EngineBufferReader::readString(std::string& value) {
    std::uint32_t size{};
    if (!readU32(size) || remaining() < size) return false;
    value.assign(reinterpret_cast<const char*>(data_.data() + offset_), size);
    offset_ += size;
    return true;
}

} // namespace cw
