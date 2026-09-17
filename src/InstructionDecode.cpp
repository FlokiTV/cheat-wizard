#include "cw/InstructionDecode.hpp"

#include "cw/RelativeAddress.hpp"

#include <cstring>
#include <limits>

namespace cw {
namespace {

std::optional<std::uintptr_t> resolveSigned(
    std::uintptr_t instructionAddress,
    std::size_t instructionSize,
    std::int64_t displacement) noexcept
{
    const auto maxAddress = (std::numeric_limits<std::uintptr_t>::max)();
    if (instructionSize > maxAddress - instructionAddress) return std::nullopt;
    const auto nextInstruction = instructionAddress + static_cast<std::uintptr_t>(instructionSize);
    if (displacement >= 0) {
        const auto amount = static_cast<std::uint64_t>(displacement);
        if (amount > static_cast<std::uint64_t>(maxAddress - nextInstruction)) return std::nullopt;
        return nextInstruction + static_cast<std::uintptr_t>(amount);
    }
    const auto magnitude = static_cast<std::uint64_t>(-(displacement + 1)) + 1u;
    if (magnitude > static_cast<std::uint64_t>(nextInstruction)) return std::nullopt;
    return nextInstruction - static_cast<std::uintptr_t>(magnitude);
}

std::int32_t readI32(const std::byte* p) noexcept {
    std::int32_t value{};
    std::memcpy(&value, p, sizeof(value));
    return value;
}

std::int8_t readI8(const std::byte* p) noexcept {
    std::int8_t value{};
    std::memcpy(&value, p, sizeof(value));
    return value;
}

bool commonRipOpcode(std::uint8_t opcode) noexcept {
    switch (opcode) {
        case 0x8B: // MOV r, r/m
        case 0x89: // MOV r/m, r
        case 0x8D: // LEA
        case 0x39: // CMP r/m, r
        case 0x3B: // CMP r, r/m
        case 0x85: // TEST r/m, r
            return true;
        default:
            return false;
    }
}

} // namespace

std::optional<std::uintptr_t> resolveRel8(
    std::uintptr_t instructionAddress,
    std::size_t instructionSize,
    std::int8_t displacement) noexcept
{
    return resolveSigned(instructionAddress, instructionSize, displacement);
}

std::optional<RelativeInstructionInfo> decodeCommonRelativeInstruction(
    std::uintptr_t instructionAddress,
    std::span<const std::byte> bytes,
    bool x64) noexcept
{
    if (bytes.empty()) return std::nullopt;
    const auto u8 = [&](std::size_t i) { return static_cast<std::uint8_t>(bytes[i]); };

    auto rel32 = [&](RelativeInstructionKind kind, std::size_t size, std::size_t dispOffset,
                     bool indirect = false) -> std::optional<RelativeInstructionInfo> {
        if (bytes.size() < size || dispOffset + 4 > size) return std::nullopt;
        const auto target = resolveRel32(instructionAddress, size, readI32(bytes.data() + dispOffset));
        if (!target) return std::nullopt;
        return RelativeInstructionInfo{kind, size, dispOffset, 4, *target, indirect};
    };
    auto rel8 = [&](RelativeInstructionKind kind, std::size_t size, std::size_t dispOffset)
        -> std::optional<RelativeInstructionInfo> {
        if (bytes.size() < size || dispOffset + 1 > size) return std::nullopt;
        const auto target = resolveRel8(instructionAddress, size, readI8(bytes.data() + dispOffset));
        if (!target) return std::nullopt;
        return RelativeInstructionInfo{kind, size, dispOffset, 1, *target, false};
    };

    if (u8(0) == 0xE8) return rel32(RelativeInstructionKind::CallRel32, 5, 1);
    if (u8(0) == 0xE9) return rel32(RelativeInstructionKind::JumpRel32, 5, 1);
    if (u8(0) == 0xEB) return rel8(RelativeInstructionKind::JumpRel8, 2, 1);
    if (u8(0) >= 0x70 && u8(0) <= 0x7F) return rel8(RelativeInstructionKind::ConditionalRel8, 2, 1);
    if (bytes.size() >= 2 && u8(0) == 0x0F && u8(1) >= 0x80 && u8(1) <= 0x8F) {
        return rel32(RelativeInstructionKind::ConditionalRel32, 6, 2);
    }

    if (x64 && bytes.size() >= 6 && u8(0) == 0xFF) {
        if (u8(1) == 0x15) return rel32(RelativeInstructionKind::IndirectCallRip, 6, 2, true);
        if (u8(1) == 0x25) return rel32(RelativeInstructionKind::IndirectJumpRip, 6, 2, true);
    }

    if (x64) {
        std::size_t prefix = 0;
        if (u8(0) >= 0x40 && u8(0) <= 0x4F) prefix = 1;
        if (bytes.size() >= prefix + 6 && commonRipOpcode(u8(prefix))) {
            const auto modrm = u8(prefix + 1);
            if ((modrm & 0xC7u) == 0x05u) {
                const auto size = prefix + 6;
                const auto dispOffset = prefix + 2;
                return rel32(RelativeInstructionKind::RipRelativeMemory, size, dispOffset);
            }
        }
    }

    return std::nullopt;
}

const char* relativeInstructionKindName(RelativeInstructionKind kind) noexcept {
    switch (kind) {
        case RelativeInstructionKind::CallRel32: return "CALL rel32";
        case RelativeInstructionKind::JumpRel32: return "JMP rel32";
        case RelativeInstructionKind::JumpRel8: return "JMP rel8";
        case RelativeInstructionKind::ConditionalRel32: return "Jcc rel32";
        case RelativeInstructionKind::ConditionalRel8: return "Jcc rel8";
        case RelativeInstructionKind::IndirectCallRip: return "CALL [RIP+disp32]";
        case RelativeInstructionKind::IndirectJumpRip: return "JMP [RIP+disp32]";
        case RelativeInstructionKind::RipRelativeMemory: return "RIP-relative memory";
    }
    return "relative instruction";
}

} // namespace cw
