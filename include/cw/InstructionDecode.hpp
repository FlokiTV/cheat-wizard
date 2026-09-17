#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace cw {

enum class RelativeInstructionKind {
    CallRel32,
    JumpRel32,
    JumpRel8,
    ConditionalRel32,
    ConditionalRel8,
    IndirectCallRip,
    IndirectJumpRip,
    RipRelativeMemory,
};

struct RelativeInstructionInfo {
    RelativeInstructionKind kind{};
    std::size_t instructionSize{};
    std::size_t displacementOffset{};
    std::size_t displacementSize{};
    std::uintptr_t target{}; // direct target, or RIP-relative memory slot/address
    bool indirect{};        // target is a pointer slot for FF /2 or FF /4
};

std::optional<std::uintptr_t> resolveRel8(
    std::uintptr_t instructionAddress,
    std::size_t instructionSize,
    std::int8_t displacement) noexcept;

std::optional<RelativeInstructionInfo> decodeCommonRelativeInstruction(
    std::uintptr_t instructionAddress,
    std::span<const std::byte> bytes,
    bool x64) noexcept;

const char* relativeInstructionKindName(RelativeInstructionKind kind) noexcept;

} // namespace cw
