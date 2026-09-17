#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace cw {

// Resolve a signed x86/x64 rel32 displacement. The displacement is interpreted
// relative to instructionAddress + instructionSize, which covers CALL/JMP rel32
// and RIP-relative memory operands when the caller supplies the correct fields.
std::optional<std::uintptr_t> resolveRel32(
    std::uintptr_t instructionAddress,
    std::size_t instructionSize,
    std::int32_t displacement) noexcept;

} // namespace cw
