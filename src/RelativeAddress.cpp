#include "cw/RelativeAddress.hpp"

#include <limits>

namespace cw {

std::optional<std::uintptr_t> resolveRel32(
    std::uintptr_t instructionAddress,
    std::size_t instructionSize,
    std::int32_t displacement) noexcept
{
    const auto maxAddress = (std::numeric_limits<std::uintptr_t>::max)();
    if (instructionSize > maxAddress - instructionAddress) return std::nullopt;
    const auto nextInstruction = instructionAddress + static_cast<std::uintptr_t>(instructionSize);

    if (displacement >= 0) {
        const auto amount = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(displacement));
        if (amount > maxAddress - nextInstruction) return std::nullopt;
        return nextInstruction + amount;
    }

    const auto magnitude = static_cast<std::uint64_t>(-(static_cast<std::int64_t>(displacement)));
    if (magnitude > static_cast<std::uint64_t>(nextInstruction)) return std::nullopt;
    return nextInstruction - static_cast<std::uintptr_t>(magnitude);
}

} // namespace cw
