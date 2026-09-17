#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace cw {

template <typename T>
bool scanExactBuffer(
    const std::byte* buffer,
    std::size_t bytesRead,
    std::uintptr_t baseAddress,
    T wanted,
    std::vector<std::uintptr_t>& out,
    std::size_t alignment = sizeof(T),
    std::size_t maxResults = (std::numeric_limits<std::size_t>::max)())
{
    if (!buffer || bytesRead < sizeof(T) || alignment == 0) {
        return true;
    }

    std::size_t start = 0;
    const std::size_t remainder = static_cast<std::size_t>(baseAddress % alignment);
    if (remainder != 0) {
        start = alignment - remainder;
    }

    for (std::size_t offset = start; offset + sizeof(T) <= bytesRead; offset += alignment) {
        T current{};
        std::memcpy(&current, buffer + offset, sizeof(T));
        if (current == wanted) {
            if (out.size() >= maxResults) return false;
            out.push_back(baseAddress + offset);
        }
    }
    return true;
}

} // namespace cw
