#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace cw {

struct AobByte {
    std::uint8_t value{};
    std::uint8_t mask{}; // 0 = wildcard, 0xF0/0x0F = nibble wildcard, 0xFF = exact
};

struct AobPattern {
    std::vector<AobByte> bytes;

    [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return bytes.size(); }
};

std::optional<AobPattern> parseAobPattern(std::string_view text, std::string& error);
[[nodiscard]] bool matchAob(const std::byte* data, const AobPattern& pattern) noexcept;
[[nodiscard]] std::string formatAobPattern(const AobPattern& pattern);

} // namespace cw
