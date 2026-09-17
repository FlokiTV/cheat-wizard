#include "cw/AobPattern.hpp"

#include <cctype>
#include <sstream>

namespace cw {
namespace {

int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

bool parseToken(std::string_view token, AobByte& out) {
    if (token == "?" || token == "??") {
        out = AobByte{0, 0};
        return true;
    }
    if (token.size() != 2) return false;

    const bool hiWild = token[0] == '?';
    const bool loWild = token[1] == '?';
    const int hi = hiWild ? 0 : hexValue(token[0]);
    const int lo = loWild ? 0 : hexValue(token[1]);
    if ((!hiWild && hi < 0) || (!loWild && lo < 0)) return false;

    std::uint8_t mask = 0;
    if (!hiWild) mask |= 0xF0u;
    if (!loWild) mask |= 0x0Fu;
    out.value = static_cast<std::uint8_t>((hi << 4) | lo);
    out.mask = mask;
    return true;
}

} // namespace

std::optional<AobPattern> parseAobPattern(std::string_view text, std::string& error) {
    AobPattern pattern;
    std::istringstream input{std::string(text)};
    std::string token;
    std::size_t index = 0;
    while (input >> token) {
        AobByte byte{};
        if (!parseToken(token, byte)) {
            std::ostringstream out;
            out << "Invalid AOB token #" << index << " ('" << token
                << "'). Use hex bytes like 8B, wildcards ??, or nibble wildcards A? / ?F.";
            error = out.str();
            return std::nullopt;
        }
        pattern.bytes.push_back(byte);
        ++index;
    }
    if (pattern.bytes.empty()) {
        error = "AOB pattern is empty";
        return std::nullopt;
    }
    if (pattern.bytes.size() > 4096) {
        error = "AOB pattern is too long (maximum 4096 bytes)";
        return std::nullopt;
    }
    error.clear();
    return pattern;
}

bool matchAob(const std::byte* data, const AobPattern& pattern) noexcept {
    if (!data || pattern.bytes.empty()) return false;
    for (std::size_t i = 0; i < pattern.bytes.size(); ++i) {
        const auto actual = static_cast<std::uint8_t>(data[i]);
        const auto& expected = pattern.bytes[i];
        if ((actual & expected.mask) != (expected.value & expected.mask)) return false;
    }
    return true;
}

std::string formatAobPattern(const AobPattern& pattern) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    for (std::size_t i = 0; i < pattern.bytes.size(); ++i) {
        if (i) out.push_back(' ');
        const auto& b = pattern.bytes[i];
        out.push_back((b.mask & 0xF0u) ? hex[(b.value >> 4) & 0xFu] : '?');
        out.push_back((b.mask & 0x0Fu) ? hex[b.value & 0xFu] : '?');
    }
    return out;
}

} // namespace cw
