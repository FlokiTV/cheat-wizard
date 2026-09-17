#include "cw/PointerProfile.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <type_traits>

namespace cw {
namespace {

constexpr std::array<char, 8> kMagic{'C','W','P','R','O','F','0','1'};
constexpr std::array<char, 8> kLegacyMagic{'M','C','E','P','R','O','F','1'};
constexpr std::uint32_t kVersion = 1;
constexpr std::size_t kMaxModuleBytes = 4096;
constexpr std::size_t kMaxProcessBytes = 4096;

template <typename T>
bool writeLe(std::ostream& out, T value) {
    static_assert(std::is_unsigned_v<T>);
    std::array<unsigned char, sizeof(T)> bytes{};
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        bytes[i] = static_cast<unsigned char>((value >> (i * 8)) & static_cast<T>(0xFF));
    }
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(out);
}

template <typename T>
bool readLe(std::istream& in, T& value) {
    static_assert(std::is_unsigned_v<T>);
    std::array<unsigned char, sizeof(T)> bytes{};
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in) return false;
    value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) value |= static_cast<T>(bytes[i]) << (i * 8);
    return true;
}

void appendUtf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7F) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string wideToUtf8(const std::wstring& text) {
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        std::uint32_t cp = static_cast<std::uint32_t>(text[i]);
        if constexpr (sizeof(wchar_t) == 2) {
            if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < text.size()) {
                const auto lo = static_cast<std::uint32_t>(text[i + 1]);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    ++i;
                }
            }
        }
        if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0xFFFD;
        if (cp > 0x10FFFF) cp = 0xFFFD;
        appendUtf8(out, cp);
    }
    return out;
}

bool decodeUtf8(const std::string& text, std::wstring& out) {
    out.clear();
    for (std::size_t i = 0; i < text.size();) {
        const auto first = static_cast<unsigned char>(text[i]);
        std::uint32_t cp{};
        std::size_t count{};
        if (first <= 0x7F) { cp = first; count = 1; }
        else if ((first & 0xE0) == 0xC0) { cp = first & 0x1F; count = 2; }
        else if ((first & 0xF0) == 0xE0) { cp = first & 0x0F; count = 3; }
        else if ((first & 0xF8) == 0xF0) { cp = first & 0x07; count = 4; }
        else return false;
        if (i + count > text.size()) return false;
        for (std::size_t j = 1; j < count; ++j) {
            const auto c = static_cast<unsigned char>(text[i + j]);
            if ((c & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3F);
        }
        if ((count == 2 && cp < 0x80) || (count == 3 && cp < 0x800) ||
            (count == 4 && cp < 0x10000) || cp > 0x10FFFF ||
            (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        if constexpr (sizeof(wchar_t) == 2) {
            if (cp <= 0xFFFF) out.push_back(static_cast<wchar_t>(cp));
            else {
                cp -= 0x10000;
                out.push_back(static_cast<wchar_t>(0xD800 + (cp >> 10)));
                out.push_back(static_cast<wchar_t>(0xDC00 + (cp & 0x3FF)));
            }
        } else out.push_back(static_cast<wchar_t>(cp));
        i += count;
    }
    return true;
}

std::uint32_t valueTypeCode(ValueType type) {
    return static_cast<std::uint32_t>(type);
}

bool validValueTypeCode(std::uint32_t code) {
    return code <= static_cast<std::uint32_t>(ValueType::Double);
}

} // namespace

bool savePointerProfile(const std::string& path, const PointerProfileData& profile, std::string& error) {
    error.clear();
    if (profile.pointerSize != 4 && profile.pointerSize != 8) { error = "pointer width must be 4 or 8"; return false; }
    if (profile.processName.size() > kMaxProcessBytes || profile.processName.size() > std::numeric_limits<std::uint16_t>::max()) { error = "process name too long"; return false; }
    if (profile.chains.empty()) { error = "profile has no chains"; return false; }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) { error = "could not open output file"; return false; }
    const auto processLen = static_cast<std::uint16_t>(profile.processName.size());
    out.write(kMagic.data(), static_cast<std::streamsize>(kMagic.size()));
    if (!writeLe<std::uint32_t>(out, kVersion) ||
        !writeLe<std::uint32_t>(out, static_cast<std::uint32_t>(profile.pointerSize)) ||
        !writeLe<std::uint32_t>(out, valueTypeCode(profile.type)) ||
        !writeLe<std::uint16_t>(out, processLen) ||
        !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(profile.chains.size()))) {
        error = "failed writing profile header"; return false;
    }
    if (processLen) out.write(profile.processName.data(), static_cast<std::streamsize>(processLen));
    for (const auto& chain : profile.chains) {
        const auto module = wideToUtf8(chain.moduleName);
        if (module.empty() || module.size() > kMaxModuleBytes || module.size() > std::numeric_limits<std::uint16_t>::max()) { error = "invalid module name"; return false; }
        if (chain.offsets.empty() || chain.offsets.size() > std::numeric_limits<std::uint32_t>::max()) { error = "invalid chain depth"; return false; }
        const auto moduleLen = static_cast<std::uint16_t>(module.size());
        if (!writeLe<std::uint16_t>(out, moduleLen)) { error = "failed writing module length"; return false; }
        out.write(module.data(), static_cast<std::streamsize>(module.size()));
        if (!out || !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(chain.rootOffset)) ||
            !writeLe<std::uint32_t>(out, static_cast<std::uint32_t>(chain.offsets.size()))) { error = "failed writing chain"; return false; }
        for (const auto offset : chain.offsets) {
            std::uint64_t raw{};
            std::memcpy(&raw, &offset, sizeof(raw));
            if (!writeLe<std::uint64_t>(out, raw)) { error = "failed writing offsets"; return false; }
        }
    }
    out.flush();
    if (!out) { error = "failed flushing profile"; return false; }
    return true;
}

bool loadPointerProfile(const std::string& path, PointerProfileData& profile, std::string& error, std::size_t maxChains, std::size_t maxDepth) {
    error.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in) { error = "could not open input file"; return false; }
    std::array<char, 8> magic{};
    in.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    std::uint32_t version{}, pointerSize{}, typeCode{};
    std::uint16_t processLen{};
    std::uint64_t chainCount{};
    if (!in || (magic != kMagic && magic != kLegacyMagic) || !readLe(in, version) || !readLe(in, pointerSize) || !readLe(in, typeCode) ||
        !readLe(in, processLen) || !readLe(in, chainCount)) { error = "invalid/truncated profile header"; return false; }
    if (version != kVersion || (pointerSize != 4 && pointerSize != 8) || !validValueTypeCode(typeCode) ||
        processLen > kMaxProcessBytes || chainCount == 0 || chainCount > maxChains) { error = "unsupported or unsafe profile"; return false; }
    PointerProfileData parsed;
    parsed.pointerSize = pointerSize;
    parsed.type = static_cast<ValueType>(typeCode);
    parsed.processName.resize(processLen);
    if (processLen) in.read(parsed.processName.data(), static_cast<std::streamsize>(processLen));
    if (!in) { error = "truncated process name"; return false; }
    parsed.chains.reserve(static_cast<std::size_t>(chainCount));
    for (std::uint64_t i = 0; i < chainCount; ++i) {
        std::uint16_t moduleLen{};
        if (!readLe(in, moduleLen) || moduleLen == 0 || moduleLen > kMaxModuleBytes) { error = "invalid module name length"; return false; }
        std::string module(moduleLen, '\0');
        in.read(module.data(), static_cast<std::streamsize>(module.size()));
        PointerChain chain;
        if (!in || !decodeUtf8(module, chain.moduleName) || chain.moduleName.empty()) { error = "invalid module name"; return false; }
        std::uint64_t root{};
        std::uint32_t depth{};
        if (!readLe(in, root) || !readLe(in, depth) || depth == 0 || depth > maxDepth) { error = "invalid chain depth"; return false; }
        if (root > std::numeric_limits<std::uintptr_t>::max()) { error = "root offset does not fit this build"; return false; }
        chain.rootOffset = static_cast<std::uintptr_t>(root);
        chain.offsets.resize(depth);
        for (std::uint32_t j = 0; j < depth; ++j) {
            std::uint64_t raw{};
            if (!readLe(in, raw)) { error = "truncated offsets"; return false; }
            std::memcpy(&chain.offsets[j], &raw, sizeof(raw));
        }
        parsed.chains.push_back(std::move(chain));
    }
    char extra{};
    in.read(&extra, 1);
    if (in.gcount() != 0) { error = "profile has trailing data"; return false; }
    profile = std::move(parsed);
    return true;
}

} // namespace cw
