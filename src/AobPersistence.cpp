#include "cw/AobPersistence.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <limits>
#include <type_traits>

namespace cw {
namespace {

constexpr std::array<char, 8> kMagic{'C','W','A','O','B','0','0','1'};
constexpr std::array<char, 8> kLegacyMagic{'M','C','E','A','O','B','0','1'};
constexpr std::uint32_t kVersion = 1;
constexpr std::size_t kMaxPatternBytes = 4096;

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

bool validScope(std::uint32_t value) {
    return value <= static_cast<std::uint32_t>(AobSearchScope::ModuleExecutable);
}

bool moduleScope(AobSearchScope scope) {
    return scope == AobSearchScope::Module || scope == AobSearchScope::ModuleExecutable;
}

} // namespace

bool saveAobSession(const std::string& path, const AobSessionData& data, std::string& error) {
    error.clear();
    if (data.pattern.empty() || data.pattern.size() > kMaxPatternBytes) {
        error = "AOB pattern is empty or too large";
        return false;
    }
    if (moduleScope(data.scope) && data.moduleName.empty()) {
        error = "module-restricted AOB session has no module name";
        return false;
    }
    if (data.moduleName.size() > std::numeric_limits<std::uint16_t>::max()) {
        error = "AOB module name is too long";
        return false;
    }
    if (data.results.size() > std::numeric_limits<std::uint64_t>::max()) {
        error = "too many AOB results";
        return false;
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) { error = "could not open output file"; return false; }

    out.write(kMagic.data(), static_cast<std::streamsize>(kMagic.size()));
    if (!writeLe<std::uint32_t>(out, kVersion) ||
        !writeLe<std::uint32_t>(out, static_cast<std::uint32_t>(data.scope)) ||
        !writeLe<std::uint32_t>(out, static_cast<std::uint32_t>(data.pattern.size())) ||
        !writeLe<std::uint16_t>(out, static_cast<std::uint16_t>(data.moduleName.size())) ||
        !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(data.results.size()))) {
        error = "failed writing AOB session header";
        return false;
    }

    for (const auto& byte : data.pattern.bytes) {
        const std::array<unsigned char, 2> pair{byte.value, byte.mask};
        out.write(reinterpret_cast<const char*>(pair.data()), 2);
        if (!out) { error = "failed writing AOB pattern"; return false; }
    }
    if (!data.moduleName.empty()) {
        out.write(data.moduleName.data(), static_cast<std::streamsize>(data.moduleName.size()));
        if (!out) { error = "failed writing AOB module name"; return false; }
    }

    for (const auto& result : data.results) {
        if (result.moduleRelative && (result.moduleName.empty() ||
            result.moduleName.size() > std::numeric_limits<std::uint16_t>::max())) {
            error = "AOB result module name is empty or too long";
            return false;
        }
        const unsigned char kind = result.moduleRelative ? 1u : 0u;
        out.write(reinterpret_cast<const char*>(&kind), 1);
        const auto nameLength = static_cast<std::uint16_t>(result.moduleRelative ? result.moduleName.size() : 0);
        if (!writeLe<std::uint16_t>(out, nameLength) ||
            !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(result.value))) {
            error = "failed writing AOB result";
            return false;
        }
        if (nameLength) {
            out.write(result.moduleName.data(), static_cast<std::streamsize>(result.moduleName.size()));
            if (!out) { error = "failed writing AOB result module"; return false; }
        }
    }

    out.flush();
    if (!out) { error = "failed flushing AOB session file"; return false; }
    return true;
}

bool loadAobSession(
    const std::string& path,
    AobSessionData& data,
    std::string& error,
    std::size_t maxResults,
    std::size_t maxNameBytes)
{
    error.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in) { error = "could not open input file"; return false; }

    std::array<char, 8> magic{};
    std::uint32_t version{}, scopeRaw{}, patternCount{};
    std::uint16_t moduleNameLength{};
    std::uint64_t resultCount{};
    in.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    if (!in || (magic != kMagic && magic != kLegacyMagic) ||
        !readLe<std::uint32_t>(in, version) || version != kVersion ||
        !readLe<std::uint32_t>(in, scopeRaw) || !validScope(scopeRaw) ||
        !readLe<std::uint32_t>(in, patternCount) || patternCount == 0 || patternCount > kMaxPatternBytes ||
        !readLe<std::uint16_t>(in, moduleNameLength) || moduleNameLength > maxNameBytes ||
        !readLe<std::uint64_t>(in, resultCount) || resultCount > maxResults) {
        error = "invalid or unsupported AOB session header";
        return false;
    }

    AobSessionData parsed;
    parsed.scope = static_cast<AobSearchScope>(scopeRaw);
    parsed.pattern.bytes.resize(patternCount);
    for (auto& byte : parsed.pattern.bytes) {
        std::array<unsigned char, 2> pair{};
        in.read(reinterpret_cast<char*>(pair.data()), 2);
        if (!in) { error = "truncated AOB pattern"; return false; }
        byte.value = pair[0];
        byte.mask = pair[1];
        if (byte.mask != 0 && byte.mask != 0x0F && byte.mask != 0xF0 && byte.mask != 0xFF) {
            error = "invalid AOB pattern mask";
            return false;
        }
    }
    parsed.moduleName.resize(moduleNameLength);
    if (moduleNameLength) {
        in.read(parsed.moduleName.data(), static_cast<std::streamsize>(moduleNameLength));
        if (!in) { error = "truncated AOB module name"; return false; }
    }
    if (moduleScope(parsed.scope) && parsed.moduleName.empty()) {
        error = "module-restricted AOB session is missing its module name";
        return false;
    }

    parsed.results.reserve(static_cast<std::size_t>(resultCount));
    for (std::uint64_t i = 0; i < resultCount; ++i) {
        unsigned char kind{};
        std::uint16_t nameLength{};
        std::uint64_t value{};
        in.read(reinterpret_cast<char*>(&kind), 1);
        if (!in || (kind != 0 && kind != 1) ||
            !readLe<std::uint16_t>(in, nameLength) || nameLength > maxNameBytes ||
            !readLe<std::uint64_t>(in, value)) {
            error = "invalid or truncated AOB result";
            return false;
        }
        AobSavedResult result;
        result.moduleRelative = kind == 1;
        result.value = static_cast<std::uintptr_t>(value);
        if (static_cast<std::uint64_t>(result.value) != value) {
            error = "AOB result address does not fit this build";
            return false;
        }
        if (nameLength) {
            result.moduleName.resize(nameLength);
            in.read(result.moduleName.data(), static_cast<std::streamsize>(nameLength));
            if (!in) { error = "truncated AOB result module name"; return false; }
        }
        if (result.moduleRelative && result.moduleName.empty()) {
            error = "module-relative AOB result has no module name";
            return false;
        }
        if (!result.moduleRelative && nameLength != 0) {
            error = "absolute AOB result unexpectedly has a module name";
            return false;
        }
        parsed.results.push_back(std::move(result));
    }

    char extra{};
    if (in.read(&extra, 1)) { error = "AOB session file has unexpected trailing data"; return false; }
    if (!in.eof()) { error = "failed while validating AOB session file"; return false; }

    data = std::move(parsed);
    return true;
}

} // namespace cw
