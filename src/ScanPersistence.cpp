#include "cw/ScanPersistence.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <fstream>
#include <limits>
#include <type_traits>

namespace cw {
namespace {

constexpr std::array<char, 8> kMagic{'C','W','S','C','A','N','0','1'};
constexpr std::array<char, 8> kLegacyMagic{'M','C','E','S','C','A','N','1'};
constexpr std::uint32_t kVersion = 1;
constexpr std::uint32_t kFlagMixed = 1u << 0;

std::uint32_t encodeType(ValueType type) {
    switch (type) {
        case ValueType::Byte: return 1;
        case ValueType::Int16: return 2;
        case ValueType::Int32: return 3;
        case ValueType::Int64: return 4;
        case ValueType::Float: return 5;
        case ValueType::Double: return 6;
    }
    return 0;
}

bool decodeType(std::uint32_t code, ValueType& type) {
    switch (code) {
        case 1: type = ValueType::Byte; return true;
        case 2: type = ValueType::Int16; return true;
        case 3: type = ValueType::Int32; return true;
        case 4: type = ValueType::Int64; return true;
        case 5: type = ValueType::Float; return true;
        case 6: type = ValueType::Double; return true;
        default: return false;
    }
}

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

} // namespace

bool saveScanSession(const std::string& path, const ScanSessionData& data, std::string& error) {
    error.clear();
    const auto primaryCode = encodeType(data.primaryType);
    if (primaryCode == 0) { error = "invalid primary value type"; return false; }
    if (data.results.size() > std::numeric_limits<std::uint64_t>::max()) {
        error = "too many scan results"; return false;
    }
    if (data.options.minAddress > data.options.maxAddress) {
        error = "invalid scan address range"; return false;
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) { error = "could not open output file"; return false; }

    out.write(kMagic.data(), static_cast<std::streamsize>(kMagic.size()));
    const std::uint32_t flags = data.mixed ? kFlagMixed : 0u;
    const std::uint32_t alignment = data.options.alignment == AlignmentMode::Byte ? 1u : 0u;
    const std::uint32_t writable = data.options.writableOnly ? 1u : 0u;
    const std::uint32_t privateOnly = data.options.privateOnly ? 1u : 0u;
    const auto toleranceBits = std::bit_cast<std::uint64_t>(data.options.floatTolerance);

    if (!writeLe<std::uint32_t>(out, kVersion) ||
        !writeLe<std::uint32_t>(out, flags) ||
        !writeLe<std::uint32_t>(out, primaryCode) ||
        !writeLe<std::uint32_t>(out, alignment) ||
        !writeLe<std::uint32_t>(out, writable) ||
        !writeLe<std::uint32_t>(out, privateOnly) ||
        !writeLe<std::uint64_t>(out, data.sourcePid) ||
        !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(data.options.minAddress)) ||
        !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(data.options.maxAddress)) ||
        !writeLe<std::uint64_t>(out, toleranceBits) ||
        !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(data.results.size()))) {
        error = "failed writing scan-session header"; return false;
    }

    for (const auto& result : data.results) {
        const auto typeCode = encodeType(result.type);
        if (typeCode == 0) { error = "scan result contains invalid type"; return false; }
        if (!writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(result.address)) ||
            !writeLe<std::uint64_t>(out, result.previousBits) ||
            !writeLe<std::uint32_t>(out, typeCode) ||
            !writeLe<std::uint32_t>(out, 0u)) {
            error = "failed writing scan-session result"; return false;
        }
    }

    out.flush();
    if (!out) { error = "failed flushing scan-session file"; return false; }
    return true;
}

bool loadScanSession(
    const std::string& path,
    ScanSessionData& data,
    std::string& error,
    std::size_t maxResults)
{
    error.clear();
    ScanSessionData parsed;
    std::ifstream in(path, std::ios::binary);
    if (!in) { error = "could not open input file"; return false; }

    std::array<char, 8> magic{};
    in.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    if (!in || (magic != kMagic && magic != kLegacyMagic)) { error = "not a supported scan-session file"; return false; }

    std::uint32_t version{}, flags{}, primaryCode{}, alignment{}, writable{}, privateOnly{};
    std::uint64_t sourcePid{}, minAddress{}, maxAddress{}, toleranceBits{}, resultCount{};
    if (!readLe(in, version) || !readLe(in, flags) || !readLe(in, primaryCode) ||
        !readLe(in, alignment) || !readLe(in, writable) || !readLe(in, privateOnly) ||
        !readLe(in, sourcePid) || !readLe(in, minAddress) || !readLe(in, maxAddress) ||
        !readLe(in, toleranceBits) || !readLe(in, resultCount)) {
        error = "truncated scan-session header"; return false;
    }
    if (version != kVersion) { error = "unsupported scan-session version"; return false; }
    if ((flags & ~kFlagMixed) != 0u) { error = "unknown scan-session flags"; return false; }
    if (alignment > 1 || writable > 1 || privateOnly > 1) {
        error = "invalid scan-session settings"; return false;
    }
    if (!decodeType(primaryCode, parsed.primaryType)) { error = "invalid primary value type"; return false; }
    if (resultCount > maxResults) { error = "scan session exceeds result safety limit"; return false; }
    if (minAddress > maxAddress || maxAddress > std::numeric_limits<std::uintptr_t>::max()) {
        error = "invalid scan-session address range"; return false;
    }
    const double tolerance = std::bit_cast<double>(toleranceBits);
    if (!(tolerance >= 0.0) || tolerance > 1.0e300) {
        error = "invalid float tolerance in scan session"; return false;
    }

    parsed.sourcePid = sourcePid;
    parsed.mixed = (flags & kFlagMixed) != 0;
    parsed.options.alignment = alignment ? AlignmentMode::Byte : AlignmentMode::Natural;
    parsed.options.writableOnly = writable != 0;
    parsed.options.privateOnly = privateOnly != 0;
    parsed.options.minAddress = static_cast<std::uintptr_t>(minAddress);
    parsed.options.maxAddress = static_cast<std::uintptr_t>(maxAddress);
    parsed.options.floatTolerance = tolerance;
    parsed.results.reserve(static_cast<std::size_t>(resultCount));

    for (std::uint64_t i = 0; i < resultCount; ++i) {
        std::uint64_t address{}, previousBits{};
        std::uint32_t typeCode{}, reserved{};
        if (!readLe(in, address) || !readLe(in, previousBits) ||
            !readLe(in, typeCode) || !readLe(in, reserved)) {
            error = "truncated scan-session result list"; return false;
        }
        if (reserved != 0u || address > std::numeric_limits<std::uintptr_t>::max()) {
            error = "invalid scan-session result record"; return false;
        }
        ValueType type{};
        if (!decodeType(typeCode, type)) { error = "invalid result type in scan session"; return false; }
        if (!parsed.mixed && type != parsed.primaryType) {
            error = "non-mixed scan session contains mismatched result type"; return false;
        }
        parsed.results.push_back(ScanResult{static_cast<std::uintptr_t>(address), previousBits, type});
    }

    char extra{};
    if (in.read(&extra, 1)) { error = "scan-session file has unexpected trailing data"; return false; }
    if (!in.eof()) { error = "failed while validating scan-session file"; return false; }

    data = std::move(parsed);
    return true;
}

} // namespace cw
