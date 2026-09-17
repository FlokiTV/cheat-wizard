#include "cw/PointerMap.hpp"

#include "cw/PointerAlgorithms.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <limits>
#include <string>
#include <type_traits>

namespace cw {
namespace {

constexpr std::array<char, 8> kMagic{'C','W','M','A','P','0','0','1'};
constexpr std::array<char, 8> kLegacyMagic{'M','C','E','P','M','A','P','1'};
constexpr std::uint32_t kVersion = 1;
constexpr std::size_t kMaxModuleBytes = 4096;

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

std::string wideToUtf8Portable(const std::wstring& text) {
    std::string out;
    out.reserve(text.size());
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
        if ((cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) cp = 0xFFFD;
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

bool sameModuleName(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        auto lower = [](wchar_t c) {
            return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
        };
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

const PointerModule* findModule(const PointerMapData& map, const std::wstring& name) {
    for (const auto& module : map.modules) if (sameModuleName(module.name, name)) return &module;
    return nullptr;
}

bool addressLess(const PointerEntry& a, const PointerEntry& b) {
    if (a.address != b.address) return a.address < b.address;
    return a.value < b.value;
}

std::optional<std::uintptr_t> pointerAtAddress(PointerMapData& map, std::uintptr_t address) {
    const PointerEntry key{0, address};
    const auto it = std::lower_bound(map.entries.begin(), map.entries.end(), key,
        [](const PointerEntry& lhs, const PointerEntry& rhs) {
            if (lhs.address != rhs.address) return lhs.address < rhs.address;
            return lhs.value < rhs.value;
        });
    if (it == map.entries.end() || it->address != address) return std::nullopt;
    return it->value;
}

std::optional<std::uintptr_t> addSignedOffset(std::uintptr_t base, std::int64_t offset) {
    if (offset >= 0) {
        const auto amount = static_cast<std::uint64_t>(offset);
        if (amount > static_cast<std::uint64_t>((std::numeric_limits<std::uintptr_t>::max)() - base)) return std::nullopt;
        return base + static_cast<std::uintptr_t>(amount);
    }
    const auto magnitude = static_cast<std::uint64_t>(-(offset + 1)) + 1u;
    if (magnitude > static_cast<std::uint64_t>(base)) return std::nullopt;
    return base - static_cast<std::uintptr_t>(magnitude);
}

} // namespace

bool savePointerMap(
    const std::string& path,
    std::size_t pointerSize,
    std::uintptr_t target,
    const std::vector<PointerModule>& modules,
    const std::vector<PointerEntry>& entries,
    bool complete,
    std::string& error)
{
    error.clear();
    if (pointerSize != 4 && pointerSize != 8) { error = "pointer width must be 4 or 8 bytes"; return false; }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) { error = "could not open output file"; return false; }

    out.write(kMagic.data(), static_cast<std::streamsize>(kMagic.size()));
    if (!writeLe<std::uint32_t>(out, kVersion) ||
        !writeLe<std::uint32_t>(out, static_cast<std::uint32_t>(pointerSize)) ||
        !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(target)) ||
        !writeLe<std::uint32_t>(out, static_cast<std::uint32_t>(modules.size())) ||
        !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(entries.size())) ||
        !writeLe<std::uint32_t>(out, complete ? 1u : 0u)) {
        error = "failed writing pointer-map header"; return false;
    }

    for (const auto& module : modules) {
        const auto name = wideToUtf8Portable(module.name);
        if (name.empty() || name.size() > kMaxModuleBytes ||
            name.size() > std::numeric_limits<std::uint16_t>::max()) {
            error = "module name is empty or too long"; return false;
        }
        if (!writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(module.base)) ||
            !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(module.size)) ||
            !writeLe<std::uint16_t>(out, static_cast<std::uint16_t>(name.size()))) {
            error = "failed writing pointer-map module"; return false;
        }
        out.write(name.data(), static_cast<std::streamsize>(name.size()));
        if (!out) { error = "failed writing pointer-map module name"; return false; }
    }

    for (const auto& entry : entries) {
        if (!writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(entry.value)) ||
            !writeLe<std::uint64_t>(out, static_cast<std::uint64_t>(entry.address))) {
            error = "failed writing pointer-map entries"; return false;
        }
    }
    out.flush();
    if (!out) { error = "failed flushing pointer-map file"; return false; }
    return true;
}

bool loadPointerMap(
    const std::string& path,
    PointerMapData& data,
    std::string& error,
    std::size_t maxEntries,
    std::size_t maxModules)
{
    error.clear();
    PointerMapData parsed;
    std::ifstream in(path, std::ios::binary);
    if (!in) { error = "could not open input file"; return false; }

    std::array<char, 8> magic{};
    in.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    if (!in || (magic != kMagic && magic != kLegacyMagic)) { error = "not a supported pointer-map file"; return false; }

    std::uint32_t version{}, pointerSize{}, moduleCount{}, flags{};
    std::uint64_t target{}, entryCount{};
    if (!readLe(in, version) || !readLe(in, pointerSize) || !readLe(in, target) ||
        !readLe(in, moduleCount) || !readLe(in, entryCount) || !readLe(in, flags)) {
        error = "truncated pointer-map header"; return false;
    }
    if (version != kVersion) { error = "unsupported pointer-map version"; return false; }
    if (pointerSize != 4 && pointerSize != 8) { error = "invalid pointer width in pointer map"; return false; }
    if (moduleCount > maxModules) { error = "pointer map exceeds module safety limit"; return false; }
    if (entryCount > maxEntries) { error = "pointer map exceeds entry safety limit"; return false; }
    if (target > std::numeric_limits<std::uintptr_t>::max()) { error = "target address does not fit this build"; return false; }

    parsed.pointerSize = pointerSize;
    parsed.target = static_cast<std::uintptr_t>(target);
    parsed.complete = (flags & 1u) != 0;
    parsed.modules.reserve(moduleCount);
    parsed.entries.reserve(static_cast<std::size_t>(entryCount));

    for (std::uint32_t i = 0; i < moduleCount; ++i) {
        std::uint64_t base{}, size{};
        std::uint16_t nameLength{};
        if (!readLe(in, base) || !readLe(in, size) || !readLe(in, nameLength) ||
            nameLength == 0 || nameLength > kMaxModuleBytes) {
            error = "invalid pointer-map module record"; return false;
        }
        if (base > std::numeric_limits<std::uintptr_t>::max() ||
            size > std::numeric_limits<std::size_t>::max()) {
            error = "module address/size does not fit this build"; return false;
        }
        std::string encoded(nameLength, '\0');
        in.read(encoded.data(), static_cast<std::streamsize>(encoded.size()));
        if (!in) { error = "truncated pointer-map module name"; return false; }
        PointerModule module;
        if (!decodeUtf8(encoded, module.name) || module.name.empty()) {
            error = "invalid UTF-8 module name in pointer map"; return false;
        }
        module.base = static_cast<std::uintptr_t>(base);
        module.size = static_cast<std::size_t>(size);
        parsed.modules.push_back(std::move(module));
    }

    for (std::uint64_t i = 0; i < entryCount; ++i) {
        std::uint64_t value{}, address{};
        if (!readLe(in, value) || !readLe(in, address)) {
            error = "truncated pointer-map entries"; return false;
        }
        if (value > std::numeric_limits<std::uintptr_t>::max() ||
            address > std::numeric_limits<std::uintptr_t>::max()) {
            error = "pointer-map entry does not fit this build"; return false;
        }
        parsed.entries.push_back(PointerEntry{
            static_cast<std::uintptr_t>(value), static_cast<std::uintptr_t>(address)});
    }

    char extra{};
    if (in.read(&extra, 1)) { error = "pointer-map file has unexpected trailing data"; return false; }
    if (!in.eof()) { error = "failed while validating pointer-map file"; return false; }

    // The on-disk contract is value-sorted, but normalize defensively so files
    // produced by future/other implementations still work.
    std::sort(parsed.entries.begin(), parsed.entries.end());
    parsed.entries.erase(std::unique(parsed.entries.begin(), parsed.entries.end(),
        [](const PointerEntry& a, const PointerEntry& b) {
            return a.value == b.value && a.address == b.address;
        }), parsed.entries.end());
    data = std::move(parsed);
    return true;
}

std::optional<std::uintptr_t> resolvePointerChainInMap(PointerMapData& map, const PointerChain& chain) {
    if (!map.entriesByAddress) {
        std::sort(map.entries.begin(), map.entries.end(), addressLess);
        map.entriesByAddress = true;
    }
    const auto* module = findModule(map, chain.moduleName);
    if (!module || chain.rootOffset >= module->size) return std::nullopt;
    std::uintptr_t address = module->base + chain.rootOffset;
    for (const auto offset : chain.offsets) {
        const auto pointer = pointerAtAddress(map, address);
        if (!pointer) return std::nullopt;
        const auto next = addSignedOffset(*pointer, offset);
        if (!next) return std::nullopt;
        address = *next;
    }
    return address;
}

std::vector<PointerChain> findCommonPointerChains(
    std::vector<PointerMapData>& maps,
    const PointerScanOptions& options,
    PointerMapCompareStats* stats)
{
    PointerMapCompareStats local{};
    local.maps = maps.size();
    for (const auto& map : maps) {
        local.peakEntriesLoaded += map.entries.size();
        if (!map.complete) ++local.partialMaps;
    }
    if (maps.empty()) {
        if (stats) *stats = local;
        return {};
    }
    const auto pointerSize = maps.front().pointerSize;
    local.pointerSize = pointerSize;
    for (const auto& map : maps) {
        if (map.pointerSize != pointerSize || (map.pointerSize != 4 && map.pointerSize != 8)) {
            if (stats) *stats = local;
            return {};
        }
    }

    std::sort(maps.front().entries.begin(), maps.front().entries.end());
    maps.front().entriesByAddress = false;
    bool truncated = false;
    auto chains = findPointerChains(
        maps.front().entries, maps.front().modules, maps.front().target, options, &truncated);
    local.initialChains = chains.size();
    local.chainsTruncated = truncated;

    for (std::size_t i = 1; i < maps.size() && !chains.empty(); ++i) {
        auto& map = maps[i];
        std::sort(map.entries.begin(), map.entries.end(), addressLess);
        map.entriesByAddress = true;
        chains.erase(std::remove_if(chains.begin(), chains.end(), [&](const PointerChain& chain) {
            const auto resolved = resolvePointerChainInMap(map, chain);
            return !resolved || *resolved != map.target;
        }), chains.end());
    }

    local.survivingChains = chains.size();
    if (stats) *stats = local;
    return chains;
}

std::vector<PointerChain> findCommonPointerChainsStreaming(
    const std::vector<std::string>& paths,
    const PointerScanOptions& options,
    PointerMapCompareStats* stats,
    std::string& error,
    std::size_t maxEntries,
    std::size_t maxModules)
{
    error.clear();
    PointerMapCompareStats local{};
    local.maps = paths.size();
    if (paths.empty()) {
        error = "no pointer-map files supplied";
        if (stats) *stats = local;
        return {};
    }

    PointerMapData map;
    if (!loadPointerMap(paths.front(), map, error, maxEntries, maxModules)) {
        if (stats) *stats = local;
        return {};
    }
    local.peakEntriesLoaded = map.entries.size();
    if (!map.complete) ++local.partialMaps;
    const auto pointerSize = map.pointerSize;
    local.pointerSize = pointerSize;

    bool truncated = false;
    auto chains = findPointerChains(map.entries, map.modules, map.target, options, &truncated);
    local.initialChains = chains.size();
    local.chainsTruncated = truncated;

    // Release the first map before loading the next one. The chain list only
    // stores module-relative roots/offsets and therefore does not depend on the
    // first map's backing entry vector after generation.
    map = PointerMapData{};

    for (std::size_t i = 1; i < paths.size(); ++i) {
        PointerMapData current;
        if (!loadPointerMap(paths[i], current, error, maxEntries, maxModules)) {
            if (stats) *stats = local;
            return {};
        }
        local.peakEntriesLoaded = (std::max)(local.peakEntriesLoaded, current.entries.size());
        if (!current.complete) ++local.partialMaps;
        if (current.pointerSize != pointerSize) {
            error = "pointer-map width mismatch between files";
            if (stats) *stats = local;
            return {};
        }

        if (!chains.empty()) {
            // A single address sort gives O(log n) pointer lookup for every chain
            // step in this map. The vector is discarded before the next map loads.
            std::sort(current.entries.begin(), current.entries.end(), addressLess);
            current.entriesByAddress = true;
            chains.erase(std::remove_if(chains.begin(), chains.end(), [&](const PointerChain& chain) {
                const auto resolved = resolvePointerChainInMap(current, chain);
                return !resolved || *resolved != current.target;
            }), chains.end());
        }
    }

    local.survivingChains = chains.size();
    if (stats) *stats = local;
    return chains;
}

} // namespace cw
