#pragma once

#include "cw/PointerTypes.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cw {

struct PointerMapData {
    std::size_t pointerSize{};
    std::uintptr_t target{};
    bool complete{true};
    std::vector<PointerModule> modules;
    std::vector<PointerEntry> entries; // persisted sorted by pointer value
    bool entriesByAddress{false}; // in-memory lookup state; not persisted
};

struct PointerMapCompareStats {
    std::size_t pointerSize{};
    std::size_t maps{};
    std::size_t initialChains{};
    std::size_t survivingChains{};
    std::size_t peakEntriesLoaded{};
    std::size_t partialMaps{};
    bool chainsTruncated{};
};

bool savePointerMap(
    const std::string& path,
    std::size_t pointerSize,
    std::uintptr_t target,
    const std::vector<PointerModule>& modules,
    const std::vector<PointerEntry>& entries,
    bool complete,
    std::string& error);

bool loadPointerMap(
    const std::string& path,
    PointerMapData& data,
    std::string& error,
    std::size_t maxEntries = 16'000'000,
    std::size_t maxModules = 4096);

// Finds chains in the first map, then keeps only chains that resolve to each
// subsequent map's recorded target using the same module-relative root and
// offsets. The input maps may be reordered internally for efficient lookup.
std::vector<PointerChain> findCommonPointerChains(
    std::vector<PointerMapData>& maps,
    const PointerScanOptions& options,
    PointerMapCompareStats* stats = nullptr);

std::optional<std::uintptr_t> resolvePointerChainInMap(
    PointerMapData& map,
    const PointerChain& chain);

// Compares pointer-map files while keeping at most one map's entry vector in
// memory at a time. This is useful when several multi-million-entry maps would
// otherwise multiply RAM usage. Each individual map must still fit within
// maxEntries. On success, error is cleared even when no chains survive.
std::vector<PointerChain> findCommonPointerChainsStreaming(
    const std::vector<std::string>& paths,
    const PointerScanOptions& options,
    PointerMapCompareStats* stats,
    std::string& error,
    std::size_t maxEntries = 16'000'000,
    std::size_t maxModules = 4096);

} // namespace cw
