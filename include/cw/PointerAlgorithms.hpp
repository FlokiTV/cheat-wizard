#pragma once

#include "cw/PointerTypes.hpp"

#include <cstdint>
#include <vector>

namespace cw {

// Input index must be sorted by PointerEntry::operator<.
std::vector<PointerChain> findPointerChains(
    const std::vector<PointerEntry>& sortedIndex,
    const std::vector<PointerModule>& modules,
    std::uintptr_t target,
    const PointerScanOptions& options,
    bool* truncated = nullptr);

} // namespace cw
