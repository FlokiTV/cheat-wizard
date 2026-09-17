#pragma once

#include "cw/PointerTypes.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace cw {

struct PointerFileData {
    std::size_t pointerSize{};
    std::vector<PointerChain> chains;
};

bool savePointerChains(
    const std::string& path,
    std::size_t pointerSize,
    const std::vector<PointerChain>& chains,
    std::string& error);

bool loadPointerChains(
    const std::string& path,
    PointerFileData& data,
    std::string& error,
    std::size_t maxChains = 100'000,
    std::size_t maxDepth = 64);

} // namespace cw
