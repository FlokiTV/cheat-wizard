#pragma once

#include "cw/PointerTypes.hpp"
#include "cw/Value.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace cw {

struct PointerProfileData {
    std::size_t pointerSize{};
    ValueType type{ValueType::Int32};
    std::string processName;
    std::vector<PointerChain> chains;
};

bool savePointerProfile(
    const std::string& path,
    const PointerProfileData& profile,
    std::string& error);

bool loadPointerProfile(
    const std::string& path,
    PointerProfileData& profile,
    std::string& error,
    std::size_t maxChains = 100'000,
    std::size_t maxDepth = 64);

} // namespace cw
