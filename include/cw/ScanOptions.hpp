#pragma once

#include <cstdint>
#include <limits>

namespace cw {

enum class AlignmentMode {
    Natural,
    Byte
};

struct ScanOptions {
    AlignmentMode alignment{AlignmentMode::Natural};
    bool writableOnly{false};
    bool privateOnly{false};
    std::uintptr_t minAddress{0};
    std::uintptr_t maxAddress{(std::numeric_limits<std::uintptr_t>::max)()};
    double floatTolerance{0.0};
};

} // namespace cw
