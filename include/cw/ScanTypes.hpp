#pragma once

#include "cw/Value.hpp"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <optional>
#include <type_traits>

namespace cw {

enum class ScanMode {
    Exact,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    BiggerThan,
    SmallerThan
};

struct ScanResult {
    std::uintptr_t address{};
    std::uint64_t previousBits{};
    ValueType type{ValueType::Int32};
};

template <typename T>
std::uint64_t packScanValue(T value) {
    static_assert(std::is_trivially_copyable_v<T>);
    static_assert(sizeof(T) <= sizeof(std::uint64_t));
    std::uint64_t bits{};
    std::memcpy(&bits, &value, sizeof(T));
    return bits;
}

template <typename T>
T unpackScanValue(std::uint64_t bits) {
    static_assert(std::is_trivially_copyable_v<T>);
    static_assert(sizeof(T) <= sizeof(std::uint64_t));
    T value{};
    std::memcpy(&value, &bits, sizeof(T));
    return value;
}

template <typename T>
bool scanEqual(T a, T b, double tolerance) {
    if constexpr (std::is_floating_point_v<T>) {
        if (tolerance > 0.0) {
            return std::fabs(static_cast<double>(a) - static_cast<double>(b)) <= tolerance;
        }
    }
    return a == b;
}

template <typename T>
bool scanMatches(
    ScanMode mode,
    T current,
    T previous,
    const std::optional<T>& wanted,
    double tolerance = 0.0)
{
    const auto equal = [&](T a, T b) { return scanEqual(a, b, tolerance); };
    switch (mode) {
        case ScanMode::Exact:
            return wanted && equal(current, *wanted);
        case ScanMode::Changed:
            return !equal(current, previous);
        case ScanMode::Unchanged:
            return equal(current, previous);
        case ScanMode::Increased:
            if constexpr (std::is_floating_point_v<T>) {
                return tolerance > 0.0
                    ? static_cast<double>(current) > static_cast<double>(previous) + tolerance
                    : current > previous;
            } else {
                return current > previous;
            }
        case ScanMode::Decreased:
            if constexpr (std::is_floating_point_v<T>) {
                return tolerance > 0.0
                    ? static_cast<double>(current) < static_cast<double>(previous) - tolerance
                    : current < previous;
            } else {
                return current < previous;
            }
        case ScanMode::BiggerThan:
            if (!wanted) return false;
            if constexpr (std::is_floating_point_v<T>) {
                return tolerance > 0.0
                    ? static_cast<double>(current) > static_cast<double>(*wanted) + tolerance
                    : current > *wanted;
            } else {
                return current > *wanted;
            }
        case ScanMode::SmallerThan:
            if (!wanted) return false;
            if constexpr (std::is_floating_point_v<T>) {
                return tolerance > 0.0
                    ? static_cast<double>(current) < static_cast<double>(*wanted) - tolerance
                    : current < *wanted;
            } else {
                return current < *wanted;
            }
    }
    return false;
}

inline bool scanModeNeedsValue(ScanMode mode) {
    return mode == ScanMode::Exact ||
           mode == ScanMode::BiggerThan ||
           mode == ScanMode::SmallerThan;
}

} // namespace cw
