#include "cw/Value.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <type_traits>

namespace cw {
namespace {

template <typename T>
std::optional<T> parseInteger(const std::string& text) {
    static_assert(std::is_integral_v<T>);

    if constexpr (std::is_same_v<T, std::uint8_t>) {
        unsigned int temp{};
        const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), temp, 10);
        if (ec != std::errc{} || ptr != text.data() + text.size() || temp > 255u) {
            return std::nullopt;
        }
        return static_cast<std::uint8_t>(temp);
    } else {
        T value{};
        const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value, 10);
        if (ec != std::errc{} || ptr != text.data() + text.size()) {
            return std::nullopt;
        }
        return value;
    }
}

template <typename T>
std::optional<T> parseFloating(const std::string& text) {
    static_assert(std::is_floating_point_v<T>);
    try {
        std::size_t consumed = 0;
        const long double parsed = std::stold(text, &consumed);
        if (consumed != text.size() || !std::isfinite(parsed)) {
            return std::nullopt;
        }
        if (parsed < -static_cast<long double>(std::numeric_limits<T>::max()) ||
            parsed > static_cast<long double>(std::numeric_limits<T>::max())) {
            return std::nullopt;
        }
        return static_cast<T>(parsed);
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace

std::optional<ValueType> parseValueType(const std::string& text) {
    std::string lowered = text;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (lowered == "byte" || lowered == "u8" || lowered == "uint8") return ValueType::Byte;
    if (lowered == "2" || lowered == "int16" || lowered == "i16") return ValueType::Int16;
    if (lowered == "4" || lowered == "int32" || lowered == "i32") return ValueType::Int32;
    if (lowered == "8" || lowered == "int64" || lowered == "i64") return ValueType::Int64;
    if (lowered == "float" || lowered == "f32") return ValueType::Float;
    if (lowered == "double" || lowered == "f64") return ValueType::Double;
    return std::nullopt;
}

std::optional<Value> parseValue(ValueType type, const std::string& text) {
    switch (type) {
        case ValueType::Byte: {
            if (auto v = parseInteger<std::uint8_t>(text)) return Value{*v};
            break;
        }
        case ValueType::Int16: {
            if (auto v = parseInteger<std::int16_t>(text)) return Value{*v};
            break;
        }
        case ValueType::Int32: {
            if (auto v = parseInteger<std::int32_t>(text)) return Value{*v};
            break;
        }
        case ValueType::Int64: {
            if (auto v = parseInteger<std::int64_t>(text)) return Value{*v};
            break;
        }
        case ValueType::Float: {
            if (auto v = parseFloating<float>(text)) return Value{*v};
            break;
        }
        case ValueType::Double: {
            if (auto v = parseFloating<double>(text)) return Value{*v};
            break;
        }
    }
    return std::nullopt;
}

std::string valueTypeName(ValueType type) {
    switch (type) {
        case ValueType::Byte: return "Byte";
        case ValueType::Int16: return "2 Bytes (int16)";
        case ValueType::Int32: return "4 Bytes (int32)";
        case ValueType::Int64: return "8 Bytes (int64)";
        case ValueType::Float: return "Float";
        case ValueType::Double: return "Double";
    }
    return "Unknown";
}

std::string formatValue(const Value& value) {
    return std::visit([](const auto& v) -> std::string {
        using T = std::decay_t<decltype(v)>;
        std::ostringstream out;
        if constexpr (std::is_same_v<T, std::uint8_t>) {
            out << static_cast<unsigned int>(v);
        } else if constexpr (std::is_floating_point_v<T>) {
            out << std::setprecision(std::numeric_limits<T>::max_digits10) << v;
        } else {
            out << v;
        }
        return out.str();
    }, value);
}

std::size_t valueTypeSize(ValueType type) {
    switch (type) {
        case ValueType::Byte: return sizeof(std::uint8_t);
        case ValueType::Int16: return sizeof(std::int16_t);
        case ValueType::Int32: return sizeof(std::int32_t);
        case ValueType::Int64: return sizeof(std::int64_t);
        case ValueType::Float: return sizeof(float);
        case ValueType::Double: return sizeof(double);
    }
    return 0;
}

bool valueMatchesType(ValueType type, const Value& value) {
    return std::visit([&](const auto& typedValue) {
        using T = std::decay_t<decltype(typedValue)>;
        return (type == ValueType::Byte && std::is_same_v<T, std::uint8_t>) ||
               (type == ValueType::Int16 && std::is_same_v<T, std::int16_t>) ||
               (type == ValueType::Int32 && std::is_same_v<T, std::int32_t>) ||
               (type == ValueType::Int64 && std::is_same_v<T, std::int64_t>) ||
               (type == ValueType::Float && std::is_same_v<T, float>) ||
               (type == ValueType::Double && std::is_same_v<T, double>);
    }, value);
}

std::vector<ValueType> allValueTypes() {
    return {
        ValueType::Byte, ValueType::Int16, ValueType::Int32,
        ValueType::Int64, ValueType::Float, ValueType::Double
    };
}

std::vector<std::pair<ValueType, Value>> parseAllCompatibleValues(const std::string& text) {
    std::vector<std::pair<ValueType, Value>> out;
    for (const auto type : allValueTypes()) {
        if (auto value = parseValue(type, text)) {
            out.emplace_back(type, *value);
        }
    }
    return out;
}

} // namespace cw
