#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>
#include <utility>

namespace cw {

enum class ValueType {
    Byte,
    Int16,
    Int32,
    Int64,
    Float,
    Double
};

using Value = std::variant<std::uint8_t, std::int16_t, std::int32_t, std::int64_t, float, double>;

std::optional<ValueType> parseValueType(const std::string& text);
std::optional<Value> parseValue(ValueType type, const std::string& text);
std::string valueTypeName(ValueType type);
std::string formatValue(const Value& value);
std::size_t valueTypeSize(ValueType type);
bool valueMatchesType(ValueType type, const Value& value);
std::vector<ValueType> allValueTypes();
std::vector<std::pair<ValueType, Value>> parseAllCompatibleValues(const std::string& text);

} // namespace cw
