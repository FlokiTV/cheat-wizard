#pragma once

#include "cw/Value.hpp"

#include <Windows.h>

#include <cstdint>

namespace cw {

struct WriteResult {
    bool ok{};
    SIZE_T bytesWritten{};
    DWORD error{};
};

WriteResult writeValue(HANDLE process, std::uintptr_t address, const Value& value);

} // namespace cw
