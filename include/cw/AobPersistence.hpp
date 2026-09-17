#pragma once

#include "cw/AobPattern.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace cw {

enum class AobSearchScope : std::uint32_t {
    Memory = 0,
    Executable = 1,
    Module = 2,
    ModuleExecutable = 3,
};

struct AobSavedResult {
    bool moduleRelative{};
    std::string moduleName;
    std::uintptr_t value{}; // module offset when moduleRelative, otherwise absolute address
};

struct AobSessionData {
    AobPattern pattern;
    AobSearchScope scope{AobSearchScope::Memory};
    std::string moduleName; // only used by module-restricted scopes
    std::vector<AobSavedResult> results;
};

bool saveAobSession(const std::string& path, const AobSessionData& data, std::string& error);
bool loadAobSession(
    const std::string& path,
    AobSessionData& data,
    std::string& error,
    std::size_t maxResults = 1'000'000,
    std::size_t maxNameBytes = 4096);

} // namespace cw
