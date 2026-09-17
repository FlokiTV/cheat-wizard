#pragma once

#include "cw/ScanOptions.hpp"
#include "cw/ScanTypes.hpp"
#include "cw/Value.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace cw {

struct ScanSessionData {
    std::uint64_t sourcePid{};
    bool mixed{};
    ValueType primaryType{ValueType::Int32};
    ScanOptions options{};
    std::vector<ScanResult> results;
};

bool saveScanSession(
    const std::string& path,
    const ScanSessionData& data,
    std::string& error);

bool loadScanSession(
    const std::string& path,
    ScanSessionData& data,
    std::string& error,
    std::size_t maxResults = 5'000'000);

} // namespace cw
