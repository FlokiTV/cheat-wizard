#include "cw/AobPattern.hpp"
#include "cw/AobScanner.hpp"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

namespace {
int failures = 0;
void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void put(std::size_t offset, std::initializer_list<std::uint8_t> bytes) {
    std::size_t i = 0;
    for (auto b : bytes) mockwin::memory[offset + i++] = static_cast<std::byte>(b);
}

bool contains(const cw::AobScanner& scanner, std::uintptr_t address) {
    for (auto value : scanner.results()) if (value == address) return true;
    return false;
}
} // namespace

int main() {
    using namespace cw;

    std::string error;
    auto pattern = parseAobPattern("89 83 ?? ?? A? ?F", error);
    expect(pattern.has_value(), "parser accepts byte, wildcard and nibble wildcard tokens");
    expect(pattern && formatAobPattern(*pattern) == "89 83 ?? ?? A? ?F", "formatter round-trips AOB pattern");
    expect(!parseAobPattern("89 GG", error).has_value(), "parser rejects invalid hex token");

    HANDLE fakeProcess = reinterpret_cast<HANDLE>(1);
    AobScanner scanner;
    scanner.setProcess(fakeProcess);

    mockwin::reset(4096);
    constexpr std::size_t a = 0x120;
    constexpr std::size_t b = 0x220;
    put(a, {0x89,0x83,0x11,0x22,0xAB,0x3F});
    put(b, {0x89,0x83,0x99,0x88,0xA1,0xEF});
    pattern = parseAobPattern("89 83 ?? ?? A? ?F", error);
    auto stats = scanner.scan(*pattern);
    expect(stats.resultCount == 2, "AOB scanner finds two wildcard matches");
    expect(contains(scanner, mockwin::base + a), "AOB scanner contains match A");
    expect(contains(scanner, mockwin::base + b), "AOB scanner contains match B");

    mockwin::reset(4096);
    put(0x40, {0xDE,0xAD,0xBE,0xEF});
    pattern = parseAobPattern("DE AD BE EF", error);
    cw::ScanOptions range{};
    range.minAddress = mockwin::base + 0x100;
    range.maxAddress = mockwin::base + 0x3FF;
    scanner.setOptions(range);
    stats = scanner.scan(*pattern);
    expect(stats.resultCount == 0, "AOB scanner honors address range");

    scanner.setOptions(ScanOptions{});
    mockwin::protection = PAGE_READWRITE;
    scanner.setExecutableOnly(true);
    stats = scanner.scan(*pattern);
    expect(stats.resultCount == 0, "executable-only AOB scan excludes RW region");
    mockwin::protection = PAGE_EXECUTE_READ;
    stats = scanner.scan(*pattern);
    expect(stats.resultCount == 1, "executable-only AOB scan accepts executable region");

    // Pattern crossing the scanner's internal 4 MiB chunk boundary.
    constexpr std::size_t fourMiB = 4u * 1024u * 1024u;
    mockwin::reset(fourMiB + 64);
    scanner.setExecutableOnly(false);
    constexpr std::size_t crossing = fourMiB - 2;
    put(crossing, {0x11,0x22,0x33,0x44,0x55,0x66});
    pattern = parseAobPattern("11 22 33 44 55 66", error);
    stats = scanner.scan(*pattern);
    expect(contains(scanner, mockwin::base + crossing), "AOB scan finds pattern crossing read-chunk boundary");

    if (failures == 0) {
        std::cout << "Mock AOB scanner tests passed\n";
        return 0;
    }
    std::cerr << failures << " failure(s)\n";
    return 1;
}
