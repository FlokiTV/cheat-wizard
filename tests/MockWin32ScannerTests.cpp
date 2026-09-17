#include "cw/MemoryScanner.hpp"
#include "cw/ScanOptions.hpp"
#include "cw/ScanTypes.hpp"
#include "cw/Value.hpp"

#include <Windows.h>

#include <cstdint>
#include <iostream>
#include <string>

namespace {
int failures = 0;

void expect(bool condition, const std::string& name) {
    if (condition) std::cout << "[PASS] " << name << '\n';
    else {
        std::cout << "[FAIL] " << name << '\n';
        ++failures;
    }
}

bool contains(const cw::MemoryScanner& scanner, std::uintptr_t address) {
    for (const auto& result : scanner.results()) {
        if (result.address == address) return true;
    }
    return false;
}

bool containsTyped(const cw::MemoryScanner& scanner, std::uintptr_t address, cw::ValueType type) {
    for (const auto& result : scanner.results()) {
        if (result.address == address && result.type == type) return true;
    }
    return false;
}
} // namespace

int main() {
    using namespace cw;
    HANDLE fakeProcess = reinterpret_cast<HANDLE>(1);
    MemoryScanner scanner;
    scanner.setProcess(fakeProcess);

    // Exact -> Changed -> Increased -> Exact on a controlled address.
    mockwin::reset();
    constexpr std::size_t a = 0x100;
    constexpr std::size_t b = 0x200;
    mockwin::write<std::int32_t>(a, 777);
    mockwin::write<std::int32_t>(b, 777);
    auto stats = scanner.firstScan(ValueType::Int32, Value{std::int32_t{777}});
    expect(stats.resultCount == 2, "exact scan finds two int32 values");
    expect(contains(scanner, mockwin::base + a), "exact scan contains controlled address A");

    mockwin::write<std::int32_t>(a, 778);
    stats = scanner.nextScan(ScanMode::Changed);
    expect(stats.resultCount == 1, "changed scan retains only modified result");
    expect(contains(scanner, mockwin::base + a), "changed scan retains A");

    mockwin::write<std::int32_t>(a, 900);
    stats = scanner.nextScan(ScanMode::Increased);
    expect(stats.resultCount == 1, "increased scan retains increased result");

    stats = scanner.nextScan(ScanMode::Exact, Value{std::int32_t{900}});
    expect(stats.resultCount == 1, "exact next scan retains expected value");


    // Mixed-type exact scan: one memory pass can retain candidates with independent types.
    mockwin::reset(512);
    scanner.setOptions(ScanOptions{});
    constexpr std::size_t mixedI32 = 0x40;
    constexpr std::size_t mixedF32 = 0x80;
    constexpr std::size_t mixedI16 = 0xC0;
    mockwin::write<std::int32_t>(mixedI32, 100);
    mockwin::write<float>(mixedF32, 100.0f);
    mockwin::write<std::int16_t>(mixedI16, 100);
    stats = scanner.firstScanAllExact("100");
    expect(scanner.mixedScanActive(), "scan all enters mixed scan state");
    expect(containsTyped(scanner, mockwin::base + mixedI32, ValueType::Int32),
           "scan all finds int32 representation");
    expect(containsTyped(scanner, mockwin::base + mixedF32, ValueType::Float),
           "scan all finds float representation");
    expect(containsTyped(scanner, mockwin::base + mixedI16, ValueType::Int16),
           "scan all finds int16 representation");

    mockwin::write<std::int32_t>(mixedI32, 83);
    mockwin::write<float>(mixedF32, 83.0f);
    mockwin::write<std::int16_t>(mixedI16, 83);
    stats = scanner.nextScanMixed(ScanMode::Exact, std::string{"83"});
    expect(containsTyped(scanner, mockwin::base + mixedI32, ValueType::Int32),
           "mixed next exact preserves int32 type");
    expect(containsTyped(scanner, mockwin::base + mixedF32, ValueType::Float),
           "mixed next exact preserves float type");
    expect(containsTyped(scanner, mockwin::base + mixedI16, ValueType::Int16),
           "mixed next exact preserves int16 type");

    mockwin::write<float>(mixedF32, 90.0f);
    stats = scanner.nextScanMixed(ScanMode::Changed);
    expect(containsTyped(scanner, mockwin::base + mixedF32, ValueType::Float),
           "mixed changed compares candidates using their own type");

    // Mixed Unknown Initial Value: one raw snapshot is later materialized into typed candidates.
    mockwin::reset(512);
    scanner.setOptions(ScanOptions{});
    constexpr std::size_t unknownAllI32 = 0x40;
    constexpr std::size_t unknownAllF32 = 0x80;
    constexpr std::size_t unknownAllI16 = 0xC0;
    mockwin::write<std::int32_t>(unknownAllI32, 100);
    mockwin::write<float>(unknownAllF32, 100.0f);
    mockwin::write<std::int16_t>(unknownAllI16, 100);
    stats = scanner.firstScanAllUnknown();
    expect(scanner.mixedScanActive(), "scan all unknown enters mixed scan state");
    expect(scanner.unknownSnapshotActive(), "scan all unknown keeps a raw snapshot");
    expect(stats.resultCount > mockwin::memory.size(),
           "scan all unknown counts candidates across multiple numeric types");

    mockwin::write<std::int32_t>(unknownAllI32, 83);
    mockwin::write<float>(unknownAllF32, 83.0f);
    mockwin::write<std::int16_t>(unknownAllI16, 83);
    stats = scanner.nextScanMixed(ScanMode::Exact, std::string{"83"});
    expect(!scanner.unknownSnapshotActive(), "first mixed-unknown next scan materializes results");
    expect(containsTyped(scanner, mockwin::base + unknownAllI32, ValueType::Int32),
           "scan all unknown + exact finds int32 representation");
    expect(containsTyped(scanner, mockwin::base + unknownAllF32, ValueType::Float),
           "scan all unknown + exact finds float representation");
    expect(containsTyped(scanner, mockwin::base + unknownAllI16, ValueType::Int16),
           "scan all unknown + exact finds int16 representation");

    mockwin::write<std::int32_t>(unknownAllI32, 61);
    mockwin::write<float>(unknownAllF32, 61.0f);
    mockwin::write<std::int16_t>(unknownAllI16, 61);
    stats = scanner.nextScanMixed(ScanMode::Exact, std::string{"61"});
    expect(containsTyped(scanner, mockwin::base + unknownAllI32, ValueType::Int32),
           "materialized all-unknown results support later mixed next scans");

    // Unknown snapshot -> Decreased should materialize only the changed typed slot.
    mockwin::reset();
    scanner.setOptions(ScanOptions{});
    constexpr std::size_t trackedValue = 0x400;
    mockwin::write<std::int32_t>(trackedValue, 100);
    stats = scanner.firstScanUnknown(ValueType::Int32);
    expect(scanner.unknownSnapshotActive(), "unknown scan keeps snapshot state");
    expect(stats.resultCount == mockwin::memory.size() / sizeof(std::int32_t),
           "unknown scan candidate count matches aligned slots");

    mockwin::write<std::int32_t>(trackedValue, 80);
    stats = scanner.nextScan(ScanMode::Decreased);
    expect(!scanner.unknownSnapshotActive(), "first unknown next scan materializes results");
    expect(stats.resultCount == 1, "unknown+decreased isolates one changed value");
    expect(contains(scanner, mockwin::base + trackedValue), "unknown+decreased finds tracked address");

    // Page batching: thousands of results should require approximately one read per page,
    // not one read per result.
    mockwin::reset(8192);
    scanner.setOptions(ScanOptions{});
    for (std::size_t offset = 0; offset < mockwin::memory.size(); offset += sizeof(std::int32_t)) {
        mockwin::write<std::int32_t>(offset, 42);
    }
    stats = scanner.firstScan(ValueType::Int32, Value{std::int32_t{42}});
    expect(stats.resultCount == 2048, "batching fixture creates 2048 results");
    mockwin::resetCounters();
    stats = scanner.nextScan(ScanMode::Exact, Value{std::int32_t{42}});
    expect(stats.resultCount == 2048, "batched next scan retains all results");
    expect(mockwin::readCalls <= 2, "batched next scan uses one range read per page");

    // Smaller-than / bigger-than value comparisons on a tiny controlled candidate set.
    mockwin::reset(16);
    scanner.setOptions(ScanOptions{});
    for (std::size_t offset = 0; offset < 16; offset += sizeof(std::int32_t)) {
        mockwin::write<std::int32_t>(offset, 42);
    }
    scanner.firstScan(ValueType::Int32, Value{std::int32_t{42}});
    mockwin::write<std::int32_t>(0, 10);
    mockwin::write<std::int32_t>(4, 30);
    stats = scanner.nextScan(ScanMode::BiggerThan, Value{std::int32_t{20}});
    expect(stats.resultCount == 3, "bigger-than keeps 30 and two 42 values");
    stats = scanner.nextScan(ScanMode::SmallerThan, Value{std::int32_t{40}});
    expect(stats.resultCount == 1, "smaller-than narrows to the 30 value");

    // Alignment mode: natural ignores an unaligned value; byte mode finds it.
    mockwin::reset(64);
    constexpr std::size_t unaligned = 3;
    mockwin::write<std::int32_t>(unaligned, 0x12345678);
    scanner.setOptions(ScanOptions{});
    stats = scanner.firstScan(ValueType::Int32, Value{std::int32_t{0x12345678}});
    expect(!contains(scanner, mockwin::base + unaligned), "natural alignment ignores unaligned int32");

    ScanOptions byteAligned{};
    byteAligned.alignment = AlignmentMode::Byte;
    scanner.setOptions(byteAligned);
    stats = scanner.firstScan(ValueType::Int32, Value{std::int32_t{0x12345678}});
    expect(contains(scanner, mockwin::base + unaligned), "byte alignment finds unaligned int32");

    // Byte-aligned scans must also detect a value that crosses the internal 4 MiB read boundary.
    constexpr std::size_t fourMiB = 4u * 1024u * 1024u;
    mockwin::reset(fourMiB + 32);
    constexpr std::size_t crossing = fourMiB - 2;
    mockwin::write<std::int32_t>(crossing, 0x11223344);
    scanner.setOptions(byteAligned);
    stats = scanner.firstScan(ValueType::Int32, Value{std::int32_t{0x11223344}});
    expect(contains(scanner, mockwin::base + crossing), "byte scan finds value crossing read-chunk boundary");

    stats = scanner.firstScanUnknown(ValueType::Int32);
    mockwin::write<std::int32_t>(crossing, 0x10203040);
    stats = scanner.nextScan(ScanMode::Changed);
    expect(contains(scanner, mockwin::base + crossing), "unknown byte scan preserves cross-boundary candidate");

    // Address range limits candidates before reading/scanning them.
    mockwin::reset(1024);
    constexpr std::size_t inRange = 0x100;
    constexpr std::size_t outRange = 0x300;
    mockwin::write<std::int32_t>(inRange, 555);
    mockwin::write<std::int32_t>(outRange, 555);
    ScanOptions ranged{};
    ranged.minAddress = mockwin::base + 0x80;
    ranged.maxAddress = mockwin::base + 0x1FF;
    scanner.setOptions(ranged);
    stats = scanner.firstScan(ValueType::Int32, Value{std::int32_t{555}});
    expect(stats.resultCount == 1 && contains(scanner, mockwin::base + inRange),
           "address range excludes matching value outside range");

    // Writable/private filters use VirtualQueryEx metadata.
    mockwin::reset(64);
    mockwin::write<std::int32_t>(0, 7777);
    mockwin::protection = PAGE_READONLY;
    ScanOptions writable{};
    writable.writableOnly = true;
    scanner.setOptions(writable);
    stats = scanner.firstScan(ValueType::Int32, Value{std::int32_t{7777}});
    expect(stats.resultCount == 0, "writable-only filter excludes read-only region");

    mockwin::reset(64);
    mockwin::write<std::int32_t>(0, 7777);
    mockwin::regionType = MEM_MAPPED;
    ScanOptions privateOnly{};
    privateOnly.privateOnly = true;
    scanner.setOptions(privateOnly);
    stats = scanner.firstScan(ValueType::Int32, Value{std::int32_t{7777}});
    expect(stats.resultCount == 0, "private-only filter excludes mapped region");

    // Float tolerance makes exact/changed scans robust to small representation/noise changes.
    mockwin::reset(64);
    constexpr std::size_t floatSlot = 0x10;
    mockwin::write<float>(floatSlot, 10.005f);
    ScanOptions tolerant{};
    tolerant.floatTolerance = 0.01;
    scanner.setOptions(tolerant);
    stats = scanner.firstScan(ValueType::Float, Value{10.0f});
    expect(contains(scanner, mockwin::base + floatSlot), "float exact scan honors tolerance");
    mockwin::write<float>(floatSlot, 10.009f);
    stats = scanner.nextScan(ScanMode::Unchanged);
    expect(contains(scanner, mockwin::base + floatSlot), "float unchanged treats delta inside tolerance as same");
    mockwin::write<float>(floatSlot, 10.05f);
    stats = scanner.nextScan(ScanMode::Changed);
    expect(contains(scanner, mockwin::base + floatSlot), "float changed detects delta beyond tolerance");

    // Materialized session restoration reconstructs the Next Scan baseline without rescanning memory.
    mockwin::reset(128);
    constexpr std::size_t restoredI32 = 0x20;
    constexpr std::size_t restoredFloat = 0x40;
    mockwin::write<std::int32_t>(restoredI32, 83);
    mockwin::write<float>(restoredFloat, 12.5f);
    ScanOptions restoredOptions{};
    restoredOptions.alignment = AlignmentMode::Byte;
    restoredOptions.floatTolerance = 0.01;
    std::vector<ScanResult> restoredResults{
        ScanResult{mockwin::base + restoredI32, packScanValue<std::int32_t>(100), ValueType::Int32},
        ScanResult{mockwin::base + restoredFloat, packScanValue<float>(12.0f), ValueType::Float},
    };
    expect(scanner.restoreMaterializedScan(
               ValueType::Int32, true, restoredOptions, std::move(restoredResults)),
           "restore materialized mixed scan state");
    expect(scanner.hasScan() && scanner.mixedScanActive() && !scanner.unknownSnapshotActive() &&
           scanner.results().size() == 2,
           "restored scan exposes materialized results");
    stats = scanner.nextScanMixed(ScanMode::Changed);
    expect(stats.resultCount == 2, "restored previous values participate in next changed scan");

    // Cancellation can be requested from a progress callback and returns a marked partial scan.
    mockwin::reset(8 * 1024 * 1024);
    for (std::size_t offset = 0; offset < mockwin::memory.size(); offset += sizeof(std::int32_t)) {
        mockwin::write<std::int32_t>(offset, 99);
    }
    scanner.setOptions(ScanOptions{});
    bool callbackCalled = false;
    scanner.setProgressCallback([&](const ScanProgress&) {
        callbackCalled = true;
        scanner.requestCancel();
    });
    stats = scanner.firstScan(ValueType::Int32, Value{std::int32_t{99}});
    expect(callbackCalled, "scan progress callback is invoked");
    expect(stats.cancelled, "scan cancellation is reported");
    expect(stats.resultCount > 0 && stats.resultCount < mockwin::memory.size() / sizeof(std::int32_t),
           "cancelled scan keeps only processed partial results");
    scanner.setProgressCallback({});

    if (failures == 0) {
        std::cout << "\nALL MOCK WIN32 SCANNER TESTS PASSED\n";
        return 0;
    }
    std::cout << "\n" << failures << " TEST(S) FAILED\n";
    return 1;
}
