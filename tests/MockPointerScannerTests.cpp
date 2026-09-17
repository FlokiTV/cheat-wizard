#include "cw/PointerScanner.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

namespace {
int failures = 0;

void expect(bool condition, const std::string& name) {
    if (condition) {
        std::cout << "[PASS] " << name << '\n';
    } else {
        std::cout << "[FAIL] " << name << '\n';
        ++failures;
    }
}

template <typename T>
void writeAt(std::uintptr_t address, T value) {
    const auto offset = static_cast<std::size_t>(address - mockwin::base);
    std::memcpy(mockwin::memory.data() + offset, &value, sizeof(value));
}
} // namespace

int main() {
    using namespace cw;

    mockwin::reset(128 * 1024);
    const std::uintptr_t rootSlot = mockwin::base + 0x100;
    const std::uintptr_t midSlot = mockwin::base + 0x2020;
    const std::uintptr_t target = mockwin::base + 0x3030;

    // [module+0x100] = base+0x2000; +0x20 => midSlot
    // [midSlot]      = base+0x3000; +0x30 => target
    writeAt<std::uint64_t>(rootSlot, mockwin::base + 0x2000);
    writeAt<std::uint64_t>(midSlot, mockwin::base + 0x3000);

    PointerScanner scanner;
    std::vector<ModuleInfo> modules{
        ModuleInfo{mockwin::base, 0x1000, L"game.exe", L"C:\\game.exe"},
    };
    scanner.setProcess(reinterpret_cast<HANDLE>(1), 8, modules);

    PointerScanOptions options;
    options.maxDepth = 3;
    options.maxOffset = 0x40;
    options.maxChains = 100;
    options.maxIndexEntries = 10000;

    const auto captureStats = scanner.captureIndex(options);
    expect(captureStats.indexEntries >= 2, "index-only capture collects pointer entries");
    expect(scanner.chains().empty(), "index-only capture does not generate chains");

    const auto stats = scanner.scan(target, options);
    expect(stats.pointerSize == 8, "scanner reports 64-bit pointer width");
    expect(scanner.chainPointerSize() == 8, "scanner tags generated chains with target pointer width");
    expect(stats.indexEntries >= 2, "pointer index contains fixture pointers");
    expect(!scanner.chains().empty(), "pointer scanner finds at least one chain");

    const auto it = std::find_if(scanner.chains().begin(), scanner.chains().end(), [](const PointerChain& chain) {
        return chain.moduleName == L"game.exe" &&
               chain.rootOffset == 0x100 &&
               chain.offsets == std::vector<std::int64_t>{0x20, 0x30};
    });
    expect(it != scanner.chains().end(), "scanner finds expected module-rooted chain");

    if (it != scanner.chains().end()) {
        const auto resolved = scanner.resolve(*it);
        expect(resolved && *resolved == target, "pointer chain resolves to target");
    }

    const auto before = scanner.chains().size();
    const auto kept = scanner.rescan(target);
    expect(kept == before, "rescan keeps chains that still resolve to target");

    writeAt<std::uint64_t>(midSlot, mockwin::base + 0x3100);
    const auto dropped = scanner.rescan(target);
    expect(dropped < kept, "rescan drops chain after pointer changes");


    // Loaded chains keep source pointer width metadata and refuse incompatible resolve.
    scanner.setProcess(reinterpret_cast<HANDLE>(1), 8, modules);
    scanner.setChains({PointerChain{L"game.exe", 0x100, {0x20, 0x30}}}, 4);
    expect(scanner.chainPointerSize() == 4, "loaded chains preserve source pointer width");
    expect(!scanner.resolve(0).has_value(), "resolve rejects pointer-width mismatch");

    // 32-bit target pointer width is interpreted independently of host width.
    mockwin::reset(128 * 1024);
    writeAt<std::uint32_t>(rootSlot, static_cast<std::uint32_t>(mockwin::base + 0x2000));
    writeAt<std::uint32_t>(midSlot, static_cast<std::uint32_t>(mockwin::base + 0x3000));
    scanner.clearChains();
    scanner.setProcess(reinterpret_cast<HANDLE>(1), 4, modules);
    const auto stats32 = scanner.scan(target, options);
    expect(stats32.pointerSize == 4, "scanner supports 32-bit target pointers");
    expect(std::any_of(scanner.chains().begin(), scanner.chains().end(), [](const PointerChain& chain) {
        return chain.rootOffset == 0x100 && chain.offsets == std::vector<std::int64_t>{0x20, 0x30};
    }), "32-bit pointer scan finds expected chain");

    // Pointer-index source filters and configurable alignment.
    mockwin::reset(128 * 1024);
    const auto unalignedSlot = mockwin::base + 0x401;
    writeAt<std::uint64_t>(unalignedSlot, mockwin::base + 0x5000);
    scanner.setProcess(reinterpret_cast<HANDLE>(1), 8, modules);

    PointerScanOptions naturalAlignment;
    naturalAlignment.maxIndexEntries = 10000;
    scanner.captureIndex(naturalAlignment);
    expect(std::none_of(scanner.index().begin(), scanner.index().end(), [&](const PointerEntry& entry) {
        return entry.address == unalignedSlot;
    }), "natural pointer alignment ignores unaligned pointer slots");

    PointerScanOptions byteAlignment = naturalAlignment;
    byteAlignment.alignment = 1;
    scanner.captureIndex(byteAlignment);
    expect(std::any_of(scanner.index().begin(), scanner.index().end(), [&](const PointerEntry& entry) {
        return entry.address == unalignedSlot && entry.value == mockwin::base + 0x5000;
    }), "byte pointer alignment can index unaligned pointer slots");

    mockwin::protection = PAGE_READONLY;
    PointerScanOptions writableOnly = byteAlignment;
    writableOnly.writableOnly = true;
    const auto writableStats = scanner.captureIndex(writableOnly);
    expect(writableStats.indexEntries == 0, "pointer writable-only filter excludes read-only regions");

    mockwin::protection = PAGE_READWRITE;
    mockwin::regionType = MEM_MAPPED;
    PointerScanOptions privateOnly = byteAlignment;
    privateOnly.privateOnly = true;
    const auto privateStats = scanner.captureIndex(privateOnly);
    expect(privateStats.indexEntries == 0, "pointer private-only filter excludes mapped regions");

    if (failures == 0) {
        std::cout << "\nALL MOCK POINTER TESTS PASSED\n";
        return 0;
    }
    std::cout << "\n" << failures << " TEST(S) FAILED\n";
    return 1;
}
