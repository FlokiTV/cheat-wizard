#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cw {

struct PointerEntry {
    std::uintptr_t value{};       // pointer-sized value stored in target memory
    std::uintptr_t address{};     // address where that value is stored

    friend bool operator<(const PointerEntry& a, const PointerEntry& b) noexcept {
        if (a.value != b.value) return a.value < b.value;
        return a.address < b.address;
    }
};

struct PointerModule {
    std::uintptr_t base{};
    std::size_t size{};
    std::wstring name;

    [[nodiscard]] bool contains(std::uintptr_t address) const noexcept {
        if (size == 0 || address < base) return false;
        return (address - base) < size;
    }
};

struct PointerChain {
    std::wstring moduleName;
    std::uintptr_t rootOffset{};
    std::vector<std::int64_t> offsets;
};

enum class PointerSearchMode : std::uint8_t {
    Auto = 0,     // indexed search, with targeted fallback when no chain is found
    Indexed = 1,  // global pointer index + reverse DFS only
    Targeted = 2, // index-free layered reverse scan
};

struct PointerScanOptions {
    std::size_t maxDepth{3};
    std::uintptr_t maxOffset{0x1000};
    std::uintptr_t maxNegativeOffset{0};
    std::size_t maxChains{10'000};
    std::size_t maxIndexEntries{8'000'000};
    std::size_t maxCandidatesPerNode{4096};
    // Global reverse-search work budget. Prevents pointer-dense heaps from
    // exploding combinatorially; hitting it marks the result as truncated.
    std::size_t maxSearchCandidates{1'500'000};

    // Pointer-index filters. alignment == 0 means natural pointer alignment
    // (4 bytes for 32-bit targets, 8 bytes for 64-bit targets).
    std::size_t alignment{0};
    bool writableOnly{false};
    bool privateOnly{false};

    PointerSearchMode searchMode{PointerSearchMode::Auto};

    // Empty = allow roots in any loaded module. The pointer search is always
    // statically rooted in a module; this narrows it to one module by name.
    std::wstring rootModuleName;
};

struct PointerScanStats {
    std::size_t pointerSize{};
    std::size_t indexEntries{};
    std::size_t chains{};
    std::uint64_t bytesRead{};
    std::uint64_t regionsRead{};
    double indexMs{};
    double searchMs{};
    std::size_t directCandidates{};
    std::size_t searchCandidates{};
    std::size_t targetedDepth{};
    std::size_t targetedFrontier{};
    std::uint64_t targetedSlots{};
    std::uint64_t targetedMatches{};
    bool indexTruncated{};
    bool chainsTruncated{};
    bool searchBudgetHit{};
    bool branchLimitHit{};
    bool targetedTruncated{};
    bool targetedUsed{};
    bool targetedFallbackUsed{};
    bool cancelled{};
};

struct PointerSearchDiagnostics {
    std::size_t candidatesExamined{};
    bool budgetHit{};
    bool branchLimitHit{};
    bool chainLimitHit{};
};

} // namespace cw
