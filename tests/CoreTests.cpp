#include "cw/AobPersistence.hpp"
#include "cw/InstructionDecode.hpp"
#ifdef _WIN32
#include "cw/MemoryScanner.hpp"
#endif
#include "cw/PointerAlgorithms.hpp"
#include "cw/PointerPersistence.hpp"
#include "cw/PointerProfile.hpp"
#include "cw/PointerMap.hpp"
#include "cw/RelativeAddress.hpp"
#include "cw/ScanAlgorithms.hpp"
#include "cw/ScanPersistence.hpp"
#include "cw/ScanTypes.hpp"
#include "cw/Value.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

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

bool fileHasMagic(const std::string& path, const char (&magic)[9]) {
    std::ifstream in(path, std::ios::binary);
    std::array<char, 8> actual{};
    in.read(actual.data(), static_cast<std::streamsize>(actual.size()));
    return static_cast<bool>(in) && std::equal(actual.begin(), actual.end(), magic);
}

bool rewriteMagic(const std::string& path, const char (&magic)[9]) {
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) return false;
    file.write(magic, 8);
    file.flush();
    return static_cast<bool>(file);
}

} // namespace

int main() {
    using namespace cw;

    expect(parseValueType("int32") == ValueType::Int32, "parse int32 type");
    expect(parseValueType("F64") == ValueType::Double, "parse type case-insensitively");
    expect(!parseValueType("wat"), "reject unknown type");

    const auto b255 = parseValue(ValueType::Byte, "255");
    expect(b255 && std::get<std::uint8_t>(*b255) == 255, "parse byte upper bound");
    expect(!parseValue(ValueType::Byte, "256"), "reject byte overflow");
    expect(!parseValue(ValueType::Int16, "40000"), "reject int16 overflow");

    const auto i32 = parseValue(ValueType::Int32, "-123456");
    expect(i32 && std::get<std::int32_t>(*i32) == -123456, "parse signed int32");

    const auto f32 = parseValue(ValueType::Float, "3.5");
    expect(f32 && std::fabs(std::get<float>(*f32) - 3.5f) < 0.0001f, "parse float");
    expect(!parseValue(ValueType::Double, "nan"), "reject non-finite float");

    const auto all100 = parseAllCompatibleValues("100");
    expect(all100.size() == 6, "scan-all parser accepts integer 100 for all six numeric types");
    const auto allDecimal = parseAllCompatibleValues("3.5");
    expect(allDecimal.size() == 2 && allDecimal[0].first == ValueType::Float && allDecimal[1].first == ValueType::Double,
           "scan-all parser keeps only compatible float types for decimal value");

    expect(formatValue(Value{std::int32_t{42}}) == "42", "format int32");
    expect(valueTypeSize(ValueType::Int64) == 8, "int64 size");
    expect(valueMatchesType(ValueType::Float, Value{1.0f}), "value/type match");
    expect(!valueMatchesType(ValueType::Float, Value{1.0}), "value/type mismatch");

    // Scan-mode comparison semantics and snapshot packing.
    expect(scanMatches<int>(ScanMode::Changed, 11, 10, std::nullopt), "changed mode");
    expect(!scanMatches<int>(ScanMode::Changed, 10, 10, std::nullopt), "changed rejects same value");
    expect(scanMatches<int>(ScanMode::Unchanged, 10, 10, std::nullopt), "unchanged mode");
    expect(scanMatches<int>(ScanMode::Increased, 11, 10, std::nullopt), "increased mode");
    expect(scanMatches<int>(ScanMode::Decreased, 9, 10, std::nullopt), "decreased mode");
    expect(scanMatches<int>(ScanMode::BiggerThan, 11, 0, std::optional<int>{10}), "bigger-than mode");
    expect(scanMatches<int>(ScanMode::SmallerThan, 9, 0, std::optional<int>{10}), "smaller-than mode");
    expect(scanMatches<int>(ScanMode::Exact, 10, 0, std::optional<int>{10}), "exact mode");
    expect(scanMatches<float>(ScanMode::Exact, 10.005f, 0.0f, std::optional<float>{10.0f}, 0.01),
           "float exact honors tolerance");
    expect(!scanMatches<float>(ScanMode::Exact, 10.02f, 0.0f, std::optional<float>{10.0f}, 0.01),
           "float exact rejects outside tolerance");
    expect(scanMatches<float>(ScanMode::Unchanged, 10.005f, 10.0f, std::nullopt, 0.01),
           "float unchanged honors tolerance");
    expect(!scanMatches<float>(ScanMode::Increased, 10.005f, 10.0f, std::nullopt, 0.01),
           "float increased ignores noise inside tolerance");
    expect(scanMatches<float>(ScanMode::Increased, 10.02f, 10.0f, std::nullopt, 0.01),
           "float increased detects change beyond tolerance");
    expect(scanModeNeedsValue(ScanMode::Exact) && scanModeNeedsValue(ScanMode::BiggerThan) &&
           !scanModeNeedsValue(ScanMode::Changed), "mode value requirements");

    const double packedSource = 42.125;
    const auto packed = packScanValue(packedSource);
    expect(unpackScanValue<double>(packed) == packedSource, "pack/unpack double snapshot value");

    // Materialized value-scan session persistence. This intentionally saves only
    // address/result state, not Unknown Initial Value raw-memory snapshots.
    {
        ScanSessionData session;
        session.sourcePid = 4242;
        session.mixed = true;
        session.primaryType = ValueType::Int32;
        session.options.alignment = AlignmentMode::Byte;
        session.options.writableOnly = true;
        session.options.privateOnly = true;
        session.options.floatTolerance = 0.125;
        session.options.minAddress = 0x1000;
        session.options.maxAddress = 0x9000;
        session.results = {
            ScanResult{0x1234, packScanValue<std::int32_t>(83), ValueType::Int32},
            ScanResult{0x4567, packScanValue<float>(12.5f), ValueType::Float},
        };

        const auto tempPath = (std::filesystem::temp_directory_path() / "cw-scan-test.cwscan").string();
        std::string fileError;
        expect(saveScanSession(tempPath, session, fileError), "save value scan session");
        expect(fileHasMagic(tempPath, "CWSCAN01"), "new scan session uses CW magic");
        ScanSessionData loaded;
        expect(loadScanSession(tempPath, loaded, fileError), "load value scan session");
        expect(loaded.sourcePid == 4242 && loaded.mixed && loaded.primaryType == ValueType::Int32,
               "scan session preserves PID and mixed metadata");
        expect(loaded.options.alignment == AlignmentMode::Byte && loaded.options.writableOnly &&
               loaded.options.privateOnly && std::fabs(loaded.options.floatTolerance - 0.125) < 1e-12 &&
               loaded.options.minAddress == 0x1000 && loaded.options.maxAddress == 0x9000,
               "scan session preserves scan options");
        expect(loaded.results.size() == 2 && loaded.results[0].address == 0x1234 &&
               loaded.results[0].type == ValueType::Int32 &&
               unpackScanValue<std::int32_t>(loaded.results[0].previousBits) == 83 &&
               loaded.results[1].type == ValueType::Float &&
               std::fabs(unpackScanValue<float>(loaded.results[1].previousBits) - 12.5f) < 0.0001f,
               "scan session preserves typed previous values");
        ScanSessionData limited;
        expect(!loadScanSession(tempPath, limited, fileError, 1),
               "scan session result safety limit is enforced");
        expect(rewriteMagic(tempPath, "MCESCAN1"), "rewrite scan fixture as legacy MCE magic");
        ScanSessionData legacyLoaded;
        expect(loadScanSession(tempPath, legacyLoaded, fileError) && legacyLoaded.results.size() == 2,
               "load legacy MCE scan session");
        std::error_code removeError;
        std::filesystem::remove(tempPath, removeError);
    }

    std::array<std::byte, 64> buffer{};
    const std::int32_t wanted = 0x12345678;
    std::memcpy(buffer.data() + 4, &wanted, sizeof(wanted));
    std::memcpy(buffer.data() + 12, &wanted, sizeof(wanted));
    std::memcpy(buffer.data() + 19, &wanted, sizeof(wanted)); // intentionally unaligned

    std::vector<std::uintptr_t> hits;
    scanExactBuffer<std::int32_t>(buffer.data(), buffer.size(), 0x1000, wanted, hits, 4);
    expect(hits.size() == 2, "natural-alignment scan ignores unaligned match");
    expect(hits.size() >= 2 && hits[0] == 0x1004 && hits[1] == 0x100C, "scan returns expected addresses");

    hits.clear();
    scanExactBuffer<std::int32_t>(buffer.data(), buffer.size(), 0x1000, wanted, hits, 1);
    expect(hits.size() == 3, "unaligned scan mode can find every match");

    std::array<std::byte, 32> shifted{};
    std::memcpy(shifted.data() + 3, &wanted, sizeof(wanted));
    hits.clear();
    scanExactBuffer<std::int32_t>(shifted.data(), shifted.size(), 0x1001, wanted, hits, 4);
    expect(hits.size() == 1 && hits[0] == 0x1004, "alignment uses virtual address, not buffer offset");

    hits.clear();
    const bool complete = scanExactBuffer<std::int32_t>(
        buffer.data(), buffer.size(), 0x1000, wanted, hits, 1, 2);
    expect(!complete && hits.size() == 2, "scan result cap stops before unbounded growth");

#ifdef _WIN32
    // Unknown Initial Value must keep refining the full snapshot when a Next Scan
    // still has more candidates than the 5M materialized-result safety cap.
    {
        constexpr std::size_t candidateBytes = 5'100'000;
        void* raw = VirtualAlloc(nullptr, candidateBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        expect(raw != nullptr, "allocate typed unknown refinement fixture");
        if (raw) {
            std::memset(raw, 7, candidateBytes);
            MemoryScanner scanner;
            scanner.setProcess(GetCurrentProcess());
            ScanOptions options;
            options.minAddress = reinterpret_cast<std::uintptr_t>(raw);
            options.maxAddress = options.minAddress + candidateBytes - 1;
            scanner.setOptions(options);

            const auto first = scanner.firstScanUnknown(ValueType::Byte);
            expect(first.resultCount == candidateBytes && scanner.unknownSnapshotActive(),
                   "typed unknown captures more than 5M candidates as a snapshot");
            const auto unchanged = scanner.nextScan(ScanMode::Unchanged);
            expect(unchanged.resultCount == candidateBytes && scanner.unknownSnapshotActive() &&
                   scanner.results().empty() && !unchanged.truncated,
                   "typed unknown keeps >5M survivors in snapshot instead of truncating results");
            expect(scanner.refinementHistory().size() == 1 &&
                   scanner.refinementHistory()[0].mode == ScanMode::Unchanged &&
                   scanner.refinementHistory()[0].beforeCount == candidateBytes &&
                   scanner.refinementHistory()[0].afterCount == candidateBytes,
                   "Guided history records typed refinement before/after counts");
            const auto exactNone = scanner.nextScan(
                ScanMode::Exact, std::optional<Value>{Value{std::uint8_t{8}}});
            expect(exactNone.resultCount == 0 && !scanner.unknownSnapshotActive() && scanner.results().empty(),
                   "typed unknown materializes after later refinement falls below result cap");
            VirtualFree(raw, 0, MEM_RELEASE);
        }
    }
    {
        constexpr std::size_t snapshotBytes = 2'300'000;
        void* raw = VirtualAlloc(nullptr, snapshotBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        expect(raw != nullptr, "allocate mixed unknown refinement fixture");
        if (raw) {
            std::memset(raw, 0, snapshotBytes);
            MemoryScanner scanner;
            scanner.setProcess(GetCurrentProcess());
            ScanOptions options;
            options.minAddress = reinterpret_cast<std::uintptr_t>(raw);
            options.maxAddress = options.minAddress + snapshotBytes - 1;
            scanner.setOptions(options);

            const auto first = scanner.firstScanAllUnknown();
            expect(first.resultCount > 5'000'000 && scanner.unknownSnapshotActive(),
                   "mixed unknown captures more than 5M typed candidates as a snapshot");
            const auto beforeCounts = scanner.candidateCountsByType();
            std::size_t beforeTotal = 0;
            for (const auto count : beforeCounts) beforeTotal += count;
            expect(beforeTotal == first.resultCount && beforeCounts[4] > 0,
                   "mixed unknown exposes candidate counts per numeric type");
            const auto floatCandidates = beforeCounts[4];
            expect(scanner.disableMixedType(ValueType::Float),
                   "mixed unknown can disable one active value type without restarting");
            const auto afterDisable = scanner.candidateCountsByType();
            expect(afterDisable[4] == 0 && scanner.candidateCount() == first.resultCount - floatCandidates,
                   "disabling mixed type removes only that type candidates");
            const auto expectedUnchanged = scanner.candidateCount();
            const auto unchanged = scanner.nextScanMixed(ScanMode::Unchanged);
            expect(unchanged.resultCount == expectedUnchanged && !unchanged.truncated &&
                   scanner.candidateCountsByType()[4] == 0 &&
                   scanner.candidateCount() == expectedUnchanged,
                   "mixed unknown keeps disabled type excluded across Next Scan/materialization");
            const auto exactNone = scanner.nextScanMixed(
                ScanMode::Exact, std::optional<std::string>{"123456789"});
            expect(exactNone.resultCount == 0 && !scanner.unknownSnapshotActive() && scanner.results().empty(),
                   "mixed unknown materializes only after refinement falls below result cap");
            VirtualFree(raw, 0, MEM_RELEASE);
        }
    }
    {
        constexpr std::size_t halfBytes = 64ull * 1024ull;
        constexpr std::size_t totalBytes = halfBytes * 2;
        void* raw = VirtualAlloc(nullptr, totalBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        expect(raw != nullptr, "allocate Smart Unknown writable-filter fixture");
        if (raw) {
            DWORD oldProtect = 0;
            const BOOL protectedOk = VirtualProtect(
                static_cast<std::byte*>(raw) + halfBytes, halfBytes, PAGE_READONLY, &oldProtect);
            expect(protectedOk != FALSE, "make half of Smart Unknown fixture read-only");

            MemoryScanner scanner;
            scanner.setProcess(GetCurrentProcess());
            ScanOptions options;
            options.minAddress = reinterpret_cast<std::uintptr_t>(raw);
            options.maxAddress = options.minAddress + totalBytes - 1;
            scanner.setOptions(options);

            const auto full = scanner.firstScanUnknown(ValueType::Byte);
            expect(full.resultCount == totalBytes,
                   "Full Unknown keeps writable and read-only private memory");
            const auto smart = scanner.firstScanUnknownSmart(ValueType::Byte);
            expect(smart.resultCount == halfBytes && scanner.unknownSnapshotActive(),
                   "Smart Unknown keeps only private writable memory");
            expect(!scanner.options().writableOnly && !scanner.options().privateOnly,
                   "Smart Unknown does not mutate persistent Full scan options");
            const auto materialized = scanner.nextScan(ScanMode::Unchanged);
            expect(materialized.resultCount == halfBytes && !scanner.unknownSnapshotActive() &&
                   scanner.results().size() == halfBytes,
                   "small Smart Unknown materializes after Guided Unchanged refinement");
            expect(scanner.refinementHistory().size() == 1 &&
                   scanner.refinementHistory()[0].beforeCount == halfBytes &&
                   scanner.refinementHistory()[0].afterCount == halfBytes,
                   "Guided history survives snapshot materialization");
            const auto ranked = scanner.rankedResults(8);
            expect(ranked.size() == 8,
                   "ranking returns requested top-N materialized candidates");
            bool rankingMetadataOk = ranked.size() == 8;
            for (const auto& item : ranked) {
                rankingMetadataOk = rankingMetadataOk && item.resultIndex < scanner.results().size() &&
                    item.privateMemory && item.writable && !item.executable && item.score >= 90;
            }
            expect(rankingMetadataOk,
                   "ranking favors private writable non-executable gameplay-style memory deterministically");
            scanner.clear();
            expect(scanner.refinementHistory().empty(), "clear resets Guided refinement history");
            VirtualFree(raw, 0, MEM_RELEASE);
        }
    }
    {
        constexpr std::size_t bytes = 4096;
        void* raw = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        expect(raw != nullptr, "allocate ranking type-order fixture");
        if (raw) {
            MemoryScanner scanner;
            scanner.setProcess(GetCurrentProcess());
            ScanOptions options;
            options.minAddress = reinterpret_cast<std::uintptr_t>(raw);
            options.maxAddress = options.minAddress + bytes - 1;
            std::vector<ScanResult> restored{
                {options.minAddress + 16, packScanValue<std::uint8_t>(1), ValueType::Byte},
                {options.minAddress + 32, packScanValue<std::int32_t>(2), ValueType::Int32},
                {options.minAddress + 48, packScanValue<float>(3.0f), ValueType::Float},
            };
            expect(scanner.restoreMaterializedScan(ValueType::Int32, true, options, std::move(restored)),
                   "restore mixed materialized ranking fixture");
            const auto ranked = scanner.rankedResults(3);
            expect(ranked.size() == 3 && ranked[0].score > ranked[1].score &&
                   ranked[1].score > ranked[2].score &&
                   scanner.results()[ranked[0].resultIndex].type == ValueType::Float &&
                   scanner.results()[ranked[1].resultIndex].type == ValueType::Int32 &&
                   scanner.results()[ranked[2].resultIndex].type == ValueType::Byte,
                   "ranking combines type and captured-value plausibility in equal memory regions");
            VirtualFree(raw, 0, MEM_RELEASE);
        }
    }
    {
        constexpr std::size_t bytes = 64;
        void* raw = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        expect(raw != nullptr, "allocate Guided Wizard sequence fixture");
        if (raw) {
            std::memset(raw, 100, bytes);
            MemoryScanner scanner;
            scanner.setProcess(GetCurrentProcess());
            ScanOptions options;
            options.minAddress = reinterpret_cast<std::uintptr_t>(raw);
            options.maxAddress = options.minAddress + bytes - 1;
            scanner.setOptions(options);

            scanner.firstScanUnknown(ValueType::Byte);
            const auto genericStart = scanner.guidedSuggestion(GuidedGoal::Generic);
            const auto moneyStart = scanner.guidedSuggestion(GuidedGoal::Money);
            expect(genericStart && genericStart->recommendedMode == ScanMode::Changed &&
                   moneyStart && moneyStart->recommendedMode == ScanMode::Decreased,
                   "Guided Wizard recommends generic change and money decrease as first actions");

            static_cast<std::uint8_t*>(raw)[0] = 99;
            scanner.nextScan(ScanMode::Decreased);
            const auto afterDecrease = scanner.guidedSuggestion(GuidedGoal::Money);
            expect(afterDecrease && afterDecrease->recommendedMode == ScanMode::Unchanged,
                   "Guided Wizard recommends a stability step after money decreases");
            scanner.nextScan(ScanMode::Unchanged);
            const auto afterStable = scanner.guidedSuggestion(GuidedGoal::Money);
            expect(afterStable && afterStable->recommendedMode == ScanMode::Increased &&
                   afterStable->rankingAvailable && afterStable->inspectRecommended,
                   "Guided Wizard alternates to increase and exposes ranking when the set is small");
            static_cast<std::uint8_t*>(raw)[0] = 100;
            scanner.nextScan(ScanMode::Increased);
            const auto afterIncrease = scanner.guidedSuggestion(GuidedGoal::Money);
            expect(afterIncrease && afterIncrease->recommendedMode == ScanMode::Unchanged,
                   "Guided Wizard recommends stability after the increase step");
            VirtualFree(raw, 0, MEM_RELEASE);
        }
    }
    {
        constexpr std::size_t bytes = 4096;
        void* raw = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        expect(raw != nullptr, "allocate Ranking V2 goal fixture");
        if (raw) {
            MemoryScanner scanner;
            scanner.setProcess(GetCurrentProcess());
            ScanOptions options;
            options.minAddress = reinterpret_cast<std::uintptr_t>(raw);
            options.maxAddress = options.minAddress + bytes - 1;
            std::vector<ScanResult> restored{
                {options.minAddress + 64, packScanValue<float>(1.0f), ValueType::Float},
                {options.minAddress + 128, packScanValue<float>(0.00208333344f), ValueType::Float},
                {options.minAddress + 192, packScanValue<float>(18997.6992f), ValueType::Float},
                {options.minAddress + 256, packScanValue<std::int32_t>(5000), ValueType::Int32},
                {options.minAddress + 320, packScanValue<std::int16_t>(30), ValueType::Int16},
                {options.minAddress + 384, packScanValue<std::uint8_t>(30), ValueType::Byte},
            };
            expect(scanner.restoreMaterializedScan(ValueType::Int32, true, options, std::move(restored)),
                   "restore Ranking V2 goal fixture");
            const auto generic = scanner.rankedResults(6, GuidedGoal::Generic);
            const auto money = scanner.rankedResults(6, GuidedGoal::Money);
            const auto health = scanner.rankedResults(6, GuidedGoal::Health);
            const auto ammo = scanner.rankedResults(6, GuidedGoal::Ammo);
            expect(generic.size() == 6 && scanner.results()[generic[0].resultIndex].type == ValueType::Float &&
                   unpackScanValue<float>(scanner.results()[generic[0].resultIndex].previousBits) == 1.0f,
                   "Ranking V2 generic score breaks broad Float ties using value shape");
            expect(money.size() == 6 && scanner.results()[money[0].resultIndex].type == ValueType::Int32,
                   "Ranking V2 money goal prioritizes counter-like Int32 candidates");
            expect(health.size() == 6 && scanner.results()[health[0].resultIndex].type == ValueType::Float,
                   "Ranking V2 health goal prioritizes plausible Float candidates");
            expect(ammo.size() == 6 && scanner.results()[ammo[0].resultIndex].type == ValueType::Int32,
                   "Ranking V2 ammo goal prioritizes integer counter candidates");
            VirtualFree(raw, 0, MEM_RELEASE);
        }
    }
    {
        // Regression for the former 512 MiB source-snapshot cap. The buffer is
        // intentionally just above that boundary; disk-backed snapshots must
        // capture the entire readable range without marking it truncated.
        constexpr std::size_t snapshotBytes = 513ull * 1024ull * 1024ull;
        void* raw = VirtualAlloc(nullptr, snapshotBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        expect(raw != nullptr, "allocate >512 MiB disk-backed unknown fixture");
        if (raw) {
            MemoryScanner scanner;
            scanner.setProcess(GetCurrentProcess());
            ScanOptions options;
            options.minAddress = reinterpret_cast<std::uintptr_t>(raw);
            options.maxAddress = options.minAddress + snapshotBytes - 1;
            scanner.setOptions(options);

            const auto first = scanner.firstScanUnknown(ValueType::Byte);
            expect(first.resultCount == snapshotBytes && first.bytesRead >= snapshotBytes &&
                   !first.truncated && !scanner.unknownSnapshotSourceTruncated() &&
                   scanner.unknownSnapshotActive(),
                   "typed unknown captures complete source beyond former 512 MiB cap");
            scanner.clear();
            VirtualFree(raw, 0, MEM_RELEASE);
        }
    }
#endif

    // rel32 helpers used by AOB result decoding (CALL/JMP and RIP-relative operands).
    const auto relForward = resolveRel32(0x1000, 5, 0x20);
    expect(relForward && *relForward == 0x1025, "rel32 resolves positive displacement");
    const auto relBackward = resolveRel32(0x1000, 5, -0x20);
    expect(relBackward && *relBackward == 0x0FE5, "rel32 resolves negative displacement");
    const auto relOverflow = resolveRel32((std::numeric_limits<std::uintptr_t>::max)() - 1, 5, 0);
    expect(!relOverflow, "rel32 rejects instruction-address overflow");
    const auto rel8Backward = resolveRel8(0x2000, 2, static_cast<std::int8_t>(-0x10));
    expect(rel8Backward && *rel8Backward == 0x1FF2, "rel8 resolves signed displacement");

    {
        const std::array<std::byte, 5> callBytes{
            std::byte{0xE8}, std::byte{0x20}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
        const auto info = decodeCommonRelativeInstruction(0x1000, callBytes, true);
        expect(info && info->kind == RelativeInstructionKind::CallRel32 && info->target == 0x1025,
               "instruction decoder recognizes CALL rel32");
    }
    {
        const std::array<std::byte, 2> shortJump{std::byte{0xEB}, std::byte{0xF0}};
        const auto info = decodeCommonRelativeInstruction(0x2000, shortJump, true);
        expect(info && info->kind == RelativeInstructionKind::JumpRel8 && info->target == 0x1FF2,
               "instruction decoder recognizes JMP rel8");
    }
    {
        const std::array<std::byte, 6> indirectCall{
            std::byte{0xFF}, std::byte{0x15}, std::byte{0x10}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
        const auto info = decodeCommonRelativeInstruction(0x3000, indirectCall, true);
        expect(info && info->kind == RelativeInstructionKind::IndirectCallRip && info->indirect &&
               info->target == 0x3016, "instruction decoder recognizes RIP-indirect CALL slot");
        expect(!decodeCommonRelativeInstruction(0x3000, indirectCall, false),
               "RIP-indirect CALL is not misdecoded for x86 targets");
    }
    {
        const std::array<std::byte, 7> leaRip{
            std::byte{0x48}, std::byte{0x8D}, std::byte{0x0D}, std::byte{0x20},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
        const auto info = decodeCommonRelativeInstruction(0x4000, leaRip, true);
        expect(info && info->kind == RelativeInstructionKind::RipRelativeMemory && info->target == 0x4027,
               "instruction decoder recognizes common RIP-relative memory operand");
    }

    // AOB search/session persistence. Results inside modules are stored as module offsets;
    // heap/non-module hits can remain absolute and are explicitly distinguishable on load.
    {
        std::string parseError;
        const auto parsedPattern = parseAobPattern("48 8D 0D ?? ?? ?? ??", parseError);
        expect(parsedPattern.has_value(), "parse AOB fixture for persistence");
        if (parsedPattern) {
            AobSessionData session;
            session.pattern = *parsedPattern;
            session.scope = AobSearchScope::ModuleExecutable;
            session.moduleName = "game.exe";
            session.results = {
                AobSavedResult{true, "game.exe", 0x1234},
                AobSavedResult{false, {}, 0x7FFF00001234ULL},
            };
            const auto tempPath = (std::filesystem::temp_directory_path() / "cw-aob-test.cwaob").string();
            std::string fileError;
            expect(saveAobSession(tempPath, session, fileError), "save AOB session");
            expect(fileHasMagic(tempPath, "CWAOB001"), "new AOB session uses CW magic");
            AobSessionData loaded;
            expect(loadAobSession(tempPath, loaded, fileError), "load AOB session");
            expect(formatAobPattern(loaded.pattern) == formatAobPattern(session.pattern),
                   "AOB session preserves wildcard pattern");
            expect(loaded.scope == AobSearchScope::ModuleExecutable && loaded.moduleName == "game.exe",
                   "AOB session preserves search scope");
            expect(loaded.results.size() == 2 && loaded.results[0].moduleRelative &&
                   loaded.results[0].moduleName == "game.exe" && loaded.results[0].value == 0x1234 &&
                   !loaded.results[1].moduleRelative && loaded.results[1].value == 0x7FFF00001234ULL,
                   "AOB session preserves module-relative and absolute results");
            AobSessionData limited;
            expect(!loadAobSession(tempPath, limited, fileError, 1),
                   "AOB session result safety limit is enforced");
            expect(rewriteMagic(tempPath, "MCEAOB01"), "rewrite AOB fixture as legacy MCE magic");
            AobSessionData legacyLoaded;
            expect(loadAobSession(tempPath, legacyLoaded, fileError) && legacyLoaded.results.size() == 2,
                   "load legacy MCE AOB session");
            std::error_code removeError;
            std::filesystem::remove(tempPath, removeError);
        }
    }

    // Pointer-chain search: module+0x200 -> +0x20 -> +0x30 -> target.
    // Slot 0x1200 (inside module) stores 0x2000. 0x2000+0x20=0x2020.
    // Slot 0x2020 stores 0x3000. 0x3000+0x30=0x3030 target.
    std::vector<PointerEntry> pointerIndex{
        {0x2000, 0x1200},
        {0x3000, 0x2020},
        // distractors
        {0x2FF0, 0x2500},
        {0x9999, 0x2600},
    };
    std::sort(pointerIndex.begin(), pointerIndex.end());
    std::vector<PointerModule> pointerModules{
        {0x1000, 0x800, L"game.exe"},
    };
    PointerScanOptions pointerOptions;
    pointerOptions.maxDepth = 3;
    pointerOptions.maxOffset = 0x40;
    pointerOptions.maxChains = 100;
    bool pointerTruncated = false;
    const auto chains = findPointerChains(
        pointerIndex, pointerModules, 0x3030, pointerOptions, &pointerTruncated);
    const auto expectedChain = std::find_if(chains.begin(), chains.end(), [](const PointerChain& chain) {
        return chain.moduleName == L"game.exe" && chain.rootOffset == 0x200 &&
               chain.offsets == std::vector<std::int64_t>{0x20, 0x30};
    });
    expect(expectedChain != chains.end(), "pointer search finds two-level module-rooted chain");
    expect(!pointerTruncated, "pointer search is not truncated for small fixture");

    PointerScanOptions rootFiltered = pointerOptions;
    rootFiltered.rootModuleName = L"other.dll";
    expect(findPointerChains(pointerIndex, pointerModules, 0x3030, rootFiltered).empty(),
           "pointer root-module filter excludes non-matching module");
    rootFiltered.rootModuleName = L"GAME.EXE";
    expect(!findPointerChains(pointerIndex, pointerModules, 0x3030, rootFiltered).empty(),
           "pointer root-module filter is case-insensitive");

    PointerScanOptions depthOne = pointerOptions;
    depthOne.maxDepth = 1;
    const auto noDeepChain = findPointerChains(pointerIndex, pointerModules, 0x3030, depthOne);
    expect(std::none_of(noDeepChain.begin(), noDeepChain.end(), [](const PointerChain& chain) {
        return chain.rootOffset == 0x200 && chain.offsets.size() == 2;
    }), "pointer depth limit is enforced");

    PointerScanOptions tightOffset = pointerOptions;
    tightOffset.maxOffset = 0x10;
    const auto noOffsetChain = findPointerChains(pointerIndex, pointerModules, 0x3030, tightOffset);
    expect(noOffsetChain.empty(), "pointer max-offset limit is enforced");

    // Dense reverse graphs must terminate under the global search-work budget.
    std::vector<PointerEntry> denseIndex;
    denseIndex.reserve(6000);
    for (std::uintptr_t i = 0; i < 6000; ++i) {
        denseIndex.push_back(PointerEntry{0x800000 - (i % 0x100), 0x800000 - ((i * 8) % 0x1000)});
    }
    std::sort(denseIndex.begin(), denseIndex.end());
    PointerScanOptions budgeted;
    budgeted.maxDepth = 6;
    budgeted.maxOffset = 0x1000;
    budgeted.maxCandidatesPerNode = 4096;
    budgeted.maxSearchCandidates = 1000;
    budgeted.maxChains = 100;
    bool budgetTruncated = false;
    (void)findPointerChains(denseIndex, {}, 0x800000, budgeted, &budgetTruncated);
    expect(budgetTruncated, "pointer search terminates at global work budget on dense graphs");

    // Signed negative pointer offsets are opt-in and bounded separately.
    std::vector<PointerEntry> negativeIndex{
        {0x3050, 0x1100}, // game+0x100 stores target+0x20, requiring -0x20
    };
    std::sort(negativeIndex.begin(), negativeIndex.end());
    PointerScanOptions negativeOptions;
    negativeOptions.maxDepth = 1;
    negativeOptions.maxOffset = 0x40;
    negativeOptions.maxNegativeOffset = 0x40;
    negativeOptions.maxChains = 100;
    const auto negativeChains = findPointerChains(
        negativeIndex, pointerModules, 0x3030, negativeOptions);
    expect(std::any_of(negativeChains.begin(), negativeChains.end(), [](const PointerChain& chain) {
        return chain.rootOffset == 0x100 && chain.offsets == std::vector<std::int64_t>{-0x20};
    }), "pointer search finds bounded negative offset chain");

    negativeOptions.maxNegativeOffset = 0;
    const auto negativeDisabled = findPointerChains(
        negativeIndex, pointerModules, 0x3030, negativeOptions);
    expect(negativeDisabled.empty(), "negative pointer offsets are disabled when maxNegativeOffset is zero");


    // Pointer-chain persistence round-trip.
    {
        const auto tempPath = (std::filesystem::temp_directory_path() / "cw-pointer-test.cwchain").string();
        std::vector<PointerChain> savedChains{
            PointerChain{L"game.exe", 0x1234, {0x10, 0x20, 0x30}},
            PointerChain{L"módulo.dll", 0xABC, {0x8, -0x18}},
        };
        std::string fileError;
        expect(savePointerChains(tempPath, 8, savedChains, fileError), "save pointer chains");
        expect(fileHasMagic(tempPath, "CWCHAIN1"), "new pointer-chain file uses CW magic");
        PointerFileData loaded;
        expect(loadPointerChains(tempPath, loaded, fileError), "load pointer chains");
        expect(loaded.pointerSize == 8, "pointer file preserves pointer width");
        expect(loaded.chains.size() == savedChains.size(), "pointer file preserves chain count");
        if (loaded.chains.size() == savedChains.size()) {
            expect(loaded.chains[0].moduleName == savedChains[0].moduleName &&
                   loaded.chains[0].rootOffset == savedChains[0].rootOffset &&
                   loaded.chains[0].offsets == savedChains[0].offsets,
                   "pointer file preserves first chain");
            expect(loaded.chains[1].moduleName == savedChains[1].moduleName &&
                   loaded.chains[1].offsets == savedChains[1].offsets,
                   "pointer file preserves UTF-8 module name");
        }
        PointerFileData limited;
        expect(!loadPointerChains(tempPath, limited, fileError, 1),
               "pointer file chain safety limit is enforced");
        expect(rewriteMagic(tempPath, "MCEPTR01"), "rewrite pointer-chain fixture as legacy MCE magic");
        PointerFileData legacyLoaded;
        expect(loadPointerChains(tempPath, legacyLoaded, fileError) && legacyLoaded.chains.size() == savedChains.size(),
               "load legacy MCE pointer-chain file");
        std::error_code removeError;
        std::filesystem::remove(tempPath, removeError);
    }


    // Pointer-profile persistence round-trip (GUI/trainer handoff format).
    {
        const auto tempPath = (std::filesystem::temp_directory_path() / "cw-pointer-profile-test.cwptr").string();
        PointerProfileData profile;
        profile.pointerSize = 8;
        profile.type = ValueType::Float;
        profile.processName = "sample.exe";
        profile.chains = {
            PointerChain{L"GameAssembly.dll", 0x2F69470, {0x2480, 0x68}},
            PointerChain{L"GameAssembly.dll", 0x31707A0, {0x2A00, 0x68}},
        };
        std::string error;
        expect(savePointerProfile(tempPath, profile, error), "save pointer profile");
        expect(fileHasMagic(tempPath, "CWPROF01"), "new pointer profile uses CW magic");
        PointerProfileData loaded;
        expect(loadPointerProfile(tempPath, loaded, error), "load pointer profile");
        expect(loaded.pointerSize == 8 && loaded.type == ValueType::Float,
               "pointer profile preserves width and value type");
        expect(loaded.processName == "sample.exe", "pointer profile preserves process name");
        expect(loaded.chains.size() == 2 && loaded.chains[0].offsets == profile.chains[0].offsets,
               "pointer profile preserves redundant chains");
        expect(rewriteMagic(tempPath, "MCEPROF1"), "rewrite pointer-profile fixture as legacy MCE magic");
        PointerProfileData legacyLoaded;
        expect(loadPointerProfile(tempPath, legacyLoaded, error) && legacyLoaded.chains.size() == 2,
               "load legacy MCE pointer profile");
        std::error_code removeError;
        std::filesystem::remove(tempPath, removeError);
    }


    // Pointer-map persistence + multi-session comparison.
    {
        PointerMapData map1;
        map1.pointerSize = 8;
        map1.target = 0x3030;
        map1.complete = true;
        map1.modules = {{0x1000, 0x1000, L"game.exe"}};
        map1.entries = {
            {0x2000, 0x1200}, // stable root: game+0x200
            {0x3000, 0x2020}, // +0x20, then +0x30 => target
            {0x2FF0, 0x1300}, // distractor direct chain (+0x40)
        };
        std::sort(map1.entries.begin(), map1.entries.end());

        PointerMapData map2;
        map2.pointerSize = 8;
        map2.target = 0x9030;
        map2.complete = true;
        map2.modules = {{0x5000, 0x1000, L"GAME.EXE"}}; // case-insensitive module match
        map2.entries = {
            {0x7000, 0x5200}, // same game+0x200 root in new session
            {0x9000, 0x7020},
            {0x1111, 0x5300}, // distractor no longer resolves to target
        };
        std::sort(map2.entries.begin(), map2.entries.end());

        std::vector<PointerMapData> maps{map1, map2};
        PointerScanOptions compareOptions;
        compareOptions.maxDepth = 3;
        compareOptions.maxOffset = 0x40;
        compareOptions.maxChains = 100;
        PointerMapCompareStats compareStats;
        const auto common = findCommonPointerChains(maps, compareOptions, &compareStats);
        expect(compareStats.maps == 2, "pointer-map comparison records map count");
        expect(compareStats.initialChains >= 2, "first pointer map contains stable + distractor chains");
        const auto stable = std::find_if(common.begin(), common.end(), [](const PointerChain& chain) {
            return chain.moduleName == L"game.exe" && chain.rootOffset == 0x200 &&
                   chain.offsets == std::vector<std::int64_t>{0x20, 0x30};
        });
        expect(stable != common.end(), "pointer-map comparison keeps cross-session stable chain");
        expect(std::none_of(common.begin(), common.end(), [](const PointerChain& chain) {
            return chain.rootOffset == 0x300 && chain.offsets == std::vector<std::int64_t>{0x40};
        }), "pointer-map comparison removes session-specific distractor");

        const auto tempPath = (std::filesystem::temp_directory_path() / "cw-pointer-map-test.cwmap").string();
        std::string mapError;
        expect(savePointerMap(tempPath, map1.pointerSize, map1.target, map1.modules, map1.entries, false, mapError),
               "save pointer map");
        expect(fileHasMagic(tempPath, "CWMAP001"), "new pointer map uses CW magic");
        PointerMapData loadedMap;
        expect(loadPointerMap(tempPath, loadedMap, mapError), "load pointer map");
        expect(loadedMap.pointerSize == 8 && loadedMap.target == map1.target,
               "pointer map preserves pointer width and target");
        expect(!loadedMap.complete, "pointer map preserves partial/completeness flag");
        expect(loadedMap.modules.size() == 1 && loadedMap.modules[0].name == L"game.exe",
               "pointer map preserves module metadata");
        expect(loadedMap.entries.size() == map1.entries.size(), "pointer map preserves entries");
        PointerMapData tooLimited;
        expect(!loadPointerMap(tempPath, tooLimited, mapError, 1),
               "pointer map entry safety limit is enforced");

        const auto tempPath2 = (std::filesystem::temp_directory_path() / "cw-pointer-map-test-2.cwmap").string();
        expect(savePointerMap(tempPath2, map2.pointerSize, map2.target, map2.modules, map2.entries, true, mapError),
               "save second pointer map");
        PointerMapCompareStats streamStats;
        std::string streamError;
        auto streamed = findCommonPointerChainsStreaming(
            std::vector<std::string>{tempPath, tempPath2}, compareOptions, &streamStats, streamError);
        expect(streamError.empty(), "streaming pointer-map compare succeeds");
        expect(streamStats.maps == 2 && streamStats.partialMaps == 1 &&
               streamStats.peakEntriesLoaded == (std::max)(map1.entries.size(), map2.entries.size()),
               "streaming pointer-map compare reports one-map peak and partial map count");
        expect(std::any_of(streamed.begin(), streamed.end(), [](const PointerChain& chain) {
            return chain.moduleName == L"game.exe" && chain.rootOffset == 0x200 &&
                   chain.offsets == std::vector<std::int64_t>{0x20, 0x30};
        }), "streaming pointer-map compare keeps stable chain");
        PointerMapCompareStats streamLimitedStats;
        std::string streamLimitedError;
        const auto streamLimited = findCommonPointerChainsStreaming(
            std::vector<std::string>{tempPath, tempPath2}, compareOptions, &streamLimitedStats, streamLimitedError, 1);
        expect(streamLimited.empty() && !streamLimitedError.empty(),
               "streaming pointer-map compare enforces per-map safety limit");

        PointerMapData noChainMap = map1;
        noChainMap.target = 0xDEADBEEF;
        const auto noChainPath = (std::filesystem::temp_directory_path() / "cw-pointer-map-no-chain.cwmap").string();
        expect(savePointerMap(noChainPath, noChainMap.pointerSize, noChainMap.target,
                              noChainMap.modules, noChainMap.entries, true, mapError),
               "save no-chain pointer map");
        PointerMapCompareStats validationStats;
        std::string validationError;
        const auto validationResult = findCommonPointerChainsStreaming(
            std::vector<std::string>{noChainPath, noChainPath + ".missing"},
            compareOptions, &validationStats, validationError);
        expect(validationResult.empty() && !validationError.empty(),
               "streaming compare validates later files even when first map has no chains");

        expect(rewriteMagic(tempPath, "MCEPMAP1"), "rewrite pointer-map fixture as legacy MCE magic");
        PointerMapData legacyMap;
        expect(loadPointerMap(tempPath, legacyMap, mapError) && legacyMap.entries.size() == map1.entries.size(),
               "load legacy MCE pointer map");

        std::error_code removeError;
        std::filesystem::remove(tempPath, removeError);
        std::filesystem::remove(tempPath2, removeError);
        std::filesystem::remove(noChainPath, removeError);
    }

    if (failures == 0) {
        std::cout << "\nALL CORE TESTS PASSED\n";
        return 0;
    }
    std::cout << "\n" << failures << " TEST(S) FAILED\n";
    return 1;
}
