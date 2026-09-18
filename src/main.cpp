#include "cw/AobPattern.hpp"
#include "cw/AobPersistence.hpp"
#include "cw/AobScanner.hpp"
#include "cw/InstructionDecode.hpp"
#include "cw/FreezeManager.hpp"
#include "cw/EngineFrontend.hpp"
#include "cw/MemoryScanner.hpp"
#include "cw/MemoryWriter.hpp"
#include "cw/ProcessManager.hpp"
#include "cw/RelativeAddress.hpp"
#include "cw/PointerScanner.hpp"
#include "cw/PointerPersistence.hpp"
#include "cw/PointerProfile.hpp"
#include "cw/PointerMap.hpp"
#include "cw/ScanOptions.hpp"
#include "cw/ScanPersistence.hpp"
#include "cw/ScanTypes.hpp"
#include "cw/Value.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace {

constexpr const char* kVersion = "1.7.3";

std::vector<std::string> split(const std::string& line) {
    std::istringstream input(line);
    std::vector<std::string> parts;
    std::string part;
    while (input >> part) parts.push_back(part);
    return parts;
}

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

std::string joinArgs(const std::vector<std::string>& args, std::size_t start) {
    std::string out;
    for (std::size_t i = start; i < args.size(); ++i) {
        if (!out.empty()) out.push_back(' ');
        out += args[i];
    }
    if (out.size() >= 2 && ((out.front() == '"' && out.back() == '"') ||
                            (out.front() == '\'' && out.back() == '\''))) {
        out = out.substr(1, out.size() - 2);
    }
    return out;
}

std::string wideToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return "<unprintable>";

    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
        result.data(), required, nullptr, nullptr);
    return result;
}

const char* scanModeName(cw::ScanMode mode) {
    switch (mode) {
        case cw::ScanMode::Exact: return "Exact";
        case cw::ScanMode::Changed: return "Changed";
        case cw::ScanMode::Unchanged: return "Unchanged";
        case cw::ScanMode::Increased: return "Increased";
        case cw::ScanMode::Decreased: return "Decreased";
        case cw::ScanMode::BiggerThan: return "Bigger Than";
        case cw::ScanMode::SmallerThan: return "Smaller Than";
    }
    return "Unknown";
}

std::optional<cw::ScanMode> parseScanMode(const std::string& text) {
    const auto mode = lower(text);
    if (mode == "exact" || mode == "eq" || mode == "=") return cw::ScanMode::Exact;
    if (mode == "changed" || mode == "change") return cw::ScanMode::Changed;
    if (mode == "unchanged" || mode == "same") return cw::ScanMode::Unchanged;
    if (mode == "increased" || mode == "increase" || mode == "inc") return cw::ScanMode::Increased;
    if (mode == "decreased" || mode == "decrease" || mode == "dec") return cw::ScanMode::Decreased;
    if (mode == "bigger" || mode == "greater" || mode == "gt" || mode == ">") return cw::ScanMode::BiggerThan;
    if (mode == "smaller" || mode == "less" || mode == "lt" || mode == "<") return cw::ScanMode::SmallerThan;
    return std::nullopt;
}

void printHelp() {
    std::cout << R"(
Commands:
  processes | ps
      List running processes.

  attach <pid>
      Open a process for scanning + writing.

  attach-name <exe-name>
      Attach to the first process whose executable name matches.

  scan <type> <value>
  scan <type> unknown | unknown-smart
  scan all <value|unknown|unknown-smart>
      First scan. Types: byte, int16, int32, int64, float, double.
      'unknown-smart' scans only writable MEM_PRIVATE memory; Full 'unknown' is unchanged.
      'all' scans every compatible numeric type in one memory pass.

  types
  types off <type> [type...]
      Show mixed-scan candidate counts or permanently drop types from the current mixed scan.

  next <value>
  next exact <value>
  next changed | unchanged | increased | decreased
  next bigger <value> | smaller <value>
      Refine the current scan. inc/dec/gt/lt aliases are accepted.

  guide <changed|unchanged|increased|decreased>
      Guided Unknown shortcut. Runs a refinement and records before/after history.
  wizard [generic|money|health|ammo]
      Show/set the Guided Wizard goal and recommend the next in-game action/refinement.
  history
      Show the refinement sequence, survivor counts and reduction per step.
  ranked [limit]
      Show goal-aware Ranking V2 candidates while preserving original result indices.

  settings
      Show scanner settings.
  settings alignment <natural|byte>
      Natural is faster; byte can find unaligned values.
  settings writable <on|off>
      Restrict First Scan/Unknown Scan to writable memory.
  settings private <on|off>
      Restrict First Scan/Unknown Scan to MEM_PRIVATE regions.
  settings tolerance <number>
      Float/double comparison tolerance. 0 = exact binary comparison.
  settings range <min_address> <max_address>
  settings range all
      Restrict the address range scanned.
      Changing any setting clears the active scan.

  results [limit]
      Show result index, address, live value and value at last scan.

  scan-save <file.cwscan>
      Save the current materialized result list, previous values, types and scan settings.
      Unknown-initial raw snapshots must be refined with Next Scan before saving.

  scan-load <file.cwscan> [force]
      Restore a saved result list. By default the stored PID must match the currently
      attached process; use 'force' only when you intentionally accept stale addresses.

  watch <target> [count] [interval_ms]
      Sample a result/address repeatedly. Defaults: 20 samples, 250 ms.

  inspect <target>
      Read up to 8 bytes and interpret them as common numeric types.

  read-at <address> <type>
      Read a typed value without requiring an active scan.

  write-at <address> <type> <value>
      Write a typed raw address without requiring an active scan.

  freeze-at <address> <type> <value> [interval_ms]
      Freeze a typed raw address without requiring an active scan.

  set <target> <value>
      Write a value once. Target is #result-index or an address.

  freeze <target> <value> [interval_ms]
      Re-write the value repeatedly. Default interval: 50 ms.
  freezes
  unfreeze <id|all>

  modules
      List modules and their current base addresses.

  aob <pattern>
      Scan readable memory for an Array-of-Bytes signature.
      Bytes may be exact (89), full wildcards (??), or nibble wildcards (A? / ?F).
      Example: aob 89 83 ?? ?? ?? ?? 8B 4B ?F

  aob-code <pattern>
      Same as aob, but only scans executable memory pages.

  aob-module <module-name> <pattern>
      Restrict an AOB scan to one loaded module.

  aob-module-code <module-name> <pattern>
      Restrict an AOB scan to executable pages inside one loaded module.

  aob-results [limit]
      Show AOB matches and module-relative offsets when available.

  aob-resolve <#aob-index|address> <disp_offset> <instruction_size>
      Decode a signed rel32 displacement from an AOB match/address.
      Examples: CALL/JMP E8/E9 => aob-resolve #0 1 5
                RIP-relative 48 8D 0D xx xx xx xx => aob-resolve #0 3 7

  aob-decode <#aob-index|address>
      Auto-decode common CALL/JMP/Jcc and x64 RIP-relative instruction forms.
      RIP-indirect CALL/JMP also dereference the pointer slot when readable.

  aob-save <file.cwaob>
      Save the active signature, search scope and matches. Module hits are stored
      as module-relative offsets so they can be rebased after ASLR.
  aob-load <file.cwaob>
      Restore saved matches against the currently attached process.
  aob-rerun <file.cwaob>
      Re-run the saved signature/search recipe against the current process.

  aob-clear
      Clear stored AOB matches.

  pointer-settings
      Show pointer-index/search filters.
  pointer-settings alignment <natural|byte|2|4|8>
  pointer-settings writable <on|off>
  pointer-settings private <on|off>
  pointer-settings branch <count>
  pointer-settings root <any|module-name>
      Pointer roots are always static module addresses; 'root' can restrict
      them to one module. Source filters/alignment affect pointer indexing.

  pointer-scan <target> [depth] [max_offset] [max_chains] [max_negative_offset]
      Find pointer chains ending at #result-index or a raw address.
      Defaults: depth=3, max_offset=0x1000, max_chains=10000, negative=0.
      Set max_negative_offset (for example 0x400) to allow signed negative offsets.

  pointer-results [limit]
      Show chains as module+root -> offsets.

  pointer-resolve <index>
      Resolve one stored pointer chain against the current process.

  pointer-rescan <target>
      Keep only stored chains that resolve to the new target address.
      Useful after restarting/re-attaching the target.

  pointer-save <file.cwchain>
      Save stored pointer chains to a portable .cwchain file.

  pointer-load <file.cwchain>
      Load raw pointer chains from .cwchain or a legacy MiniCE .mcep file.

  profile-load <file.cwptr>
  profile-read | profile-write <value> | profile-freeze <value> [interval_ms]
      Load and operate on a typed redundant pointer profile. Profile operations
      use majority consensus across all currently resolvable chains.

  pmap-capture <file.cwmap> <target> [max_entries]
      Capture a disk-backed pointer map for the current process/session.
      Current pointer-settings alignment/writable/private filters are applied.
      The target is stored with the map for later cross-session comparison.

  pmap-load <file.cwmap>
      Load a .cwmap pointer map (or legacy .mcpm) into the comparison set.

  pmap-list
      Show loaded pointer maps, recorded targets and completeness.

  pmap-compare [depth] [max_offset] [max_chains] [max_negative_offset]
      Search the first loaded map, then keep only chains that resolve to the
      recorded target in every other loaded map. Results become pointer-results.

  pmap-compare-files <file1> <file2> [file3 ...]
      Streaming comparison: keeps at most one map's entries in RAM at a time.
      Uses current pointer-settings plus default depth/offset limits.

  pmap-clear
      Unload all pointer maps from memory.

  pointer-clear
      Clear stored pointer chains/index.

  version
  status
  clear
  detach
  help
  quit

During a long scan, press Ctrl+C once to request cancellation.
A cancelled scan is partial and can miss the desired address.

Typical exact workflow:
  processes
  attach 1234
  scan int32 100
  next 83
  next 61
  results 20
  set #0 999
  freeze #0 999

Unknown-value workflow:
  scan int32 unknown
  next decreased
  next unchanged
  next decreased
  results 20
)";
}

void printStats(const cw::ScanStats& stats) {
    const double mib = static_cast<double>(stats.bytesRead) / (1024.0 * 1024.0);
    const double mibPerSecond = stats.elapsedMs > 0.0 ? mib / (stats.elapsedMs / 1000.0) : 0.0;
    std::cout << "Candidates: " << stats.resultCount
              << " | Read: " << std::fixed << std::setprecision(2) << mib << " MiB"
              << " | Reads: " << stats.regionsRead
              << " | Time: " << std::setprecision(1) << stats.elapsedMs << " ms"
              << " | Throughput: " << std::setprecision(1) << mibPerSecond << " MiB/s";
    if (stats.truncated) {
        std::cout << " | TRUNCATED: safety cap reached";
    }
    if (stats.cancelled) {
        std::cout << " | CANCELLED: partial results";
    }
    std::cout << '\n';
}

void printUnknownRefinementState(const cw::EngineClientScanner& scanner, bool wasSnapshot) {
    if (!wasSnapshot) return;
    if (scanner.unknownSnapshotActive()) {
        std::cout << "Unknown refinement snapshot: " << scanner.candidateCount()
                  << " candidate(s) remain on temporary disk backing. Continue with Next Scan; "
                     "the 5,000,000 result cap did not discard them.\n";
    } else {
        std::cout << "Unknown refinement materialized " << scanner.results().size()
                  << " result(s) from the complete temporary snapshot.\n";
    }
}

void printCandidateCountsByType(const cw::EngineClientScanner& scanner) {
    const auto counts = scanner.candidateCountsByType();
    const auto types = cw::allValueTypes();
    std::cout << "Candidates by type:";
    for (std::size_t i = 0; i < counts.size() && i < types.size(); ++i) {
        std::cout << (i == 0 ? " " : " | ") << cw::valueTypeName(types[i]) << '=' << counts[i];
    }
    std::cout << '\n';
}

void printRefinementStep(const cw::ScanRefinementStep& step, std::size_t index) {
    const double reduction = step.beforeCount == 0
        ? 0.0
        : 100.0 * static_cast<double>(step.beforeCount - (std::min)(step.beforeCount, step.afterCount)) /
              static_cast<double>(step.beforeCount);
    std::cout << "Step " << index + 1 << ": " << scanModeName(step.mode)
              << " | " << step.beforeCount << " -> " << step.afterCount
              << " | removed " << std::fixed << std::setprecision(2) << reduction << "%"
              << " | " << std::setprecision(1) << step.elapsedMs << " ms"
              << std::defaultfloat << '\n';
}

void printLatestRefinement(const cw::EngineClientScanner& scanner) {
    const auto& history = scanner.refinementHistory();
    if (!history.empty()) printRefinementStep(history.back(), history.size() - 1);
}

void printRefinementHistory(const cw::EngineClientScanner& scanner) {
    const auto& history = scanner.refinementHistory();
    if (history.empty()) {
        std::cout << "No refinement steps recorded for this scan yet.\n";
        return;
    }
    std::cout << "Guided refinement history (" << history.size() << " step(s)):\n";
    for (std::size_t i = 0; i < history.size(); ++i) printRefinementStep(history[i], i);
}

const char* guidedGoalName(cw::GuidedGoal goal) {
    switch (goal) {
        case cw::GuidedGoal::Generic: return "generic";
        case cw::GuidedGoal::Money: return "money";
        case cw::GuidedGoal::Health: return "health";
        case cw::GuidedGoal::Ammo: return "ammo";
    }
    return "generic";
}

std::optional<cw::GuidedGoal> parseGuidedGoal(const std::string& text) {
    const auto value = lower(text);
    if (value == "generic" || value == "general") return cw::GuidedGoal::Generic;
    if (value == "money" || value == "cash") return cw::GuidedGoal::Money;
    if (value == "health" || value == "hp" || value == "life") return cw::GuidedGoal::Health;
    if (value == "ammo" || value == "ammunition") return cw::GuidedGoal::Ammo;
    return std::nullopt;
}

const char* wizardAction(cw::GuidedGoal goal, cw::ScanMode mode) {
    if (mode == cw::ScanMode::Unchanged) return "Leave the target value alone briefly, then use: guide unchanged";
    switch (goal) {
        case cw::GuidedGoal::Money:
            if (mode == cw::ScanMode::Decreased) return "Spend some money, then use: guide decreased";
            if (mode == cw::ScanMode::Increased) return "Gain some money, then use: guide increased";
            break;
        case cw::GuidedGoal::Health:
            if (mode == cw::ScanMode::Decreased) return "Take damage, then use: guide decreased";
            if (mode == cw::ScanMode::Increased) return "Heal, then use: guide increased";
            break;
        case cw::GuidedGoal::Ammo:
            if (mode == cw::ScanMode::Decreased) return "Fire or consume ammo, then use: guide decreased";
            if (mode == cw::ScanMode::Increased) return "Reload or gain ammo, then use: guide increased";
            break;
        case cw::GuidedGoal::Generic:
            break;
    }
    return "Change the target value, then use: guide changed";
}

void printWizardSuggestion(const cw::EngineClientScanner& scanner, cw::GuidedGoal goal) {
    const auto suggestion = scanner.guidedSuggestion(goal);
    if (!suggestion) {
        std::cout << "Wizard: start an Unknown scan first.\n";
        return;
    }
    std::cout << "Wizard [" << guidedGoalName(goal) << "]: "
              << wizardAction(goal, suggestion->recommendedMode) << ".\n"
              << "  candidates=" << suggestion->candidateCount
              << " | steps=" << suggestion->refinementDepth;
    if (suggestion->rankingAvailable) std::cout << " | ranking available";
    if (suggestion->inspectRecommended) std::cout << " | small set: inspect top ranked candidates";
    std::cout << '\n';
}

void printRankedResults(
    const cw::EngineClientScanner& scanner, std::size_t limit, cw::GuidedGoal goal) {
    if (scanner.unknownSnapshotActive()) {
        std::cout << "Ranking is available after the Unknown snapshot is materialized (<= 5,000,000 candidates).\n";
        return;
    }
    const auto ranked = scanner.rankedResults(limit, goal);
    const auto& results = scanner.results();
    if (ranked.empty()) {
        std::cout << "No materialized results to rank.\n";
        return;
    }
    std::cout << "Ranking V2 [" << guidedGoalName(goal)
              << "] (region/type/value/goal/isolation score; no results are discarded):\n";
    for (std::size_t rank = 0; rank < ranked.size(); ++rank) {
        const auto& item = ranked[rank];
        const auto& result = results[item.resultIndex];
        const auto current = scanner.readCurrent(result);
        std::cout << "[rank " << rank + 1 << "] original #" << item.resultIndex
                  << " score=" << item.score << " 0x"
                  << std::hex << std::uppercase << result.address << std::dec << std::nouppercase
                  << " [" << cw::valueTypeName(result.type) << "]"
                  << (item.privateMemory ? " private" : "")
                  << (item.writable ? " writable" : "")
                  << (item.executable ? " executable" : " data")
                  << " scan=";
        if (const auto captured = scanner.previousValue(result)) std::cout << cw::formatValue(*captured);
        else std::cout << "<unknown>";
        std::cout << " current=";
        if (current) std::cout << cw::formatValue(*current);
        else std::cout << "<unreadable>";
        std::cout << '\n';
    }
    std::cout << "Refinement depth: " << scanner.refinementHistory().size() << " step(s).\n";
}

std::optional<std::uintptr_t> parseAddress(const std::string& text) {
    try {
        std::size_t consumed = 0;
        const unsigned long long parsed = std::stoull(text, &consumed, 0);
        if (consumed != text.size() || parsed > std::numeric_limits<std::uintptr_t>::max()) {
            return std::nullopt;
        }
        return static_cast<std::uintptr_t>(parsed);
    } catch (...) {
        return std::nullopt;
    }
}


std::optional<bool> parseToggle(const std::string& text) {
    const auto value = lower(text);
    if (value == "on" || value == "true" || value == "1" || value == "yes") return true;
    if (value == "off" || value == "false" || value == "0" || value == "no") return false;
    return std::nullopt;
}

void printSettings(const cw::ScanOptions& options) {
    std::cout << "Scanner settings:\n"
              << "  alignment : "
              << (options.alignment == cw::AlignmentMode::Natural ? "natural" : "byte") << '\n'
              << "  writable  : " << (options.writableOnly ? "on" : "off") << '\n'
              << "  private   : " << (options.privateOnly ? "on" : "off") << '\n'
              << "  tolerance : " << options.floatTolerance << '\n'
              << "  range     : 0x" << std::hex << std::uppercase << options.minAddress
              << " - 0x" << options.maxAddress << std::dec << std::nouppercase << '\n';
}

void printPointerSettings(const cw::PointerScanOptions& options) {
    std::cout << "Pointer settings:\n"
              << "  alignment : ";
    if (options.alignment == 0) std::cout << "natural";
    else if (options.alignment == 1) std::cout << "byte";
    else std::cout << options.alignment;
    std::cout << '\n'
              << "  writable  : " << (options.writableOnly ? "on" : "off") << '\n'
              << "  private   : " << (options.privateOnly ? "on" : "off") << '\n'
              << "  branch    : " << options.maxCandidatesPerNode << '\n'
              << "  root      : " << (options.rootModuleName.empty() ? "any module" : wideToUtf8(options.rootModuleName)) << '\n';
}

std::atomic<cw::EngineClientScanner*> gActiveScanner{nullptr};
std::atomic<cw::EngineClientAobScanner*> gActiveAobScanner{nullptr};
std::atomic<cw::EngineClientPointerScanner*> gActivePointerScanner{nullptr};

BOOL WINAPI consoleControlHandler(DWORD eventType) {
    if (eventType != CTRL_C_EVENT && eventType != CTRL_BREAK_EVENT) return FALSE;
    if (auto* scanner = gActiveScanner.load(std::memory_order_relaxed)) {
        scanner->requestCancel();
        return TRUE;
    }
    if (auto* scanner = gActiveAobScanner.load(std::memory_order_relaxed)) {
        scanner->requestCancel();
        return TRUE;
    }
    if (auto* scanner = gActivePointerScanner.load(std::memory_order_relaxed)) {
        scanner->requestCancel();
        return TRUE;
    }
    return FALSE;
}

template <typename Fn>
cw::ScanStats runScanWithUi(cw::EngineClientScanner& scanner, Fn&& fn) {
    auto lastPrint = std::chrono::steady_clock::now();
    bool printedProgress = false;
    scanner.setProgressCallback([&](const cw::ScanProgress& progress) {
        const auto now = std::chrono::steady_clock::now();
        if (now - lastPrint < std::chrono::milliseconds(250)) return;
        lastPrint = now;
        printedProgress = true;
        const double mib = static_cast<double>(progress.bytesRead) / (1024.0 * 1024.0);
        std::cout << "\rRead " << std::fixed << std::setprecision(1) << mib
                  << " MiB | current candidates: " << progress.resultCount
                  << " | Ctrl+C cancels" << std::flush;
    });

    gActiveScanner.store(&scanner, std::memory_order_relaxed);
    const auto stats = fn();
    gActiveScanner.store(nullptr, std::memory_order_relaxed);
    scanner.setProgressCallback({});

    if (printedProgress) {
        std::cout << "\r" << std::string(96, ' ') << "\r";
    }
    return stats;
}

template <typename Fn>
cw::ScanStats runAobScanWithUi(cw::EngineClientAobScanner& scanner, Fn&& fn) {
    auto lastPrint = std::chrono::steady_clock::now();
    bool printedProgress = false;
    scanner.setProgressCallback([&](const cw::ScanProgress& progress) {
        const auto now = std::chrono::steady_clock::now();
        if (now - lastPrint < std::chrono::milliseconds(250)) return;
        lastPrint = now;
        printedProgress = true;
        const double mib = static_cast<double>(progress.bytesRead) / (1024.0 * 1024.0);
        std::cout << "\rAOB read " << std::fixed << std::setprecision(1) << mib
                  << " MiB | matches: " << progress.resultCount
                  << " | Ctrl+C cancels" << std::flush;
    });

    gActiveAobScanner.store(&scanner, std::memory_order_relaxed);
    const auto stats = fn();
    gActiveAobScanner.store(nullptr, std::memory_order_relaxed);
    scanner.setProgressCallback({});
    if (printedProgress) std::cout << "\r" << std::string(96, ' ') << "\r";
    return stats;
}

void printPointerStats(const cw::PointerScanStats& stats) {
    const double mib = static_cast<double>(stats.bytesRead) / (1024.0 * 1024.0);
    const double mibPerSecond = stats.indexMs > 0.0 ? mib / (stats.indexMs / 1000.0) : 0.0;
    std::cout << "Pointer size: " << stats.pointerSize * 8 << "-bit"
              << " | Index: " << stats.indexEntries
              << " | Chains: " << stats.chains
              << " | Read: " << std::fixed << std::setprecision(2) << mib << " MiB"
              << " | Regions: " << stats.regionsRead
              << " | Index time: " << std::setprecision(1) << stats.indexMs << " ms"
              << " | Index throughput: " << mibPerSecond << " MiB/s"
              << " | Search time: " << stats.searchMs << " ms";
    if (stats.indexTruncated) std::cout << " | INDEX TRUNCATED";
    if (stats.chainsTruncated) std::cout << " | SEARCH TRUNCATED";
    if (stats.cancelled) std::cout << " | CANCELLED";
    std::cout << '\n';
}

cw::PointerScanStats runPointerScanWithUi(
    cw::EngineClientPointerScanner& scanner,
    std::uintptr_t target,
    const cw::PointerScanOptions& options)
{
    auto lastPrint = std::chrono::steady_clock::now();
    bool printedProgress = false;
    scanner.setProgressCallback([&](const cw::PointerProgress& progress) {
        const auto now = std::chrono::steady_clock::now();
        if (now - lastPrint < std::chrono::milliseconds(250)) return;
        lastPrint = now;
        printedProgress = true;
        const double mib = static_cast<double>(progress.bytesRead) / (1024.0 * 1024.0);
        std::cout << "\rPointer index: " << std::fixed << std::setprecision(1) << mib
                  << " MiB read | " << progress.indexEntries << " pointer candidates | Ctrl+C cancels"
                  << std::flush;
    });

    gActivePointerScanner.store(&scanner, std::memory_order_relaxed);
    const auto stats = scanner.scan(target, options);
    gActivePointerScanner.store(nullptr, std::memory_order_relaxed);
    scanner.setProgressCallback({});
    if (printedProgress) std::cout << "\r" << std::string(110, ' ') << "\r";
    return stats;
}

cw::PointerScanStats runPointerCaptureWithUi(
    cw::EngineClientPointerScanner& scanner,
    const cw::PointerScanOptions& options)
{
    auto lastPrint = std::chrono::steady_clock::now();
    bool printedProgress = false;
    scanner.setProgressCallback([&](const cw::PointerProgress& progress) {
        const auto now = std::chrono::steady_clock::now();
        if (now - lastPrint < std::chrono::milliseconds(250)) return;
        lastPrint = now;
        printedProgress = true;
        const double mib = static_cast<double>(progress.bytesRead) / (1024.0 * 1024.0);
        std::cout << "\rPointer map: " << std::fixed << std::setprecision(1) << mib
                  << " MiB read | " << progress.indexEntries << " pointer candidates | Ctrl+C cancels"
                  << std::flush;
    });

    gActivePointerScanner.store(&scanner, std::memory_order_relaxed);
    const auto stats = scanner.captureIndex(options);
    gActivePointerScanner.store(nullptr, std::memory_order_relaxed);
    scanner.setProgressCallback({});
    if (printedProgress) std::cout << "\r" << std::string(110, ' ') << "\r";
    return stats;
}

bool refreshPointerContext(cw::EngineFrontendSession& engine, bool printErrors = true) {
    std::string error;
    if (engine.refreshPointerContext(error)) return true;
    if (printErrors && !error.empty()) {
        std::cout << "Could not refresh pointer context: " << error << '\n';
    }
    return false;
}

void printPointerChain(const cw::PointerChain& chain, std::size_t index) {
    std::cout << "[P#" << index << "] " << wideToUtf8(chain.moduleName)
              << "+0x" << std::hex << std::uppercase << chain.rootOffset;
    for (const auto offset : chain.offsets) {
        if (offset < 0) {
            const auto magnitude = static_cast<std::uint64_t>(-(offset + 1)) + 1u;
            std::cout << " -> -0x" << magnitude;
        } else {
            std::cout << " -> +0x" << static_cast<std::uint64_t>(offset);
        }
    }
    std::cout << std::dec << std::nouppercase << '\n';
}

std::vector<cw::PointerModule> pointerModulesFromProcess(const std::vector<cw::ModuleInfo>& modules) {
    std::vector<cw::PointerModule> out;
    out.reserve(modules.size());
    for (const auto& module : modules) {
        out.push_back(cw::PointerModule{module.base, module.size, module.name});
    }
    return out;
}

std::optional<std::uintptr_t> resolveTarget(
    const std::string& token,
    const cw::EngineClientScanner& scanner,
    std::string& error)
{
    if (!token.empty() && token.front() == '#') {
        if (!scanner.hasScan()) {
            error = "No active scan for a result index.";
            return std::nullopt;
        }
        if (scanner.unknownSnapshotActive()) {
            error = "Unknown scan is still a snapshot. Run a Next Scan before using #result indexes.";
            return std::nullopt;
        }
        try {
            const std::size_t index = static_cast<std::size_t>(std::stoull(token.substr(1)));
            if (index >= scanner.results().size()) {
                error = "Result index out of range.";
                return std::nullopt;
            }
            return scanner.results()[index].address;
        } catch (...) {
            error = "Invalid result index. Use #0, #1, ...";
            return std::nullopt;
        }
    }

    if (auto address = parseAddress(token)) return address;
    error = "Invalid target. Use #result-index or a numeric address such as 0x1234.";
    return std::nullopt;
}

struct TypedTarget {
    std::uintptr_t address{};
    cw::ValueType type{cw::ValueType::Int32};
};

std::optional<TypedTarget> resolveTypedTarget(
    const std::string& token,
    const cw::EngineClientScanner& scanner,
    std::string& error)
{
    if (!scanner.hasScan()) {
        error = "A scan is required so Cheat Wizard knows the value type.";
        return std::nullopt;
    }
    if (!token.empty() && token.front() == '#') {
        if (scanner.unknownSnapshotActive()) {
            error = "Unknown scan is still a snapshot. Run a Next Scan first.";
            return std::nullopt;
        }
        try {
            const auto index = static_cast<std::size_t>(std::stoull(token.substr(1)));
            if (index >= scanner.results().size()) {
                error = "Result index out of range.";
                return std::nullopt;
            }
            const auto& result = scanner.results()[index];
            return TypedTarget{result.address, result.type};
        } catch (...) {
            error = "Invalid result index. Use #0, #1, ...";
            return std::nullopt;
        }
    }
    if (scanner.mixedScanActive()) {
        error = "Raw addresses are ambiguous after 'scan all'. Use a #result index or start a typed scan.";
        return std::nullopt;
    }
    if (auto address = parseAddress(token)) return TypedTarget{*address, scanner.valueType()};
    error = "Invalid target. Use #result-index or a numeric address such as 0x1234.";
    return std::nullopt;
}


} // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(consoleControlHandler, TRUE);


    cw::EngineFrontendSession engine;
    std::string engineStartError;
    if (!engine.start(engineStartError)) {
        std::cerr << "Engine startup failed: " << engineStartError << '\n';
        return 2;
    }
    auto& scanner = engine.scanner();
    auto& aobScanner = engine.aobScanner();
    auto& freezer = engine.freezer();
    auto& pointerScanner = engine.pointerScanner();
    cw::GuidedGoal guidedGoal = cw::GuidedGoal::Generic;
    cw::PointerScanOptions pointerDefaults;
    std::vector<cw::PointerMapData> pointerMaps;
    std::vector<std::string> pointerMapNames;
    cw::AobSearchScope aobScope = cw::AobSearchScope::Memory;
    std::string aobModuleName;
    std::optional<cw::PointerProfileData> activePointerProfile;

    auto resolveActiveProfile = [&]() -> std::optional<std::tuple<std::uintptr_t, std::size_t, std::size_t>> {
        if (!engine.attached() || !activePointerProfile || pointerScanner.chains().empty()) return std::nullopt;
        if (!refreshPointerContext(engine)) return std::nullopt;
        if (pointerScanner.chainPointerSize() != 0 && pointerScanner.chainPointerSize() != pointerScanner.pointerSize()) return std::nullopt;
        std::vector<std::uintptr_t> addresses;
        addresses.reserve(pointerScanner.chains().size());
        for (std::size_t i = 0; i < pointerScanner.chains().size(); ++i) {
            if (const auto resolved = pointerScanner.resolve(i)) addresses.push_back(*resolved);
        }
        if (addresses.empty()) return std::nullopt;
        std::sort(addresses.begin(), addresses.end());
        std::uintptr_t bestAddress = addresses.front();
        std::size_t bestCount = 1;
        std::size_t run = 1;
        for (std::size_t i = 1; i < addresses.size(); ++i) {
            if (addresses[i] == addresses[i - 1]) {
                ++run;
            } else {
                if (run > bestCount) { bestCount = run; bestAddress = addresses[i - 1]; }
                run = 1;
            }
        }
        if (run > bestCount) { bestCount = run; bestAddress = addresses.back(); }
        return std::tuple<std::uintptr_t, std::size_t, std::size_t>{bestAddress, bestCount, addresses.size()};
    };

    std::cout << "Cheat Wizard v" << kVersion << " - memory scanner + write + freeze\n";
    std::cout << "Type 'help' for commands.\n\n";

    std::string line;
    while (true) {
        std::cout << "cw> ";
        if (!std::getline(std::cin, line)) break;
        const auto args = split(line);
        if (args.empty()) continue;
        const std::string command = lower(args[0]);

        if (command == "quit" || command == "exit") break;
        if (command == "help" || command == "?") {
            printHelp();
            continue;
        }

        if (command == "version") {
            std::cout << "Cheat Wizard v" << kVersion << " (Windows x64 CLI milestone)\n";
            continue;
        }

        if (command == "processes" || command == "ps") {
            const auto processes = engine.listProcesses();
            if (processes.empty()) {
                std::cout << "No processes found (or snapshot failed).\n";
                continue;
            }
            std::cout << "PID        Process\n";
            std::cout << "---------- ----------------------------------------\n";
            for (const auto& p : processes) {
                std::cout << std::left << std::setw(10) << p.pid << ' ' << wideToUtf8(p.name) << '\n';
            }
            std::cout << std::right;
            continue;
        }

        if (command == "attach-name") {
            if (args.size() != 2) {
                std::cout << "Usage: attach-name <exe-name>\n";
                continue;
            }

            std::wstring name(args[1].begin(), args[1].end());
            std::string error;
            if (!engine.attachByName(name, error)) {
                std::cout << "Attach failed: " << error << "\n";
                continue;
            }
            std::cout << "Attached to PID " << engine.pid() << " (read/write).\n";
            std::string pointerError;
            const auto pointerSize = engine.targetPointerSize(pointerError);
            if (pointerSize) std::cout << "Target pointer width: " << pointerSize * 8 << "-bit.\n";
            continue;
        }

        if (command == "attach") {
            if (args.size() != 2) {
                std::cout << "Usage: attach <pid>\n";
                continue;
            }

            DWORD pid{};
            try {
                const unsigned long parsed = std::stoul(args[1]);
                if (parsed > std::numeric_limits<DWORD>::max()) throw std::out_of_range("pid");
                pid = static_cast<DWORD>(parsed);
            } catch (...) {
                std::cout << "Invalid PID.\n";
                continue;
            }

            std::string error;
            if (!engine.attach(pid, error)) {
                std::cout << "Attach failed: " << error << "\n";
                continue;
            }
            std::cout << "Attached to PID " << pid << " (read/write).\n";
            std::string pointerError;
            const auto pointerSize = engine.targetPointerSize(pointerError);
            if (pointerSize) std::cout << "Target pointer width: " << pointerSize * 8 << "-bit.\n";
            continue;
        }

        if (command == "detach") {
            engine.detach();
            std::cout << "Detached. Freeze jobs cleared; stored pointer chains were kept for rescan.\n";
            continue;
        }

        if (command == "clear") {
            engine.clearScans();
            std::cout << "Value scan and AOB results cleared. Active freezes were kept.\n";
            continue;
        }

        if (command == "settings" || command == "config") {
            if (args.size() == 1) {
                printSettings(scanner.options());
                continue;
            }

            auto options = scanner.options();
            bool valid = true;

            if (args.size() == 3 && lower(args[1]) == "alignment") {
                const auto value = lower(args[2]);
                if (value == "natural" || value == "aligned") {
                    options.alignment = cw::AlignmentMode::Natural;
                } else if (value == "byte" || value == "1" || value == "unaligned") {
                    options.alignment = cw::AlignmentMode::Byte;
                } else {
                    valid = false;
                }
            } else if (args.size() == 3 && lower(args[1]) == "writable") {
                const auto value = parseToggle(args[2]);
                if (!value) valid = false;
                else options.writableOnly = *value;
            } else if (args.size() == 3 && lower(args[1]) == "private") {
                const auto value = parseToggle(args[2]);
                if (!value) valid = false;
                else options.privateOnly = *value;
            } else if (args.size() == 3 && lower(args[1]) == "tolerance") {
                try {
                    std::size_t consumed = 0;
                    const double value = std::stod(args[2], &consumed);
                    if (consumed != args[2].size() || !std::isfinite(value) || value < 0.0) {
                        valid = false;
                    } else {
                        options.floatTolerance = value;
                    }
                } catch (...) {
                    valid = false;
                }
            } else if (args.size() == 3 && lower(args[1]) == "range" && lower(args[2]) == "all") {
                options.minAddress = 0;
                options.maxAddress = (std::numeric_limits<std::uintptr_t>::max)();
            } else if (args.size() == 4 && lower(args[1]) == "range") {
                const auto minAddress = parseAddress(args[2]);
                const auto maxAddress = parseAddress(args[3]);
                if (!minAddress || !maxAddress || *minAddress > *maxAddress) {
                    valid = false;
                } else {
                    options.minAddress = *minAddress;
                    options.maxAddress = *maxAddress;
                }
            } else {
                valid = false;
            }

            if (!valid) {
                std::cout << "Invalid settings command. Type 'help' for syntax.\n";
                continue;
            }

            scanner.setOptions(options);
            aobScanner.setOptions(options);
            aobScanner.clear();
            std::cout << "Scanner settings updated. Active value/AOB scans cleared; freeze jobs were kept.\n";
            printSettings(scanner.options());
            continue;
        }

        if (command == "scan") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() != 3) {
                std::cout << "Usage: scan <byte|int16|int32|int64|float|double|all> <value|unknown|unknown-smart>\n";
                continue;
            }

            if (lower(args[1]) == "all") {
                const auto scanToken = lower(args[2]);
                if (scanToken == "unknown" || args[2] == "?" || scanToken == "unknown-smart") {
                    const bool smart = scanToken == "unknown-smart";
                    std::cout << "Capturing " << (smart ? "Smart " : "")
                              << "Unknown Initial Value snapshot for all numeric types";
                    if (smart) std::cout << " (writable MEM_PRIVATE only)";
                    std::cout << "...\n";
                    printStats(runScanWithUi(scanner, [&] {
                        return smart ? scanner.firstScanAllUnknownSmart() : scanner.firstScanAllUnknown();
                    }));
                    if (scanner.unknownSnapshotActive()) {
                        std::cout << "Mixed snapshot active with " << scanner.candidateCount()
                                  << " candidate(s) on temporary disk backing. Continue refining with Next Scan; "
                                     "candidates above 5,000,000 are preserved.\n";
                        printCandidateCountsByType(scanner);
                    }
                    continue;
                }
                const auto compatible = cw::parseAllCompatibleValues(args[2]);
                if (compatible.empty()) {
                    std::cout << "Value is not valid for any supported numeric type.\n";
                    continue;
                }
                std::cout << "Scanning all compatible numeric types for exact value " << args[2]
                          << " in one memory pass (" << compatible.size() << " type(s))...\n";
                printStats(runScanWithUi(scanner, [&] { return scanner.firstScanAllExact(args[2]); }));
                continue;
            }

            const auto type = cw::parseValueType(args[1]);
            if (!type) {
                std::cout << "Unknown value type.\n";
                continue;
            }

            const auto scanToken = lower(args[2]);
            if (scanToken == "unknown" || args[2] == "?" || scanToken == "unknown-smart") {
                const bool smart = scanToken == "unknown-smart";
                std::cout << "Capturing " << (smart ? "Smart " : "") << "Unknown Initial Value snapshot for "
                          << cw::valueTypeName(*type);
                if (smart) std::cout << " (writable MEM_PRIVATE only)";
                std::cout << "...\n";
                printStats(runScanWithUi(scanner, [&] {
                    return smart ? scanner.firstScanUnknownSmart(*type) : scanner.firstScanUnknown(*type);
                }));
                if (scanner.unknownSnapshotActive()) {
                    std::cout << "Snapshot active with " << scanner.candidateCount()
                              << " candidate(s) on temporary disk backing. Continue refining with Next Scan; "
                                 "candidates above 5,000,000 are preserved.\n";
                }
                continue;
            }

            const auto value = cw::parseValue(*type, args[2]);
            if (!value) {
                std::cout << "Invalid value for " << cw::valueTypeName(*type) << ".\n";
                continue;
            }

            std::cout << "Scanning " << cw::valueTypeName(*type)
                      << " for exact value " << cw::formatValue(*value) << "...\n";
            printStats(runScanWithUi(scanner, [&] { return scanner.firstScan(*type, *value); }));
            continue;
        }

        if (command == "types") {
            if (!scanner.hasScan() || !scanner.mixedScanActive()) {
                std::cout << "The current scan is not a mixed-type scan.\n";
                continue;
            }
            if (args.size() == 1) {
                printCandidateCountsByType(scanner);
                continue;
            }
            if (args.size() < 3 || lower(args[1]) != "off") {
                std::cout << "Usage: types | types off <byte|int16|int32|int64|float|double> [type...]\n";
                continue;
            }
            for (std::size_t i = 2; i < args.size(); ++i) {
                const auto type = cw::parseValueType(args[i]);
                if (!type) {
                    std::cout << "Unknown value type: " << args[i] << '\n';
                    continue;
                }
                std::cout << cw::valueTypeName(*type) << ": "
                          << (scanner.disableMixedType(*type) ? "disabled" : "already empty/disabled") << '\n';
            }
            printCandidateCountsByType(scanner);
            if (scanner.unknownSnapshotActive() && scanner.candidateCount() <= 5'000'000) {
                std::cout << "Candidate count is now within the materialization cap; run Next Scan once to materialize it.\n";
            }
            continue;
        }

        if (command == "next" || command == "guide") {
            const bool guided = command == "guide";
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (!scanner.hasScan()) {
                std::cout << "Run a first scan first.\n";
                continue;
            }
            if (args.size() < 2 || args.size() > 3) {
                std::cout << "Usage: next <value> | next <changed|unchanged|increased|decreased> | "
                             "next <exact|bigger|smaller> <value>\n";
                continue;
            }

            cw::ScanMode mode = cw::ScanMode::Exact;
            std::optional<std::string> wantedText;

            if (args.size() == 2) {
                if (const auto parsedMode = parseScanMode(args[1]); parsedMode && !cw::scanModeNeedsValue(*parsedMode)) {
                    mode = *parsedMode;
                } else {
                    wantedText = args[1];
                }
            } else {
                const auto parsedMode = parseScanMode(args[1]);
                if (!parsedMode || !cw::scanModeNeedsValue(*parsedMode)) {
                    std::cout << "This form requires exact/bigger/smaller plus a value.\n";
                    continue;
                }
                mode = *parsedMode;
                wantedText = args[2];
            }

            if (guided && (args.size() != 2 ||
                           (mode != cw::ScanMode::Changed &&
                            mode != cw::ScanMode::Unchanged &&
                            mode != cw::ScanMode::Increased &&
                            mode != cw::ScanMode::Decreased))) {
                std::cout << "Usage: guide <changed|unchanged|increased|decreased>\n";
                continue;
            }

            if (scanner.mixedScanActive()) {
                if (cw::scanModeNeedsValue(mode)) {
                    if (!wantedText || cw::parseAllCompatibleValues(*wantedText).empty()) {
                        std::cout << "Value is not valid for any type still supported by this mixed scan.\n";
                        continue;
                    }
                }
                std::cout << "Next Scan (mixed types): " << scanModeName(mode);
                if (wantedText) std::cout << " " << *wantedText;
                std::cout << "...\n";
                const bool wasSnapshot = scanner.unknownSnapshotActive();
                printStats(runScanWithUi(scanner, [&] { return scanner.nextScanMixed(mode, wantedText); }));
                printUnknownRefinementState(scanner, wasSnapshot);
                printCandidateCountsByType(scanner);
                printLatestRefinement(scanner);
                if (guided) printWizardSuggestion(scanner, guidedGoal);
                continue;
            }

            std::optional<cw::Value> wanted;
            if (wantedText) {
                wanted = cw::parseValue(scanner.valueType(), *wantedText);
                if (!wanted) {
                    std::cout << "Invalid value for " << cw::valueTypeName(scanner.valueType()) << ".\n";
                    continue;
                }
            }

            std::cout << "Next Scan: " << scanModeName(mode);
            if (wanted) std::cout << " " << cw::formatValue(*wanted);
            std::cout << "...\n";
            const bool wasSnapshot = scanner.unknownSnapshotActive();
            printStats(runScanWithUi(scanner, [&] { return scanner.nextScan(mode, wanted); }));
            printUnknownRefinementState(scanner, wasSnapshot);
            printLatestRefinement(scanner);
            if (guided) printWizardSuggestion(scanner, guidedGoal);
            continue;
        }

        if (command == "wizard") {
            if (args.size() > 2) {
                std::cout << "Usage: wizard [generic|money|health|ammo]\n";
                continue;
            }
            if (args.size() == 2) {
                const auto parsed = parseGuidedGoal(args[1]);
                if (!parsed) {
                    std::cout << "Usage: wizard [generic|money|health|ammo]\n";
                    continue;
                }
                guidedGoal = *parsed;
            }
            std::cout << "Wizard goal: " << guidedGoalName(guidedGoal) << '\n';
            printWizardSuggestion(scanner, guidedGoal);
            continue;
        }

        if (command == "history") {
            if (!scanner.hasScan()) {
                std::cout << "No active scan.\n";
                continue;
            }
            printRefinementHistory(scanner);
            continue;
        }

        if (command == "ranked" || command == "rank") {
            if (!scanner.hasScan()) {
                std::cout << "No active scan.\n";
                continue;
            }
            std::size_t limit = 50;
            if (args.size() >= 2) {
                try {
                    limit = static_cast<std::size_t>(std::stoull(args[1]));
                } catch (...) {
                    std::cout << "Invalid limit.\n";
                    continue;
                }
            }
            if (args.size() > 2 || limit == 0 || limit > 5000) {
                std::cout << "Usage: ranked [1..5000]\n";
                continue;
            }
            printRankedResults(scanner, limit, guidedGoal);
            continue;
        }

        if (command == "results") {
            if (!scanner.hasScan()) {
                std::cout << "No active scan.\n";
                continue;
            }
            if (scanner.unknownSnapshotActive()) {
                std::cout << "Unknown scan snapshot/refinement has " << scanner.candidateCount()
                          << " candidate(s) but no materialized result list yet.\n"
                             "The snapshot is backed by temporary disk storage. Keep using Next Scan until the candidate count is at most 5,000,000; candidates above that cap are preserved.\n";
                continue;
            }

            std::size_t limit = 50;
            if (args.size() >= 2) {
                try {
                    limit = static_cast<std::size_t>(std::stoull(args[1]));
                } catch (...) {
                    std::cout << "Invalid limit.\n";
                    continue;
                }
            }

            const auto& results = scanner.results();
            const std::size_t count = (std::min)(limit, results.size());
            for (std::size_t i = 0; i < count; ++i) {
                const auto& result = results[i];
                const auto current = scanner.readCurrent(result);
                const auto previous = scanner.previousValue(result);
                std::cout << "[#" << i << "] 0x"
                          << std::hex << std::uppercase << result.address
                          << std::dec << std::nouppercase;
                if (scanner.mixedScanActive()) {
                    std::cout << " [" << cw::valueTypeName(result.type) << "]";
                }
                std::cout << " current=";
                if (current) std::cout << cw::formatValue(*current);
                else std::cout << "<unreadable>";
                std::cout << " last=";
                if (previous) std::cout << cw::formatValue(*previous);
                else std::cout << "<?>";
                std::cout << '\n';
            }
            if (results.size() > count) {
                std::cout << "... " << (results.size() - count) << " more result(s).\n";
            }
            std::cout << "Total: " << results.size() << '\n';
            continue;
        }

        if (command == "scan-save" || command == "ssave") {
            if (args.size() != 2) {
                std::cout << "Usage: scan-save <file.cwscan>\n";
                continue;
            }
            if (!scanner.hasScan()) {
                std::cout << "No active value scan to save.\n";
                continue;
            }
            if (scanner.unknownSnapshotActive()) {
                std::cout << "Unknown-initial raw snapshots are not persisted. Run a Next Scan first to materialize results.\n";
                continue;
            }

            cw::ScanSessionData session;
            session.sourcePid = engine.attached() ? static_cast<std::uint64_t>(engine.pid()) : 0;
            session.mixed = scanner.mixedScanActive();
            session.primaryType = scanner.valueType();
            session.options = scanner.options();
            session.results = scanner.results();

            std::string error;
            if (!cw::saveScanSession(args[1], session, error)) {
                std::cout << "Scan save failed: " << error << '\n';
                continue;
            }
            std::cout << "Saved " << session.results.size() << " scan result(s) to '" << args[1]
                      << "'" << (session.sourcePid ? " with source PID metadata" : "") << ".\n";
            continue;
        }

        if (command == "scan-load" || command == "sload") {
            if (args.size() < 2 || args.size() > 3 ||
                (args.size() == 3 && lower(args[2]) != "force")) {
                std::cout << "Usage: scan-load <file.cwscan> [force]\n";
                continue;
            }
            if (!engine.attached()) {
                std::cout << "Attach to the process that owns these addresses before loading the scan session.\n";
                continue;
            }

            cw::ScanSessionData session;
            std::string error;
            if (!cw::loadScanSession(args[1], session, error)) {
                std::cout << "Scan load failed: " << error << '\n';
                continue;
            }
            const bool force = args.size() == 3;
            const auto currentPid = static_cast<std::uint64_t>(engine.pid());
            if (!force && session.sourcePid != 0 && session.sourcePid != currentPid) {
                std::cout << "Refusing scan session: it was saved from PID " << session.sourcePid
                          << " but the attached process is PID " << currentPid << ".\n"
                             "Use 'scan-load " << args[1] << " force' only if you intentionally want to test stale addresses.\n";
                continue;
            }

            aobScanner.setOptions(session.options); // keep shared scanner settings coherent; clears old AOB matches
            if (!scanner.restoreMaterializedScan(
                    session.primaryType, session.mixed, session.options, std::move(session.results))) {
                std::cout << "Scan load failed: inconsistent session metadata.\n";
                continue;
            }
            std::cout << "Loaded " << scanner.results().size() << " scan result(s) from '" << args[1] << "'";
            if (force && session.sourcePid != 0 && session.sourcePid != currentPid) {
                std::cout << " [FORCED PID MISMATCH]";
            }
            std::cout << ". AOB matches were cleared because scanner settings were restored.\n";
            continue;
        }

        if (command == "watch") {
            if (!engine.attached() || !scanner.hasScan()) {
                std::cout << "Attach and start a scan first so the value type is known.\n";
                continue;
            }
            if (args.size() < 2 || args.size() > 4) {
                std::cout << "Usage: watch <#result-index|address> [count] [interval_ms]\n";
                continue;
            }
            std::string targetError;
            const auto typedTarget = resolveTypedTarget(args[1], scanner, targetError);
            if (!typedTarget) {
                std::cout << targetError << '\n';
                continue;
            }

            std::size_t count = 20;
            std::uint32_t intervalMs = 250;
            try {
                if (args.size() >= 3) count = static_cast<std::size_t>(std::stoull(args[2]));
                if (args.size() >= 4) intervalMs = static_cast<std::uint32_t>(std::stoul(args[3]));
            } catch (...) {
                std::cout << "Invalid count or interval.\n";
                continue;
            }
            count = (std::max)(std::size_t{1}, (std::min)(count, std::size_t{10'000}));
            intervalMs = (std::max)(10u, (std::min)(intervalMs, 60'000u));

            std::cout << "Watching 0x" << std::hex << std::uppercase << typedTarget->address
                      << std::dec << std::nouppercase << " as "
                      << cw::valueTypeName(typedTarget->type) << " for " << count
                      << " sample(s), every " << intervalMs << " ms.\n";
            for (std::size_t sample = 0; sample < count; ++sample) {
                cw::ScanResult temp{typedTarget->address, 0, typedTarget->type};
                const auto value = scanner.readCurrent(temp);
                std::cout << '[' << sample << "] ";
                if (value) std::cout << cw::formatValue(*value);
                else std::cout << "<unreadable>";
                std::cout << '\n';
                if (sample + 1 < count) std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            }
            continue;
        }

        if (command == "inspect") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() != 2) {
                std::cout << "Usage: inspect <#result-index|address>\n";
                continue;
            }
            std::string targetError;
            const auto address = resolveTarget(args[1], scanner, targetError);
            if (!address) {
                std::cout << targetError << '\n';
                continue;
            }

            std::array<std::byte, 8> bytes{};
            std::size_t bytesRead = 0;
            DWORD readError = ERROR_SUCCESS;
            const bool ok = engine.readBytes(*address, bytes.data(), bytes.size(), bytesRead, readError);
            if ((!ok && bytesRead == 0) || bytesRead == 0) {
                std::cout << "Read failed at 0x" << std::hex << std::uppercase << *address
                          << std::dec << std::nouppercase << ": "
                          << cw::win32ErrorMessage(readError) << '\n';
                continue;
            }

            std::cout << "Address: 0x" << std::hex << std::uppercase << *address
                      << std::dec << std::nouppercase << " | bytes read: " << bytesRead << "\nRaw: ";
            for (std::size_t i = 0; i < bytesRead; ++i) {
                const auto byte = static_cast<unsigned int>(std::to_integer<unsigned char>(bytes[i]));
                std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << byte;
                if (i + 1 < bytesRead) std::cout << ' ';
            }
            std::cout << std::dec << std::nouppercase << std::setfill(' ') << '\n';

            const auto printTyped = [&](const char* name, auto dummy) {
                using T = decltype(dummy);
                if (bytesRead < sizeof(T)) return;
                T value{};
                std::memcpy(&value, bytes.data(), sizeof(T));
                std::cout << std::left << std::setw(8) << name << " : ";
                if constexpr (std::is_same_v<T, std::uint8_t>) {
                    std::cout << static_cast<unsigned int>(value);
                } else if constexpr (std::is_floating_point_v<T>) {
                    std::cout << std::setprecision(std::numeric_limits<T>::max_digits10) << value;
                } else {
                    std::cout << value;
                }
                std::cout << '\n';
            };
            printTyped("uint8", std::uint8_t{});
            printTyped("int8", std::int8_t{});
            printTyped("uint16", std::uint16_t{});
            printTyped("int16", std::int16_t{});
            printTyped("uint32", std::uint32_t{});
            printTyped("int32", std::int32_t{});
            printTyped("uint64", std::uint64_t{});
            printTyped("int64", std::int64_t{});
            printTyped("float", float{});
            printTyped("double", double{});
            std::cout << std::right;
            continue;
        }

        if (command == "read-at") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() != 3) {
                std::cout << "Usage: read-at <address> <type>\n";
                continue;
            }
            const auto address = parseAddress(args[1]);
            const auto type = cw::parseValueType(args[2]);
            if (!address || !type) {
                std::cout << "Invalid address or type.\n";
                continue;
            }
            const auto value = engine.readValue(*address, *type);
            if (!value) {
                std::cout << "Read failed at 0x" << std::hex << std::uppercase << *address
                          << std::dec << std::nouppercase << ".\n";
                continue;
            }
            std::cout << "0x" << std::hex << std::uppercase << *address
                      << std::dec << std::nouppercase << " [" << cw::valueTypeName(*type)
                      << "] = " << cw::formatValue(*value) << '\n';
            continue;
        }

        if (command == "write-at") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() != 4) {
                std::cout << "Usage: write-at <address> <type> <value>\n";
                continue;
            }
            const auto address = parseAddress(args[1]);
            const auto type = cw::parseValueType(args[2]);
            if (!address || !type) {
                std::cout << "Invalid address or type.\n";
                continue;
            }
            const auto value = cw::parseValue(*type, args[3]);
            if (!value) {
                std::cout << "Invalid value for " << cw::valueTypeName(*type) << ".\n";
                continue;
            }
            const auto result = engine.writeValue(*address, *value);
            if (!result.ok) {
                std::cout << "Write failed: " << cw::win32ErrorMessage(result.error) << '\n';
                continue;
            }
            std::cout << "Wrote " << cw::formatValue(*value) << " as "
                      << cw::valueTypeName(*type) << " to 0x"
                      << std::hex << std::uppercase << *address << std::dec << std::nouppercase << ".\n";
            continue;
        }

        if (command == "freeze-at") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() != 4 && args.size() != 5) {
                std::cout << "Usage: freeze-at <address> <type> <value> [interval_ms]\n";
                continue;
            }
            const auto address = parseAddress(args[1]);
            const auto type = cw::parseValueType(args[2]);
            if (!address || !type) {
                std::cout << "Invalid address or type.\n";
                continue;
            }
            const auto value = cw::parseValue(*type, args[3]);
            if (!value) {
                std::cout << "Invalid value for " << cw::valueTypeName(*type) << ".\n";
                continue;
            }
            std::uint32_t intervalMs = 50;
            if (args.size() == 5) {
                try {
                    const auto parsed = std::stoul(args[4]);
                    if (parsed > std::numeric_limits<std::uint32_t>::max()) throw std::out_of_range("interval");
                    intervalMs = static_cast<std::uint32_t>(parsed);
                } catch (...) {
                    std::cout << "Invalid interval.\n";
                    continue;
                }
            }
            const auto existingJobs = freezer.list();
            const auto duplicate = std::find_if(existingJobs.begin(), existingJobs.end(),
                [&](const cw::FreezeSnapshot& job) { return job.address == *address; });
            if (duplicate != existingJobs.end()) {
                std::cout << "Address is already frozen by job #" << duplicate->id << ". Unfreeze it first.\n";
                continue;
            }
            const auto id = freezer.add(*address, *type, *value, intervalMs);
            if (!id) {
                std::cout << "Could not create freeze job.\n";
                continue;
            }
            std::cout << "Freeze #" << *id << " active at 0x"
                      << std::hex << std::uppercase << *address << std::dec << std::nouppercase
                      << " = " << cw::formatValue(*value)
                      << " as " << cw::valueTypeName(*type) << ".\n";
            continue;
        }

        if (command == "set" || command == "write") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (!scanner.hasScan()) {
                std::cout << "A scan is required so Cheat Wizard knows the value type.\n";
                continue;
            }
            if (args.size() != 3) {
                std::cout << "Usage: set <#result-index|address> <value>\n";
                continue;
            }

            std::string targetError;
            const auto typedTarget = resolveTypedTarget(args[1], scanner, targetError);
            if (!typedTarget) {
                std::cout << targetError << '\n';
                continue;
            }
            const auto value = cw::parseValue(typedTarget->type, args[2]);
            if (!value) {
                std::cout << "Invalid value for " << cw::valueTypeName(typedTarget->type) << ".\n";
                continue;
            }

            const auto result = engine.writeValue(typedTarget->address, *value);
            if (!result.ok) {
                std::cout << "Write failed: " << cw::win32ErrorMessage(result.error) << '\n';
                continue;
            }
            std::cout << "Wrote " << cw::formatValue(*value) << " as "
                      << cw::valueTypeName(typedTarget->type) << " to 0x"
                      << std::hex << std::uppercase << typedTarget->address << std::dec << std::nouppercase << ".\n";
            continue;
        }

        if (command == "freeze") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (!scanner.hasScan()) {
                std::cout << "A scan is required so Cheat Wizard knows the value type.\n";
                continue;
            }
            if (args.size() != 3 && args.size() != 4) {
                std::cout << "Usage: freeze <#result-index|address> <value> [interval_ms]\n";
                continue;
            }

            std::string targetError;
            const auto typedTarget = resolveTypedTarget(args[1], scanner, targetError);
            if (!typedTarget) {
                std::cout << targetError << '\n';
                continue;
            }
            const auto value = cw::parseValue(typedTarget->type, args[2]);
            if (!value) {
                std::cout << "Invalid value for " << cw::valueTypeName(typedTarget->type) << ".\n";
                continue;
            }

            std::uint32_t intervalMs = 50;
            if (args.size() == 4) {
                try {
                    const auto parsed = std::stoul(args[3]);
                    if (parsed > std::numeric_limits<std::uint32_t>::max()) throw std::out_of_range("interval");
                    intervalMs = static_cast<std::uint32_t>(parsed);
                } catch (...) {
                    std::cout << "Invalid interval.\n";
                    continue;
                }
            }

            const auto existingJobs = freezer.list();
            const auto duplicate = std::find_if(existingJobs.begin(), existingJobs.end(),
                [&](const cw::FreezeSnapshot& job) { return job.address == typedTarget->address; });
            if (duplicate != existingJobs.end()) {
                std::cout << "Address is already frozen by job #" << duplicate->id
                          << ". Unfreeze it first.\n";
                continue;
            }

            const auto id = freezer.add(typedTarget->address, typedTarget->type, *value, intervalMs);
            if (!id) {
                std::cout << "Could not create freeze job.\n";
                continue;
            }
            std::cout << "Freeze #" << *id << " active at 0x"
                      << std::hex << std::uppercase << typedTarget->address << std::dec << std::nouppercase
                      << " = " << cw::formatValue(*value)
                      << " every " << (std::max)(10u, (std::min)(intervalMs, 60'000u)) << " ms.\n";
            continue;
        }

        if (command == "freezes") {
            const auto jobs = freezer.list();
            if (jobs.empty()) {
                std::cout << "No active freezes.\n";
                continue;
            }
            std::cout << "ID   Address              Type              Value            Every  Writes  Failures\n";
            for (const auto& job : jobs) {
                std::cout << std::left << std::setw(4) << job.id << " 0x"
                          << std::right << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << job.address
                          << std::dec << std::nouppercase << std::setfill(' ') << ' ' << std::left
                          << std::setw(17) << cw::valueTypeName(job.type) << ' '
                          << std::setw(16) << cw::formatValue(job.value) << ' '
                          << std::setw(6) << (std::to_string(job.intervalMs) + "ms") << ' '
                          << std::setw(7) << job.writes << ' '
                          << job.failures;
                if (job.lastError != ERROR_SUCCESS) std::cout << " (last error " << job.lastError << ')';
                std::cout << '\n';
            }
            std::cout << std::right;
            continue;
        }

        if (command == "unfreeze") {
            if (args.size() != 2) {
                std::cout << "Usage: unfreeze <id|all>\n";
                continue;
            }
            if (lower(args[1]) == "all") {
                freezer.clear();
                std::cout << "All freeze jobs stopped.\n";
                continue;
            }
            try {
                const auto id = std::stoull(args[1]);
                if (freezer.remove(id)) std::cout << "Freeze #" << id << " stopped.\n";
                else std::cout << "Freeze id not found.\n";
            } catch (...) {
                std::cout << "Invalid freeze id.\n";
            }
            continue;
        }

        if (command == "modules") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            std::string error;
            const auto modules = engine.listModules(error);
            if (modules.empty() && !error.empty()) {
                std::cout << "Module enumeration failed: " << error << '\n';
                continue;
            }
            std::cout << "Base               Size       Module\n";
            for (const auto& module : modules) {
                std::cout << "0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0')
                          << module.base << "  0x" << std::setw(8) << module.size
                          << std::dec << std::nouppercase << std::setfill(' ')
                          << "  " << wideToUtf8(module.name) << '\n';
            }
            std::cout << "Total modules: " << modules.size() << '\n';
            continue;
        }

        if (command == "aob" || command == "aob-code" || command == "aob-module" ||
            command == "aob-module-code") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }

            std::size_t patternStart = 1;
            auto options = scanner.options();
            bool executableOnly = command == "aob-code" || command == "aob-module-code";
            const bool moduleRestricted = command == "aob-module" || command == "aob-module-code";

            if (moduleRestricted) {
                if (args.size() < 3) {
                    std::cout << "Usage: " << command << " <module-name> <pattern>\n";
                    continue;
                }
                patternStart = 2;
                std::string error;
                const auto modules = engine.listModules(error);
                if (!error.empty() && modules.empty()) {
                    std::cout << "Module enumeration failed: " << error << '\n';
                    continue;
                }
                const auto wanted = lower(args[1]);
                const cw::ModuleInfo* found = nullptr;
                for (const auto& module : modules) {
                    if (lower(wideToUtf8(module.name)) == wanted) {
                        found = &module;
                        break;
                    }
                }
                if (!found) {
                    std::cout << "Module not found: " << args[1] << "\n";
                    continue;
                }
                const auto maxAddress = (std::numeric_limits<std::uintptr_t>::max)();
                const auto moduleEnd = (found->size == 0 || found->size - 1 > maxAddress - found->base)
                    ? maxAddress
                    : found->base + static_cast<std::uintptr_t>(found->size - 1);
                options.minAddress = (std::max)(options.minAddress, found->base);
                options.maxAddress = (std::min)(options.maxAddress, moduleEnd);
                if (options.minAddress > options.maxAddress) {
                    std::cout << "Current scanner range does not overlap that module.\n";
                    continue;
                }
            } else if (args.size() < 2) {
                std::cout << "Usage: " << command << " <pattern>\n";
                continue;
            }

            const auto patternText = joinArgs(args, patternStart);
            std::string parseError;
            const auto pattern = cw::parseAobPattern(patternText, parseError);
            if (!pattern) {
                std::cout << "Invalid AOB pattern: " << parseError << '\n';
                continue;
            }

            aobScanner.setOptions(options);
            aobScanner.setExecutableOnly(executableOnly);
            if (moduleRestricted) {
                aobScope = executableOnly ? cw::AobSearchScope::ModuleExecutable
                                          : cw::AobSearchScope::Module;
                aobModuleName = args[1];
            } else {
                aobScope = executableOnly ? cw::AobSearchScope::Executable
                                          : cw::AobSearchScope::Memory;
                aobModuleName.clear();
            }
            std::cout << "AOB scan (" << pattern->size() << " bytes"
                      << (executableOnly ? ", executable pages only" : "")
                      << "): " << cw::formatAobPattern(*pattern) << "...\n";
            printStats(runAobScanWithUi(aobScanner, [&] { return aobScanner.scan(*pattern); }));
            continue;
        }

        if (command == "aob-results" || command == "aresults") {
            std::size_t limit = 50;
            if (args.size() >= 2) {
                try { limit = static_cast<std::size_t>(std::stoull(args[1])); }
                catch (...) { std::cout << "Invalid limit.\n"; continue; }
            }
            const auto& matches = aobScanner.results();
            if (matches.empty()) {
                std::cout << "No stored AOB matches.\n";
                continue;
            }
            std::string moduleError;
            const auto modules = engine.attached()
                ? engine.listModules(moduleError)
                : std::vector<cw::ModuleInfo>{};
            const std::size_t count = (std::min)(limit, matches.size());
            for (std::size_t i = 0; i < count; ++i) {
                const auto address = matches[i];
                std::cout << "[A#" << i << "] 0x" << std::hex << std::uppercase << address;
                for (const auto& module : modules) {
                    if (module.contains(address)) {
                        std::cout << "  " << wideToUtf8(module.name) << "+0x" << (address - module.base);
                        break;
                    }
                }
                std::cout << std::dec << std::nouppercase << '\n';
            }
            if (matches.size() > count) std::cout << "... " << (matches.size() - count) << " more match(es).\n";
            std::cout << "Total: " << matches.size() << '\n';
            continue;
        }

        if (command == "aob-resolve" || command == "aresolve") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() != 4) {
                std::cout << "Usage: aob-resolve <#aob-index|address> <disp_offset> <instruction_size>\n";
                continue;
            }

            std::optional<std::uintptr_t> instructionAddress;
            const auto token = args[1];
            if (!token.empty() && token.front() == '#') {
                try {
                    const auto index = static_cast<std::size_t>(std::stoull(token.substr(1), nullptr, 0));
                    if (index < aobScanner.results().size()) instructionAddress = aobScanner.results()[index];
                    else std::cout << "AOB result index out of range.\n";
                } catch (...) {
                    std::cout << "Invalid AOB result index. Use #0, #1, ...\n";
                }
            } else {
                instructionAddress = parseAddress(token);
                if (!instructionAddress) std::cout << "Invalid instruction address.\n";
            }
            if (!instructionAddress) continue;

            std::size_t displacementOffset{};
            std::size_t instructionSize{};
            try {
                displacementOffset = static_cast<std::size_t>(std::stoull(args[2], nullptr, 0));
                instructionSize = static_cast<std::size_t>(std::stoull(args[3], nullptr, 0));
            } catch (...) {
                std::cout << "Invalid displacement offset/instruction size.\n";
                continue;
            }
            if (instructionSize < 4 || instructionSize > 64 ||
                displacementOffset > instructionSize || displacementOffset + 4 > instructionSize) {
                std::cout << "Require instruction_size 4..64 and disp_offset+4 <= instruction_size.\n";
                continue;
            }
            const auto maxAddress = (std::numeric_limits<std::uintptr_t>::max)();
            if (displacementOffset > maxAddress - *instructionAddress) {
                std::cout << "Displacement address overflows the target address space.\n";
                continue;
            }
            const auto displacementAddress = *instructionAddress + displacementOffset;
            std::int32_t displacement{};
            std::size_t bytesRead{};
            DWORD readError = ERROR_SUCCESS;
            if (!engine.readBytes(displacementAddress, &displacement, sizeof(displacement), bytesRead, readError) ||
                bytesRead != sizeof(displacement)) {
                std::cout << "Could not read rel32 displacement: "
                          << cw::win32ErrorMessage(readError) << '\n';
                continue;
            }
            const auto resolved = cw::resolveRel32(*instructionAddress, instructionSize, displacement);
            if (!resolved) {
                std::cout << "rel32 resolution overflowed the address space.\n";
                continue;
            }

            std::cout << "Instruction: 0x" << std::hex << std::uppercase << *instructionAddress
                      << " | rel32 @ +0x" << displacementOffset
                      << std::dec << " = " << displacement
                      << " | target: 0x" << std::hex << std::uppercase << *resolved;
            std::string moduleError;
            const auto modules = engine.listModules(moduleError);
            for (const auto& module : modules) {
                if (module.contains(*resolved)) {
                    std::cout << "  " << wideToUtf8(module.name) << "+0x" << (*resolved - module.base);
                    break;
                }
            }
            std::cout << std::dec << std::nouppercase << '\n';
            continue;
        }

        if (command == "aob-decode" || command == "adecode") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() != 2) {
                std::cout << "Usage: aob-decode <#aob-index|address>\n";
                continue;
            }
            std::optional<std::uintptr_t> instructionAddress;
            if (!args[1].empty() && args[1].front() == '#') {
                try {
                    const auto index = static_cast<std::size_t>(std::stoull(args[1].substr(1), nullptr, 0));
                    if (index < aobScanner.results().size()) instructionAddress = aobScanner.results()[index];
                    else std::cout << "AOB result index out of range.\n";
                } catch (...) {
                    std::cout << "Invalid AOB result index. Use #0, #1, ...\n";
                }
            } else {
                instructionAddress = parseAddress(args[1]);
                if (!instructionAddress) std::cout << "Invalid instruction address.\n";
            }
            if (!instructionAddress) continue;

            std::array<std::byte, 16> bytes{};
            std::size_t bytesRead{};
            DWORD readError = ERROR_SUCCESS;
            if (!engine.readBytes(*instructionAddress, bytes.data(), bytes.size(), bytesRead, readError) || bytesRead < 2) {
                std::cout << "Could not read instruction bytes: "
                          << cw::win32ErrorMessage(readError) << '\n';
                continue;
            }
            std::string pointerError;
            const auto pointerSize = engine.targetPointerSize(pointerError);
            const bool x64 = pointerSize == 8;
            const auto decoded = cw::decodeCommonRelativeInstruction(
                *instructionAddress, std::span<const std::byte>(bytes.data(), bytesRead), x64);
            if (!decoded) {
                std::cout << "No supported relative instruction form recognized at 0x"
                          << std::hex << std::uppercase << *instructionAddress
                          << std::dec << std::nouppercase << ".\n";
                continue;
            }

            std::cout << cw::relativeInstructionKindName(decoded->kind)
                      << " @ 0x" << std::hex << std::uppercase << *instructionAddress
                      << " | size=" << std::dec << decoded->instructionSize
                      << " | disp@+0x" << std::hex << decoded->displacementOffset
                      << " | " << (decoded->indirect ? "slot" : "target")
                      << "=0x" << decoded->target;
            std::string moduleError;
            const auto modules = engine.listModules(moduleError);
            for (const auto& module : modules) {
                if (module.contains(decoded->target)) {
                    std::cout << "  " << wideToUtf8(module.name) << "+0x"
                              << (decoded->target - module.base);
                    break;
                }
            }
            std::cout << std::dec << std::nouppercase << '\n';

            if (decoded->indirect && (pointerSize == 4 || pointerSize == 8)) {
                std::uintptr_t destination{};
                std::size_t got{};
                DWORD pointerReadError = ERROR_SUCCESS;
                bool ok = false;
                if (pointerSize == 4) {
                    std::uint32_t value{};
                    ok = engine.readBytes(decoded->target, &value, sizeof(value), got, pointerReadError) && got == sizeof(value);
                    destination = value;
                } else {
                    std::uint64_t value{};
                    ok = engine.readBytes(decoded->target, &value, sizeof(value), got, pointerReadError) && got == sizeof(value);
                    destination = static_cast<std::uintptr_t>(value);
                }
                if (ok) {
                    std::cout << "Indirect destination: 0x" << std::hex << std::uppercase << destination;
                    for (const auto& module : modules) {
                        if (module.contains(destination)) {
                            std::cout << "  " << wideToUtf8(module.name) << "+0x"
                                      << (destination - module.base);
                            break;
                        }
                    }
                    std::cout << std::dec << std::nouppercase << '\n';
                } else {
                    std::cout << "Pointer slot could not be dereferenced.\n";
                }
            }
            continue;
        }

        if (command == "aob-save") {
            if (args.size() != 2) {
                std::cout << "Usage: aob-save <file.cwaob>\n";
                continue;
            }
            if (!engine.attached()) {
                std::cout << "Attach to the process that produced the AOB results before saving.\n";
                continue;
            }
            if (aobScanner.pattern().empty()) {
                std::cout << "No active AOB signature to save.\n";
                continue;
            }
            std::string moduleError;
            const auto modules = engine.listModules(moduleError);
            if (modules.empty() && !moduleError.empty()) {
                std::cout << "Module enumeration failed: " << moduleError << '\n';
                continue;
            }
            cw::AobSessionData session;
            session.pattern = aobScanner.pattern();
            session.scope = aobScope;
            session.moduleName = aobModuleName;
            session.results.reserve(aobScanner.results().size());
            for (const auto address : aobScanner.results()) {
                cw::AobSavedResult saved;
                saved.value = address;
                for (const auto& module : modules) {
                    if (module.contains(address)) {
                        saved.moduleRelative = true;
                        saved.moduleName = wideToUtf8(module.name);
                        saved.value = address - module.base;
                        break;
                    }
                }
                session.results.push_back(std::move(saved));
            }
            std::string error;
            if (!cw::saveAobSession(args[1], session, error)) {
                std::cout << "AOB save failed: " << error << '\n';
                continue;
            }
            std::cout << "Saved AOB session '" << args[1] << "': "
                      << cw::formatAobPattern(session.pattern) << " | "
                      << session.results.size() << " match(es).\n";
            continue;
        }

        if (command == "aob-load") {
            if (args.size() != 2) {
                std::cout << "Usage: aob-load <file.cwaob>\n";
                continue;
            }
            if (!engine.attached()) {
                std::cout << "Attach to a process first so module-relative matches can be rebased.\n";
                continue;
            }
            cw::AobSessionData session;
            std::string error;
            if (!cw::loadAobSession(args[1], session, error)) {
                std::cout << "AOB load failed: " << error << '\n';
                continue;
            }
            std::string moduleError;
            const auto modules = engine.listModules(moduleError);
            if (modules.empty() && !moduleError.empty()) {
                std::cout << "Module enumeration failed: " << moduleError << '\n';
                continue;
            }
            std::vector<std::uintptr_t> restored;
            restored.reserve(session.results.size());
            std::size_t skipped = 0;
            std::size_t absolute = 0;
            for (const auto& saved : session.results) {
                if (!saved.moduleRelative) {
                    restored.push_back(saved.value);
                    ++absolute;
                    continue;
                }
                const auto wanted = lower(saved.moduleName);
                const cw::ModuleInfo* found = nullptr;
                for (const auto& module : modules) {
                    if (lower(wideToUtf8(module.name)) == wanted) { found = &module; break; }
                }
                if (!found || saved.value >= found->size ||
                    saved.value > (std::numeric_limits<std::uintptr_t>::max)() - found->base) {
                    ++skipped;
                    continue;
                }
                restored.push_back(found->base + saved.value);
            }
            aobScanner.restore(session.pattern, std::move(restored));
            aobScope = session.scope;
            aobModuleName = session.moduleName;
            std::cout << "Loaded AOB session '" << args[1] << "': "
                      << aobScanner.results().size() << " match(es) restored";
            if (skipped) std::cout << ", " << skipped << " module-relative match(es) skipped";
            if (absolute) std::cout << ", " << absolute << " absolute match(es) may be stale after restart";
            std::cout << ".\n";
            continue;
        }

        if (command == "aob-rerun") {
            if (args.size() != 2) {
                std::cout << "Usage: aob-rerun <file.cwaob>\n";
                continue;
            }
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            cw::AobSessionData session;
            std::string error;
            if (!cw::loadAobSession(args[1], session, error)) {
                std::cout << "AOB preset load failed: " << error << '\n';
                continue;
            }
            auto options = scanner.options();
            const bool moduleRestricted = session.scope == cw::AobSearchScope::Module ||
                                          session.scope == cw::AobSearchScope::ModuleExecutable;
            const bool executableOnly = session.scope == cw::AobSearchScope::Executable ||
                                        session.scope == cw::AobSearchScope::ModuleExecutable;
            if (moduleRestricted) {
                std::string moduleError;
                const auto modules = engine.listModules(moduleError);
                const auto wanted = lower(session.moduleName);
                const cw::ModuleInfo* found = nullptr;
                for (const auto& module : modules) {
                    if (lower(wideToUtf8(module.name)) == wanted) { found = &module; break; }
                }
                if (!found) {
                    std::cout << "Saved AOB module is not loaded: " << session.moduleName << '\n';
                    continue;
                }
                const auto maxAddress = (std::numeric_limits<std::uintptr_t>::max)();
                const auto moduleEnd = (found->size == 0 || found->size - 1 > maxAddress - found->base)
                    ? maxAddress : found->base + static_cast<std::uintptr_t>(found->size - 1);
                options.minAddress = (std::max)(options.minAddress, found->base);
                options.maxAddress = (std::min)(options.maxAddress, moduleEnd);
                if (options.minAddress > options.maxAddress) {
                    std::cout << "Current scanner range does not overlap saved module.\n";
                    continue;
                }
            }
            aobScanner.setOptions(options);
            aobScanner.setExecutableOnly(executableOnly);
            aobScope = session.scope;
            aobModuleName = session.moduleName;
            std::cout << "Re-running saved AOB signature: "
                      << cw::formatAobPattern(session.pattern) << "...\n";
            printStats(runAobScanWithUi(aobScanner, [&] { return aobScanner.scan(session.pattern); }));
            continue;
        }

        if (command == "aob-clear") {
            aobScanner.clear();
            aobModuleName.clear();
            aobScope = cw::AobSearchScope::Memory;
            std::cout << "AOB matches cleared.\n";
            continue;
        }

        if (command == "pointer-settings" || command == "psettings") {
            if (args.size() == 1) {
                printPointerSettings(pointerDefaults);
                continue;
            }
            if (args.size() != 3) {
                std::cout << "Usage: pointer-settings <alignment|writable|private|branch|root> <value>\n";
                continue;
            }
            const auto key = lower(args[1]);
            bool valid = true;
            if (key == "alignment") {
                const auto value = lower(args[2]);
                if (value == "natural" || value == "aligned") pointerDefaults.alignment = 0;
                else if (value == "byte" || value == "1" || value == "unaligned") pointerDefaults.alignment = 1;
                else if (value == "2") pointerDefaults.alignment = 2;
                else if (value == "4") pointerDefaults.alignment = 4;
                else if (value == "8") pointerDefaults.alignment = 8;
                else valid = false;
            } else if (key == "writable") {
                const auto value = parseToggle(args[2]);
                if (!value) valid = false;
                else pointerDefaults.writableOnly = *value;
            } else if (key == "private") {
                const auto value = parseToggle(args[2]);
                if (!value) valid = false;
                else pointerDefaults.privateOnly = *value;
            } else if (key == "branch" || key == "branching") {
                try {
                    const auto value = static_cast<std::size_t>(std::stoull(args[2], nullptr, 0));
                    if (value < 1 || value > 65536) valid = false;
                    else pointerDefaults.maxCandidatesPerNode = value;
                } catch (...) {
                    valid = false;
                }
            } else if (key == "root") {
                if (lower(args[2]) == "any" || args[2] == "*") pointerDefaults.rootModuleName.clear();
                else pointerDefaults.rootModuleName = std::wstring(args[2].begin(), args[2].end());
            } else {
                valid = false;
            }
            if (!valid) {
                std::cout << "Invalid pointer setting. Type 'help' for accepted values.\n";
                continue;
            }
            pointerScanner.clearIndex();
            std::cout << "Pointer settings updated. Existing chains were kept; the next scan/map uses the new filters.\n";
            printPointerSettings(pointerDefaults);
            continue;
        }

        if (command == "pointer-scan" || command == "pscan") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() < 2 || args.size() > 6) {
                std::cout << "Usage: pointer-scan <#result-index|address> [depth] [max_offset] [max_chains] [max_negative_offset]\n";
                continue;
            }
            std::string targetError;
            const auto target = resolveTarget(args[1], scanner, targetError);
            if (!target) {
                std::cout << targetError << '\n';
                continue;
            }

            auto options = pointerDefaults;
            try {
                if (args.size() >= 3) options.maxDepth = static_cast<std::size_t>(std::stoull(args[2], nullptr, 0));
                if (args.size() >= 4) {
                    const auto value = parseAddress(args[3]);
                    if (!value) throw std::invalid_argument("offset");
                    options.maxOffset = *value;
                }
                if (args.size() >= 5) options.maxChains = static_cast<std::size_t>(std::stoull(args[4], nullptr, 0));
                if (args.size() >= 6) {
                    const auto value = parseAddress(args[5]);
                    if (!value) throw std::invalid_argument("negative offset");
                    options.maxNegativeOffset = *value;
                }
            } catch (...) {
                std::cout << "Invalid pointer-scan option.\n";
                continue;
            }
            if (options.maxDepth < 1 || options.maxDepth > 8 ||
                options.maxOffset > 0x1000000 || options.maxNegativeOffset > 0x1000000 ||
                options.maxChains < 1 || options.maxChains > 100000) {
                std::cout << "Limits: depth 1..8, positive/negative offsets <= 0x1000000, max_chains 1..100000.\n";
                continue;
            }

            if (!refreshPointerContext(engine)) continue;
            std::cout << "Building pointer index and searching chains to 0x"
                      << std::hex << std::uppercase << *target << std::dec << std::nouppercase
                      << " (depth " << options.maxDepth << ", +max 0x"
                      << std::hex << std::uppercase << options.maxOffset
                      << ", -max 0x" << options.maxNegativeOffset
                      << std::dec << std::nouppercase << ")...\n";
            const auto stats = runPointerScanWithUi(pointerScanner, *target, options);
            printPointerStats(stats);
            const auto preview = (std::min)(std::size_t{20}, pointerScanner.chains().size());
            for (std::size_t i = 0; i < preview; ++i) printPointerChain(pointerScanner.chains()[i], i);
            if (pointerScanner.chains().size() > preview) {
                std::cout << "... " << pointerScanner.chains().size() - preview
                          << " more chain(s). Use 'pointer-results'.\n";
            }
            continue;
        }

        if (command == "pointer-results" || command == "pointers") {
            std::size_t limit = 50;
            if (args.size() > 2) {
                std::cout << "Usage: pointer-results [limit]\n";
                continue;
            }
            if (args.size() == 2) {
                try { limit = static_cast<std::size_t>(std::stoull(args[1])); }
                catch (...) { std::cout << "Invalid limit.\n"; continue; }
            }
            const auto& chains = pointerScanner.chains();
            const auto count = (std::min)(limit, chains.size());
            for (std::size_t i = 0; i < count; ++i) printPointerChain(chains[i], i);
            if (chains.size() > count) std::cout << "... " << chains.size() - count << " more chain(s).\n";
            std::cout << "Total pointer chains: " << chains.size() << '\n';
            continue;
        }

        if (command == "pointer-resolve" || command == "presolve") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() != 2) {
                std::cout << "Usage: pointer-resolve <chain-index>\n";
                continue;
            }
            std::size_t index{};
            try { index = static_cast<std::size_t>(std::stoull(args[1])); }
            catch (...) { std::cout << "Invalid chain index.\n"; continue; }
            if (index >= pointerScanner.chains().size()) {
                std::cout << "Pointer chain index out of range.\n";
                continue;
            }
            if (!refreshPointerContext(engine)) continue;
            // refreshPointerContext intentionally preserves chains.
            if (pointerScanner.chainPointerSize() != 0 &&
                pointerScanner.chainPointerSize() != pointerScanner.pointerSize()) {
                std::cout << "Stored chains are " << pointerScanner.chainPointerSize() * 8
                          << "-bit but the attached target is " << pointerScanner.pointerSize() * 8 << "-bit.\n";
                continue;
            }
            const auto resolved = pointerScanner.resolve(index);
            printPointerChain(pointerScanner.chains()[index], index);
            if (resolved) {
                std::cout << "Resolved address: 0x" << std::hex << std::uppercase << *resolved
                          << std::dec << std::nouppercase << '\n';
            } else {
                std::cout << "Chain could not be resolved in the current process.\n";
            }
            continue;
        }

        if (command == "pointer-rescan" || command == "prescan") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() != 2) {
                std::cout << "Usage: pointer-rescan <#result-index|address>\n";
                continue;
            }
            if (pointerScanner.chains().empty()) {
                std::cout << "No stored pointer chains. Run pointer-scan first.\n";
                continue;
            }
            std::string targetError;
            const auto target = resolveTarget(args[1], scanner, targetError);
            if (!target) {
                std::cout << targetError << '\n';
                continue;
            }
            if (!refreshPointerContext(engine)) continue;
            if (pointerScanner.chainPointerSize() != 0 &&
                pointerScanner.chainPointerSize() != pointerScanner.pointerSize()) {
                std::cout << "Stored chains are " << pointerScanner.chainPointerSize() * 8
                          << "-bit but the attached target is " << pointerScanner.pointerSize() * 8 << "-bit.\n";
                continue;
            }
            const auto before = pointerScanner.chains().size();
            const auto after = pointerScanner.rescan(*target);
            std::cout << "Pointer rescan: " << before << " -> " << after
                      << " chain(s) resolving to 0x" << std::hex << std::uppercase << *target
                      << std::dec << std::nouppercase << ".\n";
            continue;
        }

        if (command == "pointer-save" || command == "psave") {
            if (args.size() != 2) {
                std::cout << "Usage: pointer-save <file.cwchain>\n";
                continue;
            }
            if (pointerScanner.chains().empty()) {
                std::cout << "No stored pointer chains to save.\n";
                continue;
            }
            const auto chainPointerSize = pointerScanner.chainPointerSize();
            if (chainPointerSize != 4 && chainPointerSize != 8) {
                std::cout << "Stored chains have no valid pointer-width metadata.\n";
                continue;
            }
            std::string error;
            if (!cw::savePointerChains(args[1], chainPointerSize, pointerScanner.chains(), error)) {
                std::cout << "Pointer save failed: " << error << '\n';
                continue;
            }
            std::cout << "Saved " << pointerScanner.chains().size() << " pointer chain(s) to '"
                      << args[1] << "' (" << chainPointerSize * 8 << "-bit).\n";
            continue;
        }

        if (command == "pointer-load" || command == "pload") {
            if (args.size() != 2) {
                std::cout << "Usage: pointer-load <file.cwchain>\n";
                continue;
            }
            cw::PointerFileData data;
            std::string error;
            if (!cw::loadPointerChains(args[1], data, error)) {
                std::cout << "Pointer load failed: " << error << '\n';
                continue;
            }
            if (engine.attached()) {
                std::string pointerError;
                const auto currentPointerSize = engine.targetPointerSize(pointerError);
                if (currentPointerSize != 0 && currentPointerSize != data.pointerSize) {
                    std::cout << "Refusing pointer file: file is " << data.pointerSize * 8
                              << "-bit but attached target is " << currentPointerSize * 8 << "-bit.\n";
                    continue;
                }
            }
            pointerScanner.clearIndex();
            pointerScanner.setChains(std::move(data.chains), data.pointerSize);
            std::cout << "Loaded " << pointerScanner.chains().size() << " pointer chain(s) from '"
                      << args[1] << "' (" << data.pointerSize * 8 << "-bit).\n";
            continue;
        }

        if (command == "profile-load") {
            if (args.size() != 2) {
                std::cout << "Usage: profile-load <file.cwptr>\n";
                continue;
            }
            cw::PointerProfileData data;
            std::string error;
            if (!cw::loadPointerProfile(args[1], data, error)) {
                std::cout << "PROFILE_ERR load_failed " << error << '\n';
                continue;
            }
            if (engine.attached()) {
                std::string pointerError;
                const auto currentPointerSize = engine.targetPointerSize(pointerError);
                if (currentPointerSize != 0 && currentPointerSize != data.pointerSize) {
                    std::cout << "PROFILE_ERR pointer_width_mismatch\n";
                    continue;
                }
            }
            pointerScanner.clearIndex();
            pointerScanner.setChains(data.chains, data.pointerSize);
            activePointerProfile = std::move(data);
            std::cout << "PROFILE_OK loaded chains=" << pointerScanner.chains().size()
                      << " type=" << cw::valueTypeName(activePointerProfile->type)
                      << " process=" << (activePointerProfile->processName.empty() ? "?" : activePointerProfile->processName)
                      << '\n';
            continue;
        }

        if (command == "profile-read") {
            if (!activePointerProfile) { std::cout << "PROFILE_ERR no_profile\n"; continue; }
            const auto resolved = resolveActiveProfile();
            if (!resolved) { std::cout << "PROFILE_ERR unresolved\n"; continue; }
            const auto [address, agreeing, resolvedCount] = *resolved;
            if (agreeing * 2 <= resolvedCount) { std::cout << "PROFILE_ERR ambiguous agree=" << agreeing << '/' << resolvedCount << '\n'; continue; }
            const auto value = engine.readValue(address, activePointerProfile->type);
            if (!value) { std::cout << "PROFILE_ERR unreadable\n"; continue; }
            std::cout << "PROFILE_OK address=0x" << std::hex << std::uppercase << address
                      << std::dec << std::nouppercase << " type=" << cw::valueTypeName(activePointerProfile->type)
                      << " agree=" << agreeing << '/' << resolvedCount
                      << " value=" << cw::formatValue(*value) << '\n';
            continue;
        }

        if (command == "profile-write") {
            if (!activePointerProfile) { std::cout << "PROFILE_ERR no_profile\n"; continue; }
            if (args.size() != 2) { std::cout << "Usage: profile-write <value>\n"; continue; }
            const auto resolved = resolveActiveProfile();
            if (!resolved) { std::cout << "PROFILE_ERR unresolved\n"; continue; }
            const auto [address, agreeing, resolvedCount] = *resolved;
            if (agreeing * 2 <= resolvedCount) { std::cout << "PROFILE_ERR ambiguous agree=" << agreeing << '/' << resolvedCount << '\n'; continue; }
            const auto value = cw::parseValue(activePointerProfile->type, args[1]);
            if (!value) { std::cout << "PROFILE_ERR bad_value\n"; continue; }
            const auto result = engine.writeValue(address, *value);
            if (!result.ok) { std::cout << "PROFILE_ERR write_failed\n"; continue; }
            std::cout << "PROFILE_OK written address=0x" << std::hex << std::uppercase << address
                      << std::dec << std::nouppercase << " agree=" << agreeing << '/' << resolvedCount << '\n';
            continue;
        }

        if (command == "profile-freeze") {
            if (!activePointerProfile) { std::cout << "PROFILE_ERR no_profile\n"; continue; }
            if (args.size() < 2 || args.size() > 3) { std::cout << "Usage: profile-freeze <value> [interval_ms]\n"; continue; }
            const auto resolved = resolveActiveProfile();
            if (!resolved) { std::cout << "PROFILE_ERR unresolved\n"; continue; }
            const auto [address, agreeing, resolvedCount] = *resolved;
            if (agreeing * 2 <= resolvedCount) { std::cout << "PROFILE_ERR ambiguous agree=" << agreeing << '/' << resolvedCount << '\n'; continue; }
            const auto value = cw::parseValue(activePointerProfile->type, args[1]);
            if (!value) { std::cout << "PROFILE_ERR bad_value\n"; continue; }
            std::chrono::milliseconds interval{50};
            if (args.size() == 3) {
                try { interval = std::chrono::milliseconds(std::stoll(args[2])); }
                catch (...) { std::cout << "PROFILE_ERR bad_interval\n"; continue; }
                if (interval.count() < 1 || interval.count() > 60'000) { std::cout << "PROFILE_ERR bad_interval\n"; continue; }
            }
            const auto id = freezer.add(address, activePointerProfile->type, *value, static_cast<std::uint32_t>(interval.count()));
            if (!id) { std::cout << "PROFILE_ERR freeze_failed\n"; continue; }
            std::cout << "PROFILE_OK freeze=" << *id << " address=0x" << std::hex << std::uppercase << address
                      << std::dec << std::nouppercase << " agree=" << agreeing << '/' << resolvedCount << '\n';
            continue;
        }

        if (command == "pmap-capture" || command == "pmcapture") {
            if (!engine.attached()) {
                std::cout << "Attach to a process first.\n";
                continue;
            }
            if (args.size() < 3 || args.size() > 4) {
                std::cout << "Usage: pmap-capture <file.cwmap> <#result-index|address> [max_entries]\n";
                continue;
            }
            std::string targetError;
            const auto target = resolveTarget(args[2], scanner, targetError);
            if (!target) {
                std::cout << targetError << '\n';
                continue;
            }
            std::size_t maxEntries = 8'000'000;
            if (args.size() == 4) {
                try { maxEntries = static_cast<std::size_t>(std::stoull(args[3], nullptr, 0)); }
                catch (...) { std::cout << "Invalid max_entries.\n"; continue; }
            }
            if (maxEntries < 1 || maxEntries > 16'000'000) {
                std::cout << "max_entries must be between 1 and 16000000.\n";
                continue;
            }
            if (!refreshPointerContext(engine)) continue;
            auto options = pointerDefaults;
            options.maxIndexEntries = maxEntries;
            std::cout << "Capturing pointer map to '" << args[1] << "' for target 0x"
                      << std::hex << std::uppercase << *target << std::dec << std::nouppercase << "...\n";
            const auto stats = runPointerCaptureWithUi(pointerScanner, options);
            printPointerStats(stats);
            const bool complete = !stats.cancelled && !stats.indexTruncated;
            const auto modules = pointerModulesFromProcess(pointerScanner.modules());
            std::string error;
            if (!cw::savePointerMap(
                    args[1], pointerScanner.pointerSize(), *target, modules,
                    pointerScanner.index(), complete, error)) {
                std::cout << "Pointer-map save failed: " << error << '\n';
                pointerScanner.clearIndex();
                continue;
            }
            std::cout << "Saved " << pointerScanner.index().size() << " pointer entries and "
                      << modules.size() << " module(s) to '" << args[1] << "'"
                      << (complete ? ".\n" : " [PARTIAL/TRUNCATED].\n");
            pointerScanner.clearIndex();
            continue;
        }

        if (command == "pmap-load" || command == "pmload") {
            if (args.size() != 2) {
                std::cout << "Usage: pmap-load <file.cwmap>\n";
                continue;
            }
            cw::PointerMapData map;
            std::string error;
            if (!cw::loadPointerMap(args[1], map, error)) {
                std::cout << "Pointer-map load failed: " << error << '\n';
                continue;
            }
            if (!pointerMaps.empty() && pointerMaps.front().pointerSize != map.pointerSize) {
                std::cout << "Refusing pointer map: loaded set is " << pointerMaps.front().pointerSize * 8
                          << "-bit but file is " << map.pointerSize * 8 << "-bit.\n";
                continue;
            }
            std::cout << "Loaded pointer map '" << args[1] << "': " << map.entries.size()
                      << " entries, " << map.modules.size() << " modules, target 0x"
                      << std::hex << std::uppercase << map.target << std::dec << std::nouppercase
                      << (map.complete ? ".\n" : " [PARTIAL].\n");
            pointerMapNames.push_back(args[1]);
            pointerMaps.push_back(std::move(map));
            continue;
        }

        if (command == "pmap-list" || command == "pmlist") {
            if (pointerMaps.empty()) {
                std::cout << "No pointer maps loaded.\n";
                continue;
            }
            for (std::size_t i = 0; i < pointerMaps.size(); ++i) {
                const auto& map = pointerMaps[i];
                std::cout << "[M#" << i << "] " << pointerMapNames[i]
                          << " | " << map.pointerSize * 8 << "-bit"
                          << " | entries " << map.entries.size()
                          << " | modules " << map.modules.size()
                          << " | target 0x" << std::hex << std::uppercase << map.target
                          << std::dec << std::nouppercase
                          << (map.complete ? " | complete" : " | PARTIAL") << '\n';
            }
            continue;
        }

        if (command == "pmap-compare" || command == "pmcompare") {
            if (pointerMaps.empty()) {
                std::cout << "Load at least one pointer map first with pmap-load.\n";
                continue;
            }
            if (args.size() > 5) {
                std::cout << "Usage: pmap-compare [depth] [max_offset] [max_chains] [max_negative_offset]\n";
                continue;
            }
            auto options = pointerDefaults;
            try {
                if (args.size() >= 2) options.maxDepth = static_cast<std::size_t>(std::stoull(args[1], nullptr, 0));
                if (args.size() >= 3) options.maxOffset = static_cast<std::uintptr_t>(std::stoull(args[2], nullptr, 0));
                if (args.size() >= 4) options.maxChains = static_cast<std::size_t>(std::stoull(args[3], nullptr, 0));
                if (args.size() >= 5) options.maxNegativeOffset = static_cast<std::uintptr_t>(std::stoull(args[4], nullptr, 0));
            } catch (...) {
                std::cout << "Invalid pmap-compare option.\n";
                continue;
            }
            if (options.maxDepth < 1 || options.maxDepth > 8 ||
                options.maxOffset > 0x1000000 || options.maxNegativeOffset > 0x1000000 ||
                options.maxChains < 1 || options.maxChains > 100000) {
                std::cout << "Limits: depth 1..8, positive/negative offsets <= 0x1000000, max_chains 1..100000.\n";
                continue;
            }
            const bool anyPartial = std::any_of(pointerMaps.begin(), pointerMaps.end(),
                [](const cw::PointerMapData& map) { return !map.complete; });
            if (anyPartial) {
                std::cout << "Warning: at least one loaded map is partial; valid chains may be missing.\n";
            }
            std::cout << "Comparing " << pointerMaps.size() << " pointer map(s)...\n";
            const auto started = std::chrono::steady_clock::now();
            cw::PointerMapCompareStats compareStats;
            auto chains = cw::findCommonPointerChains(pointerMaps, options, &compareStats);
            const auto elapsed = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - started).count();
            pointerScanner.clearIndex();
            pointerScanner.setChains(std::move(chains), pointerMaps.front().pointerSize);
            std::cout << "Pointer-map compare: " << compareStats.initialChains << " initial -> "
                      << compareStats.survivingChains << " common chain(s) across "
                      << compareStats.maps << " map(s) | " << std::fixed << std::setprecision(1)
                      << elapsed << " ms";
            if (compareStats.chainsTruncated) std::cout << " | INITIAL SEARCH TRUNCATED";
            std::cout << '\n';
            const auto preview = (std::min)(std::size_t{20}, pointerScanner.chains().size());
            for (std::size_t i = 0; i < preview; ++i) printPointerChain(pointerScanner.chains()[i], i);
            if (pointerScanner.chains().size() > preview) {
                std::cout << "... " << pointerScanner.chains().size() - preview
                          << " more chain(s). Use 'pointer-results'.\n";
            }
            continue;
        }

        if (command == "pmap-compare-files" || command == "pmcompare-files") {
            if (args.size() < 3) {
                std::cout << "Usage: pmap-compare-files <file1> <file2> [file3 ...]\n";
                continue;
            }
            if (args.size() > 18) {
                std::cout << "At most 16 pointer-map files may be compared in one command.\n";
                continue;
            }
            std::vector<std::string> paths(args.begin() + 1, args.end());
            auto options = pointerDefaults;
            const auto started = std::chrono::steady_clock::now();
            cw::PointerMapCompareStats compareStats;
            std::string compareError;
            auto chains = cw::findCommonPointerChainsStreaming(
                paths, options, &compareStats, compareError);
            const auto elapsed = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - started).count();
            if (!compareError.empty()) {
                std::cout << "Streaming pointer-map compare failed: " << compareError << '\n';
                continue;
            }
            pointerScanner.clearIndex();
            pointerScanner.setChains(std::move(chains), compareStats.pointerSize);
            const double approxPeakMiB =
                static_cast<double>(compareStats.peakEntriesLoaded * sizeof(cw::PointerEntry)) /
                (1024.0 * 1024.0);
            std::cout << "Streaming pointer-map compare: " << compareStats.initialChains << " initial -> "
                      << compareStats.survivingChains << " common chain(s) across "
                      << compareStats.maps << " map(s) | " << std::fixed << std::setprecision(1)
                      << elapsed << " ms | approx peak entry RAM " << approxPeakMiB << " MiB";
            if (compareStats.partialMaps) {
                std::cout << " | WARNING: " << compareStats.partialMaps << " partial map(s)";
            }
            if (compareStats.chainsTruncated) std::cout << " | INITIAL SEARCH TRUNCATED";
            std::cout << '\n';
            const auto preview = (std::min)(std::size_t{20}, pointerScanner.chains().size());
            for (std::size_t i = 0; i < preview; ++i) printPointerChain(pointerScanner.chains()[i], i);
            if (pointerScanner.chains().size() > preview) {
                std::cout << "... " << pointerScanner.chains().size() - preview
                          << " more chain(s). Use 'pointer-results'.\n";
            }
            continue;
        }

        if (command == "pmap-clear" || command == "pmclear") {
            pointerMaps.clear();
            pointerMaps.shrink_to_fit();
            pointerMapNames.clear();
            pointerMapNames.shrink_to_fit();
            std::cout << "Loaded pointer maps cleared.\n";
            continue;
        }

        if (command == "pointer-clear" || command == "pclear") {
            pointerScanner.clearIndex();
            pointerScanner.clearChains();
            std::cout << "Pointer index and chains cleared.\n";
            continue;
        }

        if (command == "status") {
            if (!engine.attached()) std::cout << "Process: <detached>\n";
            else std::cout << "Process PID: " << engine.pid() << '\n';

            if (!scanner.hasScan()) {
                std::cout << "Scan: <none>\n";
            } else {
                if (scanner.mixedScanActive()) std::cout << "Type: Mixed numeric types (scan all)\n";
                else std::cout << "Type: " << cw::valueTypeName(scanner.valueType()) << '\n';
                if (scanner.unknownSnapshotActive()) {
                    std::cout << "Scan state: Unknown snapshot/refinement\n";
                    std::cout << "Candidates: " << scanner.candidateCount() << '\n';
                    std::cout << "Materialization cap: 5000000\n";
                    std::cout << "Snapshot storage: temporary disk backing (delete-on-close)\n";
                } else {
                    std::cout << "Scan state: materialized results\n";
                    std::cout << "Results: " << scanner.results().size() << '\n';
                }
                if (scanner.mixedScanActive()) printCandidateCountsByType(scanner);
                std::cout << "Guided refinement depth: " << scanner.refinementHistory().size() << " step(s)\n";
                std::cout << "Wizard goal: " << guidedGoalName(guidedGoal) << '\n';
            }
            std::cout << "Active freezes: " << freezer.size() << '\n';
            std::cout << "Stored pointer chains: " << pointerScanner.chains().size() << '\n';
            std::cout << "Loaded pointer maps: " << pointerMaps.size() << '\n';
            if (pointerScanner.chainPointerSize()) std::cout << "Chain pointer width: " << pointerScanner.chainPointerSize() * 8 << "-bit\n";
            if (pointerScanner.pointerSize()) std::cout << "Target pointer width: " << pointerScanner.pointerSize() * 8 << "-bit\n";
            printSettings(scanner.options());
            continue;
        }

        std::cout << "Unknown command. Type 'help'.\n";
    }

    freezer.setProcess(nullptr);
    scanner.setProcess(nullptr);
    aobScanner.setProcess(nullptr);
    pointerScanner.setProcess(nullptr, 0, {});
    engine.detach();
    return 0;
}
