#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

struct CwGuiProcessInfo {
    std::uint32_t pid;
    char name[260];
};

struct CwGuiModuleInfo {
    std::uint64_t base;
    std::uint64_t size;
    char name[260];
};

struct CwGuiScanOptions {
    std::uint8_t alignmentByte;
    std::uint8_t writableOnly;
    std::uint8_t privateOnly;
    std::uint8_t reserved;
    std::uint64_t minAddress;
    std::uint64_t maxAddress;
    double floatTolerance;
};

struct CwGuiScanSummary {
    std::uint8_t hasScan;
    std::uint8_t snapshotActive;
    std::uint8_t mixed;
    std::uint8_t primaryType;
    std::uint8_t truncated;
    std::uint8_t cancelled;
    std::uint8_t reserved[2];
    std::uint64_t candidateCount;
    std::uint64_t resultCount;
    std::uint64_t bytesRead;
    std::uint64_t regionsRead;
    double elapsedMs;
    std::uint64_t typeCounts[6];
};

struct CwGuiScanResult {
    std::uint64_t address;
    std::uint8_t previous[8];
    std::uint8_t current[8];
    std::uint8_t type;
    std::uint8_t previousPresent;
    std::uint8_t currentPresent;
    std::uint8_t reserved;
};

struct CwGuiFreezeInfo {
    std::uint64_t id;
    std::uint64_t address;
    std::uint8_t value[8];
    std::uint8_t valueSize;
    std::uint8_t type;
    std::uint16_t reserved;
    std::uint32_t intervalMs;
    std::uint64_t writes;
    std::uint64_t failures;
    std::uint32_t lastError;
};

struct CwGuiPointerOptions {
    std::uint16_t maxDepth;
    std::uint16_t alignment;
    std::uint32_t maxChains;
    std::uint32_t maxIndexEntries;
    std::uint32_t maxCandidatesPerNode;
    std::uint32_t maxSearchCandidates;
    std::uint64_t maxOffset;
    std::uint64_t maxNegativeOffset;
    std::uint8_t writableOnly;
    std::uint8_t privateOnly;
    std::uint8_t reserved[6];
    char rootModule[260];
};

struct CwGuiPointerStats {
    std::uint16_t pointerSize;
    std::uint8_t indexTruncated;
    std::uint8_t chainsTruncated;
    std::uint8_t cancelled;
    std::uint8_t reserved[3];
    std::uint64_t indexEntries;
    std::uint64_t chains;
    std::uint64_t bytesRead;
    std::uint64_t regionsRead;
    double indexMs;
    double searchMs;
};

struct CwGuiPointerChain {
    char module[256];
    std::uint64_t rootOffset;
    std::int64_t offsets[8];
    std::uint8_t depth;
    std::uint8_t resolved;
    std::uint8_t reserved[6];
    std::uint64_t resolvedAddress;
};

bool cw_gui_engine_start(char* error, std::size_t errorCapacity);
void cw_gui_engine_shutdown();

bool cw_gui_engine_exists();
bool cw_gui_engine_builder_exists();
bool cw_gui_engine_build(char* error, std::size_t errorCapacity);

bool cw_gui_engine_connected();
bool cw_gui_engine_attached();
std::uint32_t cw_gui_engine_pid();
std::uint32_t cw_gui_engine_pointer_size();

bool cw_gui_engine_list_processes(
    CwGuiProcessInfo* output,
    std::uint32_t capacity,
    std::uint32_t* count,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_list_modules(
    CwGuiModuleInfo* output,
    std::uint32_t capacity,
    std::uint32_t* count,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_attach(
    std::uint32_t pid,
    std::uint32_t* pointerSize,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_detach(char* error, std::size_t errorCapacity);

bool cw_gui_engine_read_value(
    std::uint64_t address,
    std::uint8_t valueType,
    std::uint8_t output[8],
    std::uint8_t* outputSize,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_write_value(
    std::uint64_t address,
    std::uint8_t valueType,
    const std::uint8_t* valueBytes,
    std::uint8_t valueSize,
    std::uint32_t* win32Error,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_read_bytes(
    std::uint64_t address,
    void* output,
    std::uint32_t size,
    std::uint32_t* bytesRead,
    std::uint32_t* win32Error,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_scan_first(
    std::uint8_t scanKind,
    std::uint8_t valueType,
    const char* valueText,
    const CwGuiScanOptions* options,
    CwGuiScanSummary* summary,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_scan_next(
    std::uint8_t scanMode,
    const char* valueText,
    CwGuiScanSummary* summary,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_scan_clear(char* error, std::size_t errorCapacity);

bool cw_gui_engine_scan_disable_type(
    std::uint8_t valueType,
    CwGuiScanSummary* summary,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_scan_results(
    std::uint64_t offset,
    CwGuiScanResult* output,
    std::uint32_t capacity,
    std::uint32_t* count,
    std::uint64_t* total,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_freeze_add(
    std::uint64_t address,
    std::uint8_t valueType,
    const std::uint8_t* valueBytes,
    std::uint8_t valueSize,
    std::uint32_t intervalMs,
    std::uint64_t* freezeId,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_freeze_remove(
    std::uint64_t freezeId,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_freeze_clear(char* error, std::size_t errorCapacity);

bool cw_gui_engine_freeze_list(
    CwGuiFreezeInfo* output,
    std::uint32_t capacity,
    std::uint32_t* count,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_pointer_scan(
    std::uint64_t target,
    const CwGuiPointerOptions* options,
    CwGuiPointerStats* stats,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_pointer_rescan(
    std::uint64_t target,
    std::uint64_t* before,
    std::uint64_t* after,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_pointer_chains(
    std::uint64_t offset,
    CwGuiPointerChain* output,
    std::uint32_t capacity,
    std::uint32_t* count,
    std::uint64_t* total,
    std::uint32_t* pointerSize,
    std::uint32_t* chainPointerSize,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_pointer_set_chains(
    const CwGuiPointerChain* chains,
    std::uint32_t count,
    std::uint32_t pointerSize,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_pointer_resolve(
    std::uint64_t index,
    std::uint64_t* address,
    char* error,
    std::size_t errorCapacity);

bool cw_gui_engine_pointer_clear(char* error, std::size_t errorCapacity);

} // extern "C"
