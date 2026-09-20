#include "GuiEngineBridge.hpp"

#include "cw/EngineClient.hpp"
#include "cw/EngineFrontend.hpp"
#include "cw/Value.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

cw::EngineClient g_client;
cw::EngineClientScanner g_scanner{g_client};
cw::EngineClientAobScanner g_aobScanner{g_client};
cw::EngineClientFreezeManager g_freezer{g_client};
cw::EngineClientPointerScanner g_pointerScanner{g_client};
std::mutex g_mutex;

void copyError(std::string_view text, char* output, std::size_t capacity) {
    if (!output || capacity == 0) return;
    const auto count = (std::min)(text.size(), capacity - 1);
    if (count != 0) std::memcpy(output, text.data(), count);
    output[count] = '\0';
}

void clearError(char* output, std::size_t capacity) {
    if (output && capacity != 0) output[0] = '\0';
}

std::wstring frontendDirectory() {
    std::array<wchar_t, 32768> buffer{};
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return L".";
    std::wstring path(buffer.data(), length);
    const auto slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L".";
    path.resize(slash);
    return path;
}

std::wstring siblingPath(std::wstring_view filename) {
    auto path = frontendDirectory();
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/') path.push_back(L'\\');
    path.append(filename);
    return path;
}

bool regularFileExists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), required, nullptr, nullptr) != required) return {};
    return result;
}

std::wstring utf8ToWide(std::string_view value) {
    if (value.empty()) return {};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) return {};
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), required) != required) return {};
    return result;
}

std::optional<cw::ValueType> valueTypeFromWire(std::uint8_t type) {
    switch (type) {
        case 0: return cw::ValueType::Byte;
        case 1: return cw::ValueType::Int16;
        case 2: return cw::ValueType::Int32;
        case 3: return cw::ValueType::Int64;
        case 4: return cw::ValueType::Float;
        case 5: return cw::ValueType::Double;
        default: return std::nullopt;
    }
}

std::size_t valueSize(cw::ValueType type) {
    switch (type) {
        case cw::ValueType::Byte: return sizeof(std::uint8_t);
        case cw::ValueType::Int16: return sizeof(std::int16_t);
        case cw::ValueType::Int32: return sizeof(std::int32_t);
        case cw::ValueType::Int64: return sizeof(std::int64_t);
        case cw::ValueType::Float: return sizeof(float);
        case cw::ValueType::Double: return sizeof(double);
    }
    return 0;
}

std::vector<std::byte> encodeValue(const cw::Value& value) {
    return std::visit([](const auto& typed) {
        std::vector<std::byte> bytes(sizeof(typed));
        std::memcpy(bytes.data(), &typed, sizeof(typed));
        return bytes;
    }, value);
}

std::optional<cw::Value> decodeValue(cw::ValueType type, const std::uint8_t* bytes, std::size_t size) {
    if (!bytes || size != valueSize(type)) return std::nullopt;
    auto decode = [&](auto tag) -> cw::Value {
        using T = decltype(tag);
        T value{};
        std::memcpy(&value, bytes, sizeof(value));
        return cw::Value{value};
    };
    switch (type) {
        case cw::ValueType::Byte: return decode(std::uint8_t{});
        case cw::ValueType::Int16: return decode(std::int16_t{});
        case cw::ValueType::Int32: return decode(std::int32_t{});
        case cw::ValueType::Int64: return decode(std::int64_t{});
        case cw::ValueType::Float: return decode(float{});
        case cw::ValueType::Double: return decode(double{});
    }
    return std::nullopt;
}

std::optional<cw::ScanMode> scanModeFromGui(std::uint8_t mode) {
    switch (mode) {
        case 0: return cw::ScanMode::Exact;
        case 1: return cw::ScanMode::Changed;
        case 2: return cw::ScanMode::Unchanged;
        case 3: return cw::ScanMode::Increased;
        case 4: return cw::ScanMode::Decreased;
        case 5: return cw::ScanMode::BiggerThan;
        case 6: return cw::ScanMode::SmallerThan;
        default: return std::nullopt;
    }
}

void fillScanSummary(const cw::ScanStats& stats, CwGuiScanSummary& out) {
    std::memset(&out, 0, sizeof(out));
    out.hasScan = g_scanner.hasScan() ? 1u : 0u;
    out.snapshotActive = g_scanner.unknownSnapshotActive() ? 1u : 0u;
    out.mixed = g_scanner.mixedScanActive() ? 1u : 0u;
    out.primaryType = out.mixed ? 6u : static_cast<std::uint8_t>(g_scanner.valueType());
    out.truncated = stats.truncated ? 1u : 0u;
    out.cancelled = stats.cancelled ? 1u : 0u;
    out.candidateCount = static_cast<std::uint64_t>(g_scanner.candidateCount());
    out.resultCount = static_cast<std::uint64_t>(g_scanner.resultCount());
    out.bytesRead = stats.bytesRead;
    out.regionsRead = stats.regionsRead;
    out.elapsedMs = stats.elapsedMs;
    const auto counts = g_scanner.candidateCountsByType();
    for (std::size_t i = 0; i < counts.size(); ++i) out.typeCounts[i] = static_cast<std::uint64_t>(counts[i]);
}

void copyValueRaw(const cw::Value& value, std::uint8_t output[8], std::uint8_t& size) {
    const auto bytes = encodeValue(value);
    std::memset(output, 0, 8);
    std::memcpy(output, bytes.data(), bytes.size());
    size = static_cast<std::uint8_t>(bytes.size());
}

} // namespace

extern "C" bool cw_gui_engine_start(char* error, std::size_t errorCapacity) {
    std::lock_guard lock(g_mutex);
    if (g_client.connected()) { clearError(error, errorCapacity); return true; }
    std::string message;
    const bool ok = g_client.start(message);
    if (ok) clearError(error, errorCapacity); else copyError(message, error, errorCapacity);
    return ok;
}

extern "C" void cw_gui_engine_shutdown() {
    std::lock_guard lock(g_mutex);
    g_client.shutdown();
}

extern "C" bool cw_gui_engine_exists() {
    return regularFileExists(siblingPath(L"cw-engine.exe"));
}

extern "C" bool cw_gui_engine_connected() {
    std::lock_guard lock(g_mutex);
    return g_client.connected();
}

extern "C" bool cw_gui_engine_attached() {
    std::lock_guard lock(g_mutex);
    return g_client.attached();
}

extern "C" std::uint32_t cw_gui_engine_pid() {
    std::lock_guard lock(g_mutex);
    return g_client.pid();
}

extern "C" std::uint32_t cw_gui_engine_pointer_size() {
    std::lock_guard lock(g_mutex);
    return static_cast<std::uint32_t>(g_client.targetPointerSize());
}

extern "C" bool cw_gui_engine_list_processes(
    CwGuiProcessInfo* output, std::uint32_t capacity, std::uint32_t* count,
    char* error, std::size_t errorCapacity)
{
    if (!count) { copyError("Invalid process output", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    std::vector<cw::ProcessInfo> processes;
    std::string message;
    if (!g_client.listProcesses(processes, message)) { copyError(message, error, errorCapacity); return false; }
    const auto written = (std::min)(processes.size(), static_cast<std::size_t>(capacity));
    if (written != 0 && !output) { copyError("Invalid process buffer", error, errorCapacity); return false; }
    for (std::size_t i = 0; i < written; ++i) {
        output[i].pid = processes[i].pid;
        const auto name = wideToUtf8(processes[i].name);
        const auto nameSize = (std::min)(name.size(), sizeof(output[i].name) - 1);
        if (nameSize != 0) std::memcpy(output[i].name, name.data(), nameSize);
        output[i].name[nameSize] = '\0';
    }
    *count = static_cast<std::uint32_t>(written);
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_list_modules(
    CwGuiModuleInfo* output, std::uint32_t capacity, std::uint32_t* count,
    char* error, std::size_t errorCapacity)
{
    if (!count) { copyError("Invalid module output", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    std::vector<cw::ModuleInfo> modules;
    std::string message;
    if (!g_client.listModules(modules, message)) { copyError(message, error, errorCapacity); return false; }
    const auto written = (std::min)(modules.size(), static_cast<std::size_t>(capacity));
    if (written != 0 && !output) { copyError("Invalid module buffer", error, errorCapacity); return false; }
    for (std::size_t i = 0; i < written; ++i) {
        output[i].base = modules[i].base;
        output[i].size = modules[i].size;
        const auto name = wideToUtf8(modules[i].name);
        const auto nameSize = (std::min)(name.size(), sizeof(output[i].name) - 1);
        if (nameSize != 0) std::memcpy(output[i].name, name.data(), nameSize);
        output[i].name[nameSize] = '\0';
    }
    *count = static_cast<std::uint32_t>(written);
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_attach(
    std::uint32_t pid, std::uint32_t* pointerSize, char* error, std::size_t errorCapacity)
{
    std::lock_guard lock(g_mutex);
    std::string message;
    if (!g_client.attach(pid, message)) { copyError(message, error, errorCapacity); return false; }
    g_scanner.setProcess(nullptr);
    g_aobScanner.setProcess(nullptr);
    std::vector<cw::ModuleInfo> modules;
    if (!g_client.listModules(modules, message)) {
        std::string ignored;
        g_client.detach(ignored);
        copyError(message, error, errorCapacity);
        return false;
    }
    g_pointerScanner.setContext(g_client.targetPointerSize(), std::move(modules));
    if (pointerSize) *pointerSize = static_cast<std::uint32_t>(g_client.targetPointerSize());
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_detach(char* error, std::size_t errorCapacity) {
    std::lock_guard lock(g_mutex);
    std::string message;
    const bool ok = g_client.detach(message);
    g_scanner.setProcess(nullptr);
    g_aobScanner.setProcess(nullptr);
    g_pointerScanner.setProcess(nullptr, 0, {});
    if (ok) clearError(error, errorCapacity); else copyError(message, error, errorCapacity);
    return ok;
}

extern "C" bool cw_gui_engine_read_value(
    std::uint64_t address, std::uint8_t valueType, std::uint8_t output[8], std::uint8_t* outputSize,
    char* error, std::size_t errorCapacity)
{
    const auto type = valueTypeFromWire(valueType);
    if (!type || !output || !outputSize) { copyError("Invalid read parameters", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    std::string message;
    const auto value = g_client.readValue(static_cast<std::uintptr_t>(address), *type, message);
    if (!value) { copyError(message, error, errorCapacity); return false; }
    const auto bytes = encodeValue(*value);
    std::memset(output, 0, 8);
    std::memcpy(output, bytes.data(), bytes.size());
    *outputSize = static_cast<std::uint8_t>(bytes.size());
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_write_value(
    std::uint64_t address, std::uint8_t valueType, const std::uint8_t* valueBytes, std::uint8_t valueSize,
    std::uint32_t* win32Error, char* error, std::size_t errorCapacity)
{
    const auto type = valueTypeFromWire(valueType);
    const auto value = type ? decodeValue(*type, valueBytes, valueSize) : std::nullopt;
    if (!type || !value) { copyError("Invalid write parameters", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    std::string message;
    const auto result = g_client.writeValue(static_cast<std::uintptr_t>(address), *value, message);
    if (win32Error) *win32Error = result.error;
    if (!result.ok) { copyError(message, error, errorCapacity); return false; }
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_read_bytes(
    std::uint64_t address, void* output, std::uint32_t size, std::uint32_t* bytesRead,
    std::uint32_t* win32Error, char* error, std::size_t errorCapacity)
{
    if (!output || size == 0 || !bytesRead) { copyError("Invalid raw-read parameters", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    std::size_t read = 0;
    DWORD readError = ERROR_SUCCESS;
    std::string message;
    const bool ok = g_client.readBytes(static_cast<std::uintptr_t>(address), output, size, read, readError, message);
    *bytesRead = static_cast<std::uint32_t>(read);
    if (win32Error) *win32Error = readError;
    if (!ok) { copyError(message, error, errorCapacity); return false; }
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_scan_first(
    std::uint8_t scanKind, std::uint8_t valueType, const char* valueText,
    const CwGuiScanOptions* options, CwGuiScanSummary* summary,
    char* error, std::size_t errorCapacity)
{
    if (!options || !summary || scanKind > 2 || valueType > 6) {
        copyError("Invalid first-scan parameters", error, errorCapacity);
        return false;
    }
    std::lock_guard lock(g_mutex);
    if (!g_client.attached()) { copyError("No process attached", error, errorCapacity); return false; }

    cw::ScanOptions scanOptions;
    scanOptions.alignment = options->alignmentByte ? cw::AlignmentMode::Byte : cw::AlignmentMode::Natural;
    scanOptions.writableOnly = options->writableOnly != 0;
    scanOptions.privateOnly = options->privateOnly != 0;
    scanOptions.minAddress = static_cast<std::uintptr_t>(options->minAddress);
    scanOptions.maxAddress = static_cast<std::uintptr_t>(options->maxAddress);
    scanOptions.floatTolerance = options->floatTolerance;
    g_scanner.setOptions(scanOptions);

    const std::string textValue = valueText ? valueText : "";
    cw::ScanStats stats{};
    if (valueType == 6) {
        if (scanKind == 0) stats = g_scanner.firstScanAllExact(textValue);
        else if (scanKind == 1) stats = g_scanner.firstScanAllUnknown();
        else stats = g_scanner.firstScanAllUnknownSmart();
    } else {
        const auto type = valueTypeFromWire(valueType);
        if (!type) { copyError("Invalid first-scan value type", error, errorCapacity); return false; }
        if (scanKind == 0) {
            const auto value = cw::parseValue(*type, textValue);
            if (!value) { copyError("Invalid first-scan value", error, errorCapacity); return false; }
            stats = g_scanner.firstScan(*type, *value);
        } else if (scanKind == 1) {
            stats = g_scanner.firstScanUnknown(*type);
        } else {
            stats = g_scanner.firstScanUnknownSmart(*type);
        }
    }
    fillScanSummary(stats, *summary);
    if (!summary->hasScan && !stats.cancelled) {
        copyError("Engine did not create a scan", error, errorCapacity);
        return false;
    }
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_scan_next(
    std::uint8_t scanMode, const char* valueText, CwGuiScanSummary* summary,
    char* error, std::size_t errorCapacity)
{
    if (!summary) { copyError("Invalid next-scan output", error, errorCapacity); return false; }
    const auto mode = scanModeFromGui(scanMode);
    if (!mode) { copyError("Invalid next-scan mode", error, errorCapacity); return false; }

    std::lock_guard lock(g_mutex);
    if (!g_client.attached() || !g_scanner.hasScan()) {
        copyError("No active scan", error, errorCapacity);
        return false;
    }
    const std::string textValue = valueText ? valueText : "";
    cw::ScanStats stats{};
    if (g_scanner.mixedScanActive()) {
        std::optional<std::string> wanted;
        if (cw::scanModeNeedsValue(*mode)) wanted = textValue;
        stats = g_scanner.nextScanMixed(*mode, wanted);
    } else {
        std::optional<cw::Value> wanted;
        if (cw::scanModeNeedsValue(*mode)) {
            wanted = cw::parseValue(g_scanner.valueType(), textValue);
            if (!wanted) { copyError("Invalid next-scan value", error, errorCapacity); return false; }
        }
        stats = g_scanner.nextScan(*mode, wanted);
    }
    fillScanSummary(stats, *summary);
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_scan_clear(char* error, std::size_t errorCapacity) {
    std::lock_guard lock(g_mutex);
    g_scanner.clear();
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_scan_disable_type(
    std::uint8_t valueType, CwGuiScanSummary* summary,
    char* error, std::size_t errorCapacity)
{
    const auto type = valueTypeFromWire(valueType);
    if (!type || !summary) { copyError("Invalid mixed-scan type", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    if (!g_scanner.disableMixedType(*type)) {
        copyError("Mixed-scan type could not be disabled", error, errorCapacity);
        return false;
    }
    cw::ScanStats stats{};
    stats.resultCount = g_scanner.resultCount();
    fillScanSummary(stats, *summary);
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_scan_results(
    std::uint64_t offset, CwGuiScanResult* output, std::uint32_t capacity, std::uint32_t* count, std::uint64_t* total,
    char* error, std::size_t errorCapacity)
{
    if (!count || !total) { copyError("Invalid scan-result output", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    const auto& results = g_scanner.results();
    *total = static_cast<std::uint64_t>(results.size());
    const auto begin = (std::min)(static_cast<std::size_t>(offset), results.size());
    const auto written = (std::min)(results.size() - begin, static_cast<std::size_t>(capacity));
    if (written != 0 && !output) { copyError("Invalid scan-result buffer", error, errorCapacity); return false; }

    for (std::size_t i = 0; i < written; ++i) {
        const auto resultIndex = begin + i;
        auto& dst = output[i];
        std::memset(&dst, 0, sizeof(dst));
        dst.address = static_cast<std::uint64_t>(results[resultIndex].address);
        dst.type = static_cast<std::uint8_t>(results[resultIndex].type);
        if (const auto previous = g_scanner.previousValue(results[resultIndex])) {
            std::uint8_t size = 0;
            copyValueRaw(*previous, dst.previous, size);
            dst.previousPresent = 1;
        }
    }
    *count = static_cast<std::uint32_t>(written);
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_freeze_add(
    std::uint64_t address, std::uint8_t valueType, const std::uint8_t* valueBytes, std::uint8_t valueSize,
    std::uint32_t intervalMs, std::uint64_t* freezeId, char* error, std::size_t errorCapacity)
{
    const auto type = valueTypeFromWire(valueType);
    const auto value = type ? decodeValue(*type, valueBytes, valueSize) : std::nullopt;
    if (!type || !value || !freezeId) { copyError("Invalid freeze parameters", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    const auto id = g_freezer.add(static_cast<std::uintptr_t>(address), *type, *value, intervalMs);
    if (!id) { copyError("Engine could not create freeze", error, errorCapacity); return false; }
    *freezeId = *id;
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_freeze_remove(
    std::uint64_t freezeId, char* error, std::size_t errorCapacity)
{
    if (freezeId == 0) { copyError("Invalid freeze id", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    if (!g_freezer.remove(freezeId)) { copyError("Engine could not remove freeze", error, errorCapacity); return false; }
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_freeze_clear(char* error, std::size_t errorCapacity) {
    std::lock_guard lock(g_mutex);
    g_freezer.clear();
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_freeze_list(
    CwGuiFreezeInfo* output, std::uint32_t capacity, std::uint32_t* count,
    char* error, std::size_t errorCapacity)
{
    if (!count) { copyError("Invalid freeze-list output", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    const auto items = g_freezer.list();
    const auto written = (std::min)(items.size(), static_cast<std::size_t>(capacity));
    if (written != 0 && !output) { copyError("Invalid freeze-list buffer", error, errorCapacity); return false; }
    for (std::size_t i = 0; i < written; ++i) {
        auto& dst = output[i];
        std::memset(&dst, 0, sizeof(dst));
        dst.id = items[i].id;
        dst.address = static_cast<std::uint64_t>(items[i].address);
        dst.type = static_cast<std::uint8_t>(items[i].type);
        std::uint8_t size = 0;
        copyValueRaw(items[i].value, dst.value, size);
        dst.valueSize = size;
        dst.intervalMs = items[i].intervalMs;
        dst.writes = items[i].writes;
        dst.failures = items[i].failures;
        dst.lastError = items[i].lastError;
    }
    *count = static_cast<std::uint32_t>(written);
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_pointer_scan(
    std::uint64_t target, const CwGuiPointerOptions* options, CwGuiPointerStats* stats,
    char* error, std::size_t errorCapacity)
{
    if (!options || !stats || options->maxDepth == 0 || options->maxDepth > 8 ||
        options->maxChains == 0 || options->maxChains > 10000) {
        copyError("Invalid pointer-scan parameters", error, errorCapacity);
        return false;
    }
    std::lock_guard lock(g_mutex);
    if (!g_client.attached()) { copyError("No process attached", error, errorCapacity); return false; }

    cw::PointerScanOptions native;
    native.maxDepth = options->maxDepth;
    native.alignment = options->alignment;
    native.maxChains = options->maxChains;
    native.maxIndexEntries = options->maxIndexEntries;
    native.maxCandidatesPerNode = options->maxCandidatesPerNode;
    native.maxSearchCandidates = options->maxSearchCandidates;
    native.maxOffset = static_cast<std::uintptr_t>(options->maxOffset);
    native.maxNegativeOffset = static_cast<std::uintptr_t>(options->maxNegativeOffset);
    native.writableOnly = options->writableOnly != 0;
    native.privateOnly = options->privateOnly != 0;
    if (options->searchMode > static_cast<std::uint8_t>(cw::PointerSearchMode::Targeted)) {
        copyError("Invalid pointer search mode", error, errorCapacity);
        return false;
    }
    native.searchMode = static_cast<cw::PointerSearchMode>(options->searchMode);
    if (options->rootModule[0]) {
        native.rootModuleName = utf8ToWide(options->rootModule);
        if (native.rootModuleName.empty()) {
            copyError("Invalid pointer root module", error, errorCapacity);
            return false;
        }
    }

    const auto result = g_pointerScanner.scan(static_cast<std::uintptr_t>(target), native);
    if (!g_pointerScanner.lastOperationOk()) {
        copyError(g_pointerScanner.lastError().empty() ? "Pointer scan failed" : g_pointerScanner.lastError(),
                  error, errorCapacity);
        return false;
    }
    std::memset(stats, 0, sizeof(*stats));
    stats->pointerSize = static_cast<std::uint16_t>(result.pointerSize);
    stats->indexTruncated = result.indexTruncated ? 1u : 0u;
    stats->chainsTruncated = result.chainsTruncated ? 1u : 0u;
    stats->cancelled = result.cancelled ? 1u : 0u;
    stats->searchBudgetHit = result.searchBudgetHit ? 1u : 0u;
    stats->branchLimitHit = result.branchLimitHit ? 1u : 0u;
    stats->targetedTruncated = result.targetedTruncated ? 1u : 0u;
    stats->targetedUsed = result.targetedUsed ? 1u : 0u;
    stats->targetedFallbackUsed = result.targetedFallbackUsed ? 1u : 0u;
    stats->indexEntries = static_cast<std::uint64_t>(result.indexEntries);
    stats->chains = static_cast<std::uint64_t>(result.chains);
    stats->bytesRead = result.bytesRead;
    stats->regionsRead = result.regionsRead;
    stats->directCandidates = static_cast<std::uint64_t>(result.directCandidates);
    stats->searchCandidates = static_cast<std::uint64_t>(result.searchCandidates);
    stats->targetedDepth = static_cast<std::uint64_t>(result.targetedDepth);
    stats->targetedFrontier = static_cast<std::uint64_t>(result.targetedFrontier);
    stats->targetedSlots = result.targetedSlots;
    stats->targetedMatches = result.targetedMatches;
    stats->indexMs = result.indexMs;
    stats->searchMs = result.searchMs;
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_pointer_rescan(
    std::uint64_t target, std::uint64_t* before, std::uint64_t* after,
    char* error, std::size_t errorCapacity)
{
    if (!before || !after) { copyError("Invalid pointer-rescan output", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    if (!g_client.attached()) { copyError("No process attached", error, errorCapacity); return false; }
    *before = static_cast<std::uint64_t>(g_pointerScanner.chains().size());
    *after = static_cast<std::uint64_t>(g_pointerScanner.rescan(static_cast<std::uintptr_t>(target)));
    if (!g_pointerScanner.lastOperationOk()) {
        copyError(g_pointerScanner.lastError().empty() ? "Pointer rescan failed" : g_pointerScanner.lastError(),
                  error, errorCapacity);
        return false;
    }
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_pointer_chains(
    std::uint64_t offset, CwGuiPointerChain* output, std::uint32_t capacity,
    std::uint32_t* count, std::uint64_t* total, std::uint32_t* pointerSize,
    std::uint32_t* chainPointerSize, char* error, std::size_t errorCapacity)
{
    if (!count || !total) { copyError("Invalid pointer-chain output", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    const auto& chains = g_pointerScanner.chains();
    *total = static_cast<std::uint64_t>(chains.size());
    if (pointerSize) *pointerSize = static_cast<std::uint32_t>(g_pointerScanner.pointerSize());
    if (chainPointerSize) *chainPointerSize = static_cast<std::uint32_t>(g_pointerScanner.chainPointerSize());
    const auto begin = (std::min)(static_cast<std::size_t>(offset), chains.size());
    const auto written = (std::min)(chains.size() - begin, static_cast<std::size_t>(capacity));
    if (written != 0 && !output) { copyError("Invalid pointer-chain buffer", error, errorCapacity); return false; }

    for (std::size_t i = 0; i < written; ++i) {
        const auto index = begin + i;
        auto& dst = output[i];
        std::memset(&dst, 0, sizeof(dst));
        const auto module = wideToUtf8(chains[index].moduleName);
        const auto moduleSize = (std::min)(module.size(), sizeof(dst.module) - 1);
        if (moduleSize) std::memcpy(dst.module, module.data(), moduleSize);
        dst.module[moduleSize] = '\0';
        dst.rootOffset = static_cast<std::uint64_t>(chains[index].rootOffset);
        dst.depth = static_cast<std::uint8_t>((std::min)(chains[index].offsets.size(), std::size_t{8}));
        for (std::size_t step = 0; step < dst.depth; ++step) dst.offsets[step] = chains[index].offsets[step];
        if (const auto resolved = g_pointerScanner.resolve(index)) {
            dst.resolved = 1;
            dst.resolvedAddress = static_cast<std::uint64_t>(*resolved);
        }
    }
    *count = static_cast<std::uint32_t>(written);
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_pointer_set_chains(
    const CwGuiPointerChain* chains, std::uint32_t count, std::uint32_t pointerSize,
    char* error, std::size_t errorCapacity)
{
    if (!chains || count == 0 || count > 10000 || (pointerSize != 4 && pointerSize != 8)) {
        copyError("Invalid pointer-chain input", error, errorCapacity);
        return false;
    }
    std::vector<cw::PointerChain> native;
    native.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        if (!chains[i].module[0] || chains[i].depth == 0 || chains[i].depth > 8) {
            copyError("Invalid pointer chain", error, errorCapacity);
            return false;
        }
        cw::PointerChain chain;
        chain.moduleName = utf8ToWide(chains[i].module);
        if (chain.moduleName.empty()) { copyError("Invalid pointer module name", error, errorCapacity); return false; }
        chain.rootOffset = static_cast<std::uintptr_t>(chains[i].rootOffset);
        chain.offsets.reserve(chains[i].depth);
        for (std::uint8_t step = 0; step < chains[i].depth; ++step) chain.offsets.push_back(chains[i].offsets[step]);
        native.push_back(std::move(chain));
    }

    std::lock_guard lock(g_mutex);
    if (!g_client.attached()) { copyError("No process attached", error, errorCapacity); return false; }
    g_pointerScanner.setChains(std::move(native), pointerSize);
    if (g_pointerScanner.chains().size() != count) {
        copyError("Engine rejected pointer chains", error, errorCapacity);
        return false;
    }
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_pointer_resolve(
    std::uint64_t index, std::uint64_t* address, char* error, std::size_t errorCapacity)
{
    if (!address) { copyError("Invalid pointer-resolve output", error, errorCapacity); return false; }
    std::lock_guard lock(g_mutex);
    if (index >= g_pointerScanner.chains().size()) {
        copyError("Pointer chain index is out of range", error, errorCapacity);
        return false;
    }
    const auto resolved = g_pointerScanner.resolve(static_cast<std::size_t>(index));
    if (!resolved) { copyError("Pointer chain could not be resolved", error, errorCapacity); return false; }
    *address = static_cast<std::uint64_t>(*resolved);
    clearError(error, errorCapacity);
    return true;
}

extern "C" bool cw_gui_engine_pointer_clear(char* error, std::size_t errorCapacity) {
    std::lock_guard lock(g_mutex);
    g_pointerScanner.clearIndex();
    g_pointerScanner.clearChains();
    clearError(error, errorCapacity);
    return true;
}
