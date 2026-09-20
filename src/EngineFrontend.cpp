#include "cw/EngineFrontend.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <span>
#include <utility>

namespace cw {
namespace {

std::optional<std::uint8_t> toWireType(ValueType type) {
    switch (type) {
        case ValueType::Byte: return std::uint8_t{1};
        case ValueType::Int16: return std::uint8_t{2};
        case ValueType::Int32: return std::uint8_t{3};
        case ValueType::Int64: return std::uint8_t{4};
        case ValueType::Float: return std::uint8_t{5};
        case ValueType::Double: return std::uint8_t{6};
    }
    return std::nullopt;
}

std::optional<ValueType> fromWireType(std::uint8_t type) {
    switch (type) {
        case 1: return ValueType::Byte;
        case 2: return ValueType::Int16;
        case 3: return ValueType::Int32;
        case 4: return ValueType::Int64;
        case 5: return ValueType::Float;
        case 6: return ValueType::Double;
        default: return std::nullopt;
    }
}

std::uint8_t toWireScanMode(ScanMode mode) {
    switch (mode) {
        case ScanMode::Exact: return 0;
        case ScanMode::Changed: return 1;
        case ScanMode::Unchanged: return 2;
        case ScanMode::Increased: return 3;
        case ScanMode::Decreased: return 4;
        case ScanMode::BiggerThan: return 5;
        case ScanMode::SmallerThan: return 6;
    }
    return 0;
}

std::uint64_t doubleToBits(double value) {
    std::uint64_t bits{};
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

double bitsToDouble(std::uint64_t bits) {
    double value{};
    std::memcpy(&value, &bits, sizeof(value));
    return value;
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

std::vector<std::byte> encodeValue(const Value& value) {
    return std::visit([](const auto& typed) {
        std::vector<std::byte> bytes(sizeof(typed));
        std::memcpy(bytes.data(), &typed, sizeof(typed));
        return bytes;
    }, value);
}

std::size_t wireValueSize(std::uint8_t type) {
    switch (type) {
        case 1: return sizeof(std::uint8_t);
        case 2: return sizeof(std::int16_t);
        case 3: return sizeof(std::int32_t);
        case 4: return sizeof(std::int64_t);
        case 5: return sizeof(float);
        case 6: return sizeof(double);
        default: return 0;
    }
}

template <typename T>
Value decodeTyped(std::span<const std::byte> bytes) {
    T value{};
    std::memcpy(&value, bytes.data(), sizeof(value));
    return Value{value};
}

std::optional<Value> decodeValue(std::uint8_t type, std::span<const std::byte> bytes) {
    if (bytes.size() != wireValueSize(type)) return std::nullopt;
    switch (type) {
        case 1: return decodeTyped<std::uint8_t>(bytes);
        case 2: return decodeTyped<std::int16_t>(bytes);
        case 3: return decodeTyped<std::int32_t>(bytes);
        case 4: return decodeTyped<std::int64_t>(bytes);
        case 5: return decodeTyped<float>(bytes);
        case 6: return decodeTyped<double>(bytes);
        default: return std::nullopt;
    }
}

std::uint64_t packValueBits(const Value& value) {
    return std::visit([](const auto& typed) {
        std::uint64_t bits{};
        std::memcpy(&bits, &typed, sizeof(typed));
        return bits;
    }, value);
}

std::optional<Value> valueFromBits(ValueType type, std::uint64_t bits) {
    switch (type) {
        case ValueType::Byte: return Value{unpackScanValue<std::uint8_t>(bits)};
        case ValueType::Int16: return Value{unpackScanValue<std::int16_t>(bits)};
        case ValueType::Int32: return Value{unpackScanValue<std::int32_t>(bits)};
        case ValueType::Int64: return Value{unpackScanValue<std::int64_t>(bits)};
        case ValueType::Float: return Value{unpackScanValue<float>(bits)};
        case ValueType::Double: return Value{unpackScanValue<double>(bits)};
    }
    return std::nullopt;
}

bool readOptionalValue(EngineBufferReader& reader, std::uint8_t wireType, std::optional<Value>& value) {
    std::uint8_t present = 0;
    std::uint8_t size = 0;
    if (!reader.readU8(present) || !reader.readU8(size)) return false;
    if (!present) { value.reset(); return size == 0; }
    const auto expected = wireValueSize(wireType);
    if (expected == 0 || size != expected) return false;
    std::array<std::byte, 8> bytes{};
    if (!reader.readBytes(std::span(bytes.data(), size))) return false;
    value = decodeValue(wireType, std::span(bytes.data(), size));
    return value.has_value();
}

void writeScanOptions(EngineBufferWriter& payload, const ScanOptions& options) {
    payload.writeU8(options.alignment == AlignmentMode::Natural ? 0u : 1u);
    std::uint8_t flags = 0;
    if (options.writableOnly) flags |= 0x1u;
    if (options.privateOnly) flags |= 0x2u;
    payload.writeU8(flags);
    payload.writeU64(static_cast<std::uint64_t>(options.minAddress));
    payload.writeU64(static_cast<std::uint64_t>(options.maxAddress));
    payload.writeU64(doubleToBits(options.floatTolerance));
}

} // namespace

void EngineClientScanner::resetStateLocal() {
    hasScan_ = false;
    snapshotActive_ = false;
    mixed_ = false;
    truncated_ = false;
    type_ = ValueType::Int32;
    candidateCount_ = 0;
    resultCount_ = 0;
    typeCounts_.fill(0);
    results_.clear();
    resultsLoaded_ = true;
    history_.clear();
}

void EngineClientScanner::clear() {
    if (client_ && client_->connected()) {
        EngineFrame response;
        std::string ignored;
        client_->transact(EngineMessageKind::NewScan, {}, response, ignored);
    }
    resetStateLocal();
}

void EngineClientScanner::setProcess(HANDLE process) {
    if (!process) resetStateLocal();
}

void EngineClientScanner::setOptions(const ScanOptions& options) {
    options_ = options;
    if (!std::isfinite(options_.floatTolerance) || options_.floatTolerance < 0.0) options_.floatTolerance = 0.0;
    clear();
}

bool EngineClientScanner::parseScanSummary(const EngineFrame& response, ScanStats& stats) {
    EngineBufferReader reader(response.payload);
    std::uint8_t hasScan = 0;
    std::uint8_t snapshot = 0;
    std::uint8_t mixed = 0;
    std::uint8_t wireType = 0;
    std::uint64_t candidates = 0;
    std::uint64_t resultCount = 0;
    std::uint64_t elapsedBits = 0;
    std::uint8_t truncated = 0;
    std::uint8_t cancelled = 0;
    if (!reader.readU8(hasScan) || !reader.readU8(snapshot) || !reader.readU8(mixed) ||
        !reader.readU8(wireType) || !reader.readU64(candidates) || !reader.readU64(resultCount) ||
        !reader.readU64(stats.bytesRead) || !reader.readU64(stats.regionsRead) ||
        !reader.readU64(elapsedBits) || !reader.readU8(truncated) || !reader.readU8(cancelled)) return false;
    std::array<std::uint64_t, 6> typeCounts{};
    for (auto& count : typeCounts) if (!reader.readU64(count)) return false;
    if (!reader.empty()) return false;

    const auto decodedType = fromWireType(wireType);
    if (!decodedType) return false;
    hasScan_ = hasScan != 0;
    snapshotActive_ = snapshot != 0;
    mixed_ = mixed != 0;
    type_ = *decodedType;
    candidateCount_ = static_cast<std::size_t>(candidates);
    resultCount_ = static_cast<std::size_t>(resultCount);
    for (std::size_t i = 0; i < typeCounts_.size(); ++i) typeCounts_[i] = static_cast<std::size_t>(typeCounts[i]);
    truncated_ = truncated != 0;
    stats.resultCount = resultCount_;
    stats.elapsedMs = bitsToDouble(elapsedBits);
    stats.truncated = truncated_;
    stats.cancelled = cancelled != 0;
    results_.clear();
    resultsLoaded_ = resultCount_ == 0;
    if (progressCallback_) progressCallback_(ScanProgress{stats.bytesRead, stats.regionsRead, stats.resultCount});
    return true;
}

ScanStats EngineClientScanner::runFirstScan(std::uint8_t kind, std::uint8_t wireType, const std::string& valueText) {
    ScanStats stats{};
    if (!client_ || !client_->connected()) return stats;
    EngineBufferWriter payload;
    payload.writeU8(kind);
    payload.writeU8(wireType);
    writeScanOptions(payload, options_);
    payload.writeString(valueText);
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::FirstScan, payload.take(), response, error) ||
        response.header.kind != EngineMessageKind::FirstScanResult || !parseScanSummary(response, stats)) return ScanStats{};
    history_.clear();
    return stats;
}

ScanStats EngineClientScanner::firstScan(ValueType type, const Value& wanted) {
    const auto wire = toWireType(type);
    if (!wire || !valueMatchesType(type, wanted)) return {};
    return runFirstScan(0, *wire, formatValue(wanted));
}

ScanStats EngineClientScanner::firstScanUnknown(ValueType type) {
    const auto wire = toWireType(type);
    return wire ? runFirstScan(1, *wire, "") : ScanStats{};
}

ScanStats EngineClientScanner::firstScanUnknownSmart(ValueType type) {
    const auto wire = toWireType(type);
    return wire ? runFirstScan(2, *wire, "") : ScanStats{};
}

ScanStats EngineClientScanner::firstScanAllExact(const std::string& text) { return runFirstScan(0, 0, text); }
ScanStats EngineClientScanner::firstScanAllUnknown() { return runFirstScan(1, 0, ""); }
ScanStats EngineClientScanner::firstScanAllUnknownSmart() { return runFirstScan(2, 0, ""); }

ScanStats EngineClientScanner::runNextScan(ScanMode mode, const std::string& valueText) {
    ScanStats stats{};
    if (!client_ || !client_->connected() || !hasScan_) return stats;
    const auto before = candidateCount_;
    const auto beforeByType = candidateCountsByType();
    EngineBufferWriter payload;
    payload.writeU8(toWireScanMode(mode));
    payload.writeString(valueText);
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::NextScan, payload.take(), response, error) ||
        response.header.kind != EngineMessageKind::NextScanResult || !parseScanSummary(response, stats)) return ScanStats{};
    ScanRefinementStep step;
    step.mode = mode;
    step.beforeCount = before;
    step.afterCount = candidateCount_;
    step.beforeByType = beforeByType;
    step.afterByType = candidateCountsByType();
    step.elapsedMs = stats.elapsedMs;
    history_.push_back(step);
    return stats;
}

ScanStats EngineClientScanner::nextScan(ScanMode mode, const std::optional<Value>& wanted) {
    return runNextScan(mode, wanted ? formatValue(*wanted) : std::string{});
}

ScanStats EngineClientScanner::nextScanMixed(ScanMode mode, const std::optional<std::string>& wantedText) {
    return runNextScan(mode, wantedText.value_or(std::string{}));
}

bool EngineClientScanner::fetchAllResults() const {
    if (resultsLoaded_) return true;
    results_.clear();
    std::uint64_t total = 0;
    std::uint32_t offset = 0;
    for (;;) {
        EngineBufferWriter payload;
        payload.writeU32(offset);
        payload.writeU32(2000);
        EngineFrame response;
        std::string error;
        if (!client_->transact(EngineMessageKind::GetScanResults, payload.take(), response, error) ||
            response.header.kind != EngineMessageKind::GetScanResultsResult) return false;
        EngineBufferReader reader(response.payload);
        std::uint8_t hasScan = 0, snapshot = 0, mixed = 0;
        std::uint64_t candidates = 0;
        std::uint32_t count = 0;
        if (!reader.readU8(hasScan) || !reader.readU8(snapshot) || !reader.readU8(mixed) ||
            !reader.readU64(candidates) || !reader.readU64(total) || !reader.readU32(count)) return false;
        if (offset == 0) {
            results_.reserve(static_cast<std::size_t>((std::min<std::uint64_t>)(total, 5'000'000ull)));
        }
        for (std::uint32_t i = 0; i < count; ++i) {
            std::uint64_t index = 0;
            std::uint64_t address = 0;
            std::uint8_t wireType = 0;
            if (!reader.readU64(index) || !reader.readU64(address) || !reader.readU8(wireType)) return false;
            const auto type = fromWireType(wireType);
            if (!type || index != static_cast<std::uint64_t>(results_.size())) return false;
            std::optional<Value> previous;
            std::optional<Value> current;
            if (!readOptionalValue(reader, wireType, previous) || !readOptionalValue(reader, wireType, current)) return false;
            results_.push_back(ScanResult{
                static_cast<std::uintptr_t>(address),
                previous ? packValueBits(*previous) : 0,
                *type
            });
        }
        if (!reader.empty()) return false;
        offset += count;
        if (count == 0 || offset >= total) break;
    }
    resultsLoaded_ = results_.size() == total;
    return resultsLoaded_;
}

const std::vector<ScanResult>& EngineClientScanner::results() const {
    fetchAllResults();
    return results_;
}

std::optional<Value> EngineClientScanner::readCurrent(std::uintptr_t address) const {
    std::string error;
    return client_ ? client_->readValue(address, type_, error) : std::nullopt;
}

std::optional<Value> EngineClientScanner::readCurrent(const ScanResult& result) const {
    std::string error;
    return client_ ? client_->readValue(result.address, result.type, error) : std::nullopt;
}

std::optional<Value> EngineClientScanner::previousValue(const ScanResult& result) const {
    return valueFromBits(result.type, result.previousBits);
}

std::array<std::size_t, 6> EngineClientScanner::candidateCountsByType() const {
    if (snapshotActive_) return typeCounts_;
    std::array<std::size_t, 6> counts{};
    fetchAllResults();
    for (const auto& result : results_) {
        const auto index = static_cast<std::size_t>(result.type);
        if (index < counts.size()) ++counts[index];
    }
    return counts;
}

bool EngineClientScanner::disableMixedType(ValueType type) {
    const auto wire = toWireType(type);
    if (!wire || !client_) return false;
    EngineBufferWriter payload;
    payload.writeU8(*wire);
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::DisableMixedType, payload.take(), response, error) ||
        response.header.kind != EngineMessageKind::DisableMixedTypeResult) return false;
    EngineBufferReader reader(response.payload);
    std::uint8_t changed = 0;
    std::uint64_t candidates = 0;
    if (!reader.readU8(changed) || !reader.readU64(candidates)) return false;
    for (std::size_t i = 0; i < typeCounts_.size(); ++i) {
        std::uint64_t count{};
        if (!reader.readU64(count)) return false;
        typeCounts_[i] = static_cast<std::size_t>(count);
    }
    if (!reader.empty()) return false;
    candidateCount_ = static_cast<std::size_t>(candidates);
    resultsLoaded_ = false;
    return changed != 0;
}

std::optional<GuidedWizardSuggestion> EngineClientScanner::guidedSuggestion(GuidedGoal goal) const noexcept {
    if (!hasScan_) return std::nullopt;
    GuidedWizardSuggestion out;
    switch (goal) {
        case GuidedGoal::Money: out.recommendedMode = ScanMode::Changed; break;
        case GuidedGoal::Health: out.recommendedMode = ScanMode::Decreased; break;
        case GuidedGoal::Ammo: out.recommendedMode = ScanMode::Decreased; break;
        case GuidedGoal::Generic: out.recommendedMode = ScanMode::Changed; break;
    }
    out.candidateCount = candidateCount_;
    out.refinementDepth = history_.size();
    out.snapshotActive = snapshotActive_;
    out.rankingAvailable = !snapshotActive_;
    out.inspectRecommended = !snapshotActive_ && candidateCount_ <= 100;
    return out;
}

std::vector<RankedScanResult> EngineClientScanner::rankedResults(std::size_t limit, GuidedGoal) const {
    fetchAllResults();
    const auto count = (std::min)(limit, results_.size());
    std::vector<RankedScanResult> ranked;
    ranked.reserve(count);
    for (std::size_t i = 0; i < count; ++i) ranked.push_back(RankedScanResult{i, 0, false, false, false});
    return ranked;
}

bool EngineClientScanner::restoreMaterializedScan(
    ValueType primaryType, bool mixed, const ScanOptions& options, std::vector<ScanResult> results)
{
    const auto wire = toWireType(primaryType);
    if (!wire || !client_ || results.size() > 900'000) return false;
    EngineBufferWriter payload;
    payload.writeU8(*wire);
    payload.writeU8(mixed ? 1u : 0u);
    writeScanOptions(payload, options);
    payload.writeU32(static_cast<std::uint32_t>(results.size()));
    for (const auto& result : results) {
        const auto resultWire = toWireType(result.type);
        if (!resultWire) return false;
        payload.writeU64(static_cast<std::uint64_t>(result.address));
        payload.writeU64(result.previousBits);
        payload.writeU8(*resultWire);
    }
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::RestoreScan, payload.take(), response, error) ||
        response.header.kind != EngineMessageKind::RestoreScanResult) return false;
    EngineBufferReader reader(response.payload);
    std::uint8_t ok = 0;
    std::uint64_t count = 0;
    if (!reader.readU8(ok) || !reader.readU64(count) || !reader.empty() || !ok || count != results.size()) return false;
    options_ = options;
    hasScan_ = true;
    snapshotActive_ = false;
    mixed_ = mixed;
    type_ = primaryType;
    candidateCount_ = results.size();
    resultCount_ = results.size();
    results_ = std::move(results);
    resultsLoaded_ = true;
    history_.clear();
    return true;
}

void EngineClientAobScanner::clearLocal() {
    pattern_.bytes.clear();
    results_.clear();
}

void EngineClientAobScanner::setProcess(HANDLE process) {
    if (!process) clearLocal();
}

void EngineClientAobScanner::clear() {
    if (client_ && client_->connected()) {
        EngineFrame response;
        std::string ignored;
        client_->transact(EngineMessageKind::AobClear, {}, response, ignored);
    }
    clearLocal();
}

ScanStats EngineClientAobScanner::scan(const AobPattern& pattern) {
    ScanStats stats{};
    if (!client_ || pattern.empty()) return stats;
    EngineBufferWriter payload;
    payload.writeU8(executableOnly_ ? 1u : 0u);
    payload.writeU8(options_.alignment == AlignmentMode::Natural ? 0u : 1u);
    std::uint8_t flags = 0;
    if (options_.writableOnly) flags |= 0x1u;
    if (options_.privateOnly) flags |= 0x2u;
    payload.writeU8(flags);
    payload.writeU64(static_cast<std::uint64_t>(options_.minAddress));
    payload.writeU64(static_cast<std::uint64_t>(options_.maxAddress));
    payload.writeU32(static_cast<std::uint32_t>(pattern.bytes.size()));
    for (const auto& byte : pattern.bytes) { payload.writeU8(byte.value); payload.writeU8(byte.mask); }
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::AobScan, payload.take(), response, error) ||
        response.header.kind != EngineMessageKind::AobScanResult) return stats;
    EngineBufferReader reader(response.payload);
    std::uint64_t resultCount = 0;
    std::uint64_t elapsedBits = 0;
    std::uint8_t truncated = 0, cancelled = 0;
    if (!reader.readU64(resultCount) || !reader.readU64(stats.bytesRead) || !reader.readU64(stats.regionsRead) ||
        !reader.readU64(elapsedBits) || !reader.readU8(truncated) || !reader.readU8(cancelled) || !reader.empty()) return {};
    stats.resultCount = static_cast<std::size_t>(resultCount);
    stats.elapsedMs = bitsToDouble(elapsedBits);
    stats.truncated = truncated != 0;
    stats.cancelled = cancelled != 0;
    pattern_ = pattern;
    results_.clear();
    if (!fetchAllResults()) return {};
    if (progressCallback_) progressCallback_(ScanProgress{stats.bytesRead, stats.regionsRead, stats.resultCount});
    return stats;
}

bool EngineClientAobScanner::fetchAllResults() {
    results_.clear();
    std::uint32_t offset = 0;
    std::uint64_t total = 0;
    for (;;) {
        EngineBufferWriter payload;
        payload.writeU32(offset);
        payload.writeU32(5000);
        EngineFrame response;
        std::string error;
        if (!client_->transact(EngineMessageKind::AobResults, payload.take(), response, error) ||
            response.header.kind != EngineMessageKind::AobResultsResult) return false;
        EngineBufferReader reader(response.payload);
        std::uint32_t patternCount = 0;
        if (!reader.readU32(patternCount) || patternCount > 1'000'000) return false;
        AobPattern remotePattern;
        remotePattern.bytes.reserve(patternCount);
        for (std::uint32_t i = 0; i < patternCount; ++i) {
            std::uint8_t value = 0, mask = 0;
            if (!reader.readU8(value) || !reader.readU8(mask)) return false;
            remotePattern.bytes.push_back(AobByte{value, mask});
        }
        std::uint32_t count = 0;
        if (!reader.readU64(total) || !reader.readU32(count)) return false;
        if (offset == 0) { pattern_ = std::move(remotePattern); results_.reserve(static_cast<std::size_t>(total)); }
        for (std::uint32_t i = 0; i < count; ++i) {
            std::uint64_t address = 0;
            if (!reader.readU64(address)) return false;
            results_.push_back(static_cast<std::uintptr_t>(address));
        }
        if (!reader.empty()) return false;
        offset += count;
        if (count == 0 || offset >= total) break;
    }
    return results_.size() == total;
}

void EngineClientAobScanner::restore(const AobPattern& pattern, std::vector<std::uintptr_t> results) {
    if (!client_ || pattern.empty() || results.size() > 1'000'000) { clearLocal(); return; }
    EngineBufferWriter payload;
    payload.writeU32(static_cast<std::uint32_t>(pattern.bytes.size()));
    for (const auto& byte : pattern.bytes) { payload.writeU8(byte.value); payload.writeU8(byte.mask); }
    payload.writeU32(static_cast<std::uint32_t>(results.size()));
    for (const auto address : results) payload.writeU64(static_cast<std::uint64_t>(address));
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::AobRestore, payload.take(), response, error) ||
        response.header.kind != EngineMessageKind::AobRestoreResult) { clearLocal(); return; }
    pattern_ = pattern;
    results_ = std::move(results);
}

bool EngineClientFreezeManager::setProcess(HANDLE process) {
    if (!process) clear();
    return true;
}

std::optional<std::uint64_t> EngineClientFreezeManager::add(
    std::uintptr_t address, ValueType type, const Value& value, std::uint32_t intervalMs)
{
    if (!client_) return std::nullopt;
    const auto wire = toWireType(type);
    if (!wire || !valueMatchesType(type, value)) return std::nullopt;
    const auto bytes = encodeValue(value);
    EngineBufferWriter payload;
    payload.writeU64(static_cast<std::uint64_t>(address));
    payload.writeU8(*wire);
    payload.writeU8(static_cast<std::uint8_t>(bytes.size()));
    payload.writeBytes(bytes);
    payload.writeU32(intervalMs);
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::SetFreeze, payload.take(), response, error) ||
        response.header.kind != EngineMessageKind::SetFreezeResult) return std::nullopt;
    EngineBufferReader reader(response.payload);
    std::uint8_t ok = 0;
    std::uint64_t id = 0;
    if (!reader.readU8(ok) || !reader.readU64(id) || !reader.empty() || !ok || id == 0) return std::nullopt;
    return id;
}

bool EngineClientFreezeManager::remove(std::uint64_t id) {
    if (!client_) return false;
    EngineBufferWriter payload;
    payload.writeU64(id);
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::RemoveFreeze, payload.take(), response, error) ||
        response.header.kind != EngineMessageKind::RemoveFreezeResult) return false;
    EngineBufferReader reader(response.payload);
    std::uint8_t removed = 0;
    return reader.readU8(removed) && reader.empty() && removed != 0;
}

void EngineClientFreezeManager::clear() {
    if (!client_ || !client_->connected()) return;
    EngineFrame response;
    std::string ignored;
    client_->transact(EngineMessageKind::ClearFreezes, {}, response, ignored);
}

std::vector<FreezeSnapshot> EngineClientFreezeManager::list() const {
    std::vector<FreezeSnapshot> out;
    if (!client_) return out;
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::ListFreezes, {}, response, error) ||
        response.header.kind != EngineMessageKind::ListFreezesResult) return out;
    EngineBufferReader reader(response.payload);
    std::uint32_t count = 0;
    if (!reader.readU32(count) || count > 100'000) return {};
    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        FreezeSnapshot item;
        std::uint64_t address = 0;
        std::uint8_t wire = 0;
        std::uint8_t size = 0;
        std::array<std::byte, 8> bytes{};
        std::uint32_t lastError = 0;
        if (!reader.readU64(item.id) || !reader.readU64(address) || !reader.readU8(wire) || !reader.readU8(size) ||
            size != wireValueSize(wire) || !reader.readBytes(std::span(bytes.data(), size)) ||
            !reader.readU32(item.intervalMs) || !reader.readU64(item.writes) || !reader.readU64(item.failures) ||
            !reader.readU32(lastError)) return {};
        const auto type = fromWireType(wire);
        const auto value = decodeValue(wire, std::span(bytes.data(), size));
        if (!type || !value) return {};
        item.address = static_cast<std::uintptr_t>(address);
        item.type = *type;
        item.value = *value;
        item.lastError = static_cast<DWORD>(lastError);
        out.push_back(std::move(item));
    }
    if (!reader.empty()) return {};
    return out;
}

std::size_t EngineClientFreezeManager::size() const { return list().size(); }

void EngineClientPointerScanner::setProcess(HANDLE process, std::size_t pointerSize, std::vector<ModuleInfo> modules) {
    if (!process) { pointerSize_ = 0; modules_.clear(); index_.clear(); resolved_.clear(); return; }
    setContext(pointerSize, std::move(modules));
}

void EngineClientPointerScanner::setContext(std::size_t pointerSize, std::vector<ModuleInfo> modules) {
    pointerSize_ = pointerSize;
    modules_ = std::move(modules);
    index_.clear();
}

bool EngineClientPointerScanner::writeOptions(EngineBufferWriter& payload, const PointerScanOptions& options) const {
    if (options.maxDepth == 0 || options.maxDepth > 64 || options.maxChains == 0 ||
        options.maxChains > 100'000 || options.maxIndexEntries == 0 || options.maxIndexEntries > 20'000'000 ||
        options.maxCandidatesPerNode == 0 || options.maxCandidatesPerNode > 100'000 ||
        options.maxSearchCandidates == 0 || options.maxSearchCandidates > 20'000'000) return false;
    payload.writeU16(static_cast<std::uint16_t>(options.maxDepth));
    payload.writeU64(static_cast<std::uint64_t>(options.maxOffset));
    payload.writeU64(static_cast<std::uint64_t>(options.maxNegativeOffset));
    payload.writeU32(static_cast<std::uint32_t>(options.maxChains));
    payload.writeU32(static_cast<std::uint32_t>(options.maxIndexEntries));
    payload.writeU32(static_cast<std::uint32_t>(options.maxCandidatesPerNode));
    payload.writeU32(static_cast<std::uint32_t>(options.maxSearchCandidates));
    payload.writeU16(static_cast<std::uint16_t>(options.alignment));
    std::uint8_t flags = 0;
    if (options.writableOnly) flags |= 0x1u;
    if (options.privateOnly) flags |= 0x2u;
    payload.writeU8(flags);
    const auto searchMode = static_cast<std::uint8_t>(options.searchMode);
    if (searchMode > static_cast<std::uint8_t>(PointerSearchMode::Targeted)) return false;
    payload.writeU8(searchMode);
    return payload.writeString(wideToUtf8(options.rootModuleName));
}

bool EngineClientPointerScanner::parseStats(const EngineFrame& response, PointerScanStats& stats) {
    EngineBufferReader reader(response.payload);
    std::uint16_t pointerSize = 0;
    std::uint64_t indexEntries = 0, chains = 0, indexMs = 0, searchMs = 0;
    std::uint64_t directCandidates = 0, searchCandidates = 0;
    std::uint64_t targetedDepth = 0, targetedFrontier = 0, targetedSlots = 0, targetedMatches = 0;
    std::uint8_t indexTruncated = 0, chainsTruncated = 0, searchBudgetHit = 0, branchLimitHit = 0;
    std::uint8_t targetedTruncated = 0, targetedUsed = 0, targetedFallbackUsed = 0, cancelled = 0;
    if (!reader.readU16(pointerSize) || !reader.readU64(indexEntries) || !reader.readU64(chains) ||
        !reader.readU64(stats.bytesRead) || !reader.readU64(stats.regionsRead) || !reader.readU64(indexMs) ||
        !reader.readU64(searchMs) || !reader.readU64(directCandidates) || !reader.readU64(searchCandidates) ||
        !reader.readU64(targetedDepth) || !reader.readU64(targetedFrontier) ||
        !reader.readU64(targetedSlots) || !reader.readU64(targetedMatches) ||
        !reader.readU8(indexTruncated) || !reader.readU8(chainsTruncated) ||
        !reader.readU8(searchBudgetHit) || !reader.readU8(branchLimitHit) ||
        !reader.readU8(targetedTruncated) || !reader.readU8(targetedUsed) ||
        !reader.readU8(targetedFallbackUsed) || !reader.readU8(cancelled) || !reader.empty()) return false;
    stats.pointerSize = pointerSize;
    stats.indexEntries = static_cast<std::size_t>(indexEntries);
    stats.chains = static_cast<std::size_t>(chains);
    stats.indexMs = bitsToDouble(indexMs);
    stats.searchMs = bitsToDouble(searchMs);
    stats.directCandidates = static_cast<std::size_t>(directCandidates);
    stats.searchCandidates = static_cast<std::size_t>(searchCandidates);
    stats.targetedDepth = static_cast<std::size_t>(targetedDepth);
    stats.targetedFrontier = static_cast<std::size_t>(targetedFrontier);
    stats.targetedSlots = targetedSlots;
    stats.targetedMatches = targetedMatches;
    stats.indexTruncated = indexTruncated != 0;
    stats.chainsTruncated = chainsTruncated != 0;
    stats.searchBudgetHit = searchBudgetHit != 0;
    stats.branchLimitHit = branchLimitHit != 0;
    stats.targetedTruncated = targetedTruncated != 0;
    stats.targetedUsed = targetedUsed != 0;
    stats.targetedFallbackUsed = targetedFallbackUsed != 0;
    stats.cancelled = cancelled != 0;
    pointerSize_ = pointerSize;
    return true;
}

bool EngineClientPointerScanner::fetchChains() {
    chains_.clear();
    resolved_.clear();
    std::uint32_t offset = 0;
    std::uint64_t total = 0;
    for (;;) {
        EngineBufferWriter payload;
        payload.writeU32(offset);
        payload.writeU32(1000);
        EngineFrame response;
        std::string error;
        if (!client_->transact(EngineMessageKind::PointerResults, payload.take(), response, error) ||
            response.header.kind != EngineMessageKind::PointerResultsResult) return false;
        EngineBufferReader reader(response.payload);
        std::uint16_t pointerSize = 0, chainPointerSize = 0;
        std::uint32_t count = 0;
        if (!reader.readU16(pointerSize) || !reader.readU16(chainPointerSize) || !reader.readU64(total) || !reader.readU32(count)) return false;
        if (offset == 0) {
            pointerSize_ = pointerSize;
            chainPointerSize_ = chainPointerSize;
            chains_.reserve(static_cast<std::size_t>(total));
            resolved_.reserve(static_cast<std::size_t>(total));
        }
        for (std::uint32_t i = 0; i < count; ++i) {
            std::string moduleName;
            std::uint64_t rootOffset = 0;
            std::uint16_t depth = 0;
            if (!reader.readString(moduleName) || !reader.readU64(rootOffset) || !reader.readU16(depth) || depth > 64) return false;
            PointerChain chain;
            chain.moduleName = utf8ToWide(moduleName);
            chain.rootOffset = static_cast<std::uintptr_t>(rootOffset);
            chain.offsets.reserve(depth);
            for (std::uint16_t step = 0; step < depth; ++step) {
                std::int64_t value = 0;
                if (!reader.readI64(value)) return false;
                chain.offsets.push_back(value);
            }
            std::uint8_t hasResolved = 0;
            std::uint64_t resolved = 0;
            if (!reader.readU8(hasResolved) || !reader.readU64(resolved)) return false;
            chains_.push_back(std::move(chain));
            resolved_.push_back(hasResolved ? std::optional<std::uintptr_t>(static_cast<std::uintptr_t>(resolved)) : std::nullopt);
        }
        if (!reader.empty()) return false;
        offset += count;
        if (count == 0 || offset >= total) break;
    }
    return chains_.size() == total;
}

bool EngineClientPointerScanner::fetchIndex() {
    index_.clear();
    std::uint32_t offset = 0;
    std::uint64_t total = 0;
    for (;;) {
        EngineBufferWriter payload;
        payload.writeU32(offset);
        payload.writeU32(5000);
        EngineFrame response;
        std::string error;
        if (!client_->transact(EngineMessageKind::PointerIndexResults, payload.take(), response, error) ||
            response.header.kind != EngineMessageKind::PointerIndexResultsResult) return false;
        EngineBufferReader reader(response.payload);
        std::uint32_t count = 0;
        if (!reader.readU64(total) || !reader.readU32(count)) return false;
        if (offset == 0) index_.reserve(static_cast<std::size_t>(total));
        for (std::uint32_t i = 0; i < count; ++i) {
            std::uint64_t value = 0, address = 0;
            if (!reader.readU64(value) || !reader.readU64(address)) return false;
            index_.push_back(PointerEntry{static_cast<std::uintptr_t>(value), static_cast<std::uintptr_t>(address)});
        }
        if (!reader.empty()) return false;
        offset += count;
        if (count == 0 || offset >= total) break;
    }
    return index_.size() == total;
}

PointerScanStats EngineClientPointerScanner::captureIndex(const PointerScanOptions& options) {
    PointerScanStats stats{};
    lastOperationOk_ = false;
    lastError_.clear();
    if (!client_) { lastError_ = "Engine pointer client is unavailable"; return stats; }
    EngineBufferWriter payload;
    if (!writeOptions(payload, options)) { lastError_ = "Invalid pointer-index options"; return stats; }
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::PointerCaptureIndex, payload.take(), response, error)) {
        lastError_ = error.empty() ? "Pointer index RPC failed" : error;
        return stats;
    }
    if (response.header.kind != EngineMessageKind::PointerCaptureIndexResult) {
        lastError_ = "Unexpected PointerCaptureIndex response";
        return stats;
    }
    if (!parseStats(response, stats)) {
        lastError_ = "Malformed PointerCaptureIndex response";
        return stats;
    }
    if (!fetchIndex()) {
        lastError_ = "Could not fetch pointer index results";
        return stats;
    }
    lastOperationOk_ = true;
    if (progressCallback_) progressCallback_(PointerProgress{stats.bytesRead, stats.regionsRead, stats.indexEntries});
    return stats;
}

PointerScanStats EngineClientPointerScanner::scan(std::uintptr_t target, const PointerScanOptions& options) {
    PointerScanStats stats{};
    lastOperationOk_ = false;
    lastError_.clear();
    if (!client_) { lastError_ = "Engine pointer client is unavailable"; return stats; }
    EngineBufferWriter payload;
    payload.writeU64(static_cast<std::uint64_t>(target));
    if (!writeOptions(payload, options)) { lastError_ = "Invalid pointer-scan options"; return stats; }
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::PointerDiscover, payload.take(), response, error)) {
        lastError_ = error.empty() ? "PointerDiscover RPC failed" : error;
        return stats;
    }
    if (response.header.kind != EngineMessageKind::PointerDiscoverResult) {
        lastError_ = "Unexpected PointerDiscover response";
        return stats;
    }
    if (!parseStats(response, stats)) {
        lastError_ = "Malformed PointerDiscover response";
        return stats;
    }
    if (!fetchChains()) {
        lastError_ = "Could not fetch pointer chains";
        return stats;
    }
    index_.clear();
    lastOperationOk_ = true;
    if (progressCallback_) progressCallback_(PointerProgress{stats.bytesRead, stats.regionsRead, stats.indexEntries});
    return stats;
}

std::size_t EngineClientPointerScanner::rescan(std::uintptr_t target) {
    lastOperationOk_ = false;
    lastError_.clear();
    if (!client_) { lastError_ = "Engine pointer client is unavailable"; return 0; }
    EngineBufferWriter payload;
    payload.writeU64(static_cast<std::uint64_t>(target));
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::PointerRescan, payload.take(), response, error)) {
        lastError_ = error.empty() ? "PointerRescan RPC failed" : error;
        return chains_.size();
    }
    if (response.header.kind != EngineMessageKind::PointerRescanResult) {
        lastError_ = "Unexpected PointerRescan response";
        return chains_.size();
    }
    EngineBufferReader reader(response.payload);
    std::uint64_t before = 0, after = 0;
    if (!reader.readU64(before) || !reader.readU64(after) || !reader.empty()) {
        lastError_ = "Malformed PointerRescan response";
        return chains_.size();
    }
    if (!fetchChains()) {
        lastError_ = "Could not fetch rescanned pointer chains";
        return chains_.size();
    }
    lastOperationOk_ = true;
    return static_cast<std::size_t>(after);
}

void EngineClientPointerScanner::clearIndex() {
    if (client_ && client_->connected()) {
        EngineBufferWriter payload; payload.writeU8(0x1u);
        EngineFrame response; std::string ignored; client_->transact(EngineMessageKind::PointerClear, payload.take(), response, ignored);
    }
    index_.clear();
}

void EngineClientPointerScanner::clearChains() {
    if (client_ && client_->connected()) {
        EngineBufferWriter payload; payload.writeU8(0x2u);
        EngineFrame response; std::string ignored; client_->transact(EngineMessageKind::PointerClear, payload.take(), response, ignored);
    }
    chains_.clear();
    resolved_.clear();
    chainPointerSize_ = 0;
}

void EngineClientPointerScanner::setChains(std::vector<PointerChain> chains, std::size_t sourcePointerSize) {
    if (!client_ || (sourcePointerSize != 4 && sourcePointerSize != 8) || chains.size() > 100'000) return;
    EngineBufferWriter payload;
    payload.writeU16(static_cast<std::uint16_t>(sourcePointerSize));
    payload.writeU32(static_cast<std::uint32_t>(chains.size()));
    for (const auto& chain : chains) {
        payload.writeString(wideToUtf8(chain.moduleName));
        payload.writeU64(static_cast<std::uint64_t>(chain.rootOffset));
        payload.writeU16(static_cast<std::uint16_t>((std::min)(chain.offsets.size(), std::size_t{64})));
        for (std::size_t i = 0; i < chain.offsets.size() && i < 64; ++i) payload.writeI64(chain.offsets[i]);
    }
    EngineFrame response;
    std::string error;
    if (!client_->transact(EngineMessageKind::SetPointerChains, payload.take(), response, error) ||
        response.header.kind != EngineMessageKind::SetPointerChainsResult) return;
    chains_ = std::move(chains);
    chainPointerSize_ = sourcePointerSize;
    fetchChains();
}

std::optional<std::uintptr_t> EngineClientPointerScanner::resolve(std::size_t chainIndex) const {
    if (chainIndex >= resolved_.size()) return std::nullopt;
    return resolved_[chainIndex];
}

EngineFrontendSession::EngineFrontendSession()
    : scanner_(client_), aobScanner_(client_), freezer_(client_), pointerScanner_(client_) {}

EngineFrontendSession::~EngineFrontendSession() { shutdown(); }

bool EngineFrontendSession::start(std::string& error) { return client_.start(error); }

void EngineFrontendSession::shutdown() noexcept { client_.shutdown(); }

std::vector<ProcessInfo> EngineFrontendSession::listProcesses() const {
    std::vector<ProcessInfo> out;
    std::string ignored;
    client_.listProcesses(out, ignored);
    return out;
}

std::vector<ModuleInfo> EngineFrontendSession::listModules(std::string& error) const {
    std::vector<ModuleInfo> out;
    client_.listModules(out, error);
    return out;
}

bool EngineFrontendSession::attach(DWORD pid, std::string& error) {
    if (!client_.attach(pid, error)) return false;
    scanner_.setProcess(nullptr);
    aobScanner_.setProcess(nullptr);
    return refreshPointerContext(error);
}

bool EngineFrontendSession::attachByName(const std::wstring& name, std::string& error) {
    if (!client_.attachByName(name, error)) return false;
    scanner_.setProcess(nullptr);
    aobScanner_.setProcess(nullptr);
    return refreshPointerContext(error);
}

void EngineFrontendSession::detach() {
    std::string ignored;
    client_.detach(ignored);
    scanner_.setProcess(nullptr);
    aobScanner_.setProcess(nullptr);
    pointerScanner_.setProcess(nullptr, 0, {});
}

std::size_t EngineFrontendSession::targetPointerSize(std::string& error) const {
    if (!client_.attached()) { error = "No process attached"; return 0; }
    const auto size = client_.targetPointerSize();
    if (size != 4 && size != 8) { error = "Invalid target pointer size"; return 0; }
    error.clear();
    return size;
}

bool EngineFrontendSession::refreshPointerContext(std::string& error) {
    if (!client_.attached()) { error = "No process attached"; return false; }
    std::vector<ModuleInfo> modules;
    if (!client_.listModules(modules, error)) return false;
    pointerScanner_.setContext(client_.targetPointerSize(), std::move(modules));
    error.clear();
    return true;
}

void EngineFrontendSession::clearScans() { scanner_.clear(); aobScanner_.clear(); }

bool EngineFrontendSession::readBytes(
    std::uintptr_t address, void* buffer, std::size_t size, std::size_t& bytesRead, DWORD& error) const
{
    std::string ignored;
    return client_.readBytes(address, buffer, size, bytesRead, error, ignored);
}

std::optional<Value> EngineFrontendSession::readValue(std::uintptr_t address, ValueType type) const {
    std::string ignored;
    return client_.readValue(address, type, ignored);
}

WriteResult EngineFrontendSession::writeValue(std::uintptr_t address, const Value& value) const {
    std::string ignored;
    return client_.writeValue(address, value, ignored);
}

} // namespace cw
