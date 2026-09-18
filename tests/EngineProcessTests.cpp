#include "cw/EnginePipe.hpp"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

volatile std::int32_t* gPointerProbe = nullptr;

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

bool skipOptionalValue(cw::EngineBufferReader& reader) {
    std::uint8_t present = 0;
    std::uint8_t size = 0;
    if (!reader.readU8(present) || !reader.readU8(size)) return false;
    if (!present) return size == 0;
    if (size == 0 || size > 8) return false;
    std::array<std::byte, 8> bytes{};
    return reader.readBytes(std::span(bytes.data(), size));
}

bool expect(bool condition, const char* message) {
    if (condition) return true;
    std::cerr << "FAIL: " << message << '\n';
    return false;
}

std::wstring quote(const std::wstring& value) {
    return L"\"" + value + L"\"";
}

bool transact(
    cw::EnginePipeClient& client,
    cw::EngineMessageKind kind,
    std::uint64_t requestId,
    std::vector<std::byte> payload,
    cw::EngineFrame& response,
    std::string& error)
{
    cw::EngineFrame request;
    request.header.kind = kind;
    request.header.requestId = requestId;
    request.payload = std::move(payload);
    return client.send(request, error) && client.receive(response, error);
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::cerr << "EngineProcessTests requires path to cw-engine.exe\n";
        return 2;
    }

    bool ok = true;
    const DWORD ownerPid = GetCurrentProcessId();
    const std::wstring pipeName = L"\\\\.\\pipe\\CheatWizard.Engine.ProcessTest." +
        std::to_wstring(ownerPid) + L"." + std::to_wstring(GetTickCount64());

    std::wstring command = quote(argv[1]) + L" --pipe " + quote(pipeName) +
        L" --owner-pid " + std::to_wstring(ownerPid);
    std::vector<wchar_t> commandLine(command.begin(), command.end());
    commandLine.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(argv[1], commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &process)) {
        std::cerr << "CreateProcessW failed: " << GetLastError() << '\n';
        return 3;
    }
    CloseHandle(process.hThread);

    cw::EnginePipeClient client;
    std::string error;
    if (!client.connect(pipeName, 5000, error)) {
        std::cerr << "Engine client connect failed: " << error << '\n';
        TerminateProcess(process.hProcess, 90);
        CloseHandle(process.hProcess);
        return 4;
    }

    std::uint64_t requestId = 1;
    cw::EngineBufferWriter helloPayload;
    helloPayload.writeString("engine-process-test");
    cw::EngineFrame response;
    ok &= expect(transact(client, cw::EngineMessageKind::Hello, requestId++, helloPayload.take(), response, error),
                 "Hello transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::HelloAck, "HelloAck response");

    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::ListProcesses, requestId++, {}, response, error),
                 "ListProcesses transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::ListProcessesResult, "ListProcessesResult response");
    cw::EngineBufferReader processReader(response.payload);
    std::uint32_t processCount{};
    ok &= expect(processReader.readU32(processCount) && processCount > 0, "process list not empty");
    bool foundOwner = false;
    for (std::uint32_t i = 0; i < processCount; ++i) {
        std::uint32_t pid{};
        std::string name;
        if (!processReader.readU32(pid) || !processReader.readString(name)) { ok = false; break; }
        if (pid == ownerPid) foundOwner = true;
    }
    ok &= expect(foundOwner && processReader.empty(), "owner process appears in process list");

    cw::EngineBufferWriter attachPayload;
    attachPayload.writeU32(ownerPid);
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::AttachProcess, requestId++, attachPayload.take(), response, error),
                 "AttachProcess transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::AttachProcessResult, "AttachProcessResult response");
    cw::EngineBufferReader attachReader(response.payload);
    std::uint8_t attachOk{};
    std::uint32_t attachedPid{};
    std::uint16_t pointerSize{};
    std::string attachError;
    ok &= expect(attachReader.readU8(attachOk) && attachOk == 1, "attach succeeded");
    ok &= expect(attachReader.readU32(attachedPid) && attachedPid == ownerPid, "attached PID matches owner");
    ok &= expect(attachReader.readU16(pointerSize) && (pointerSize == 4 || pointerSize == 8), "pointer size valid");
    ok &= expect(attachReader.readString(attachError) && attachReader.empty(), "attach payload complete");

    volatile std::int32_t probe = 123456789;
    const auto probeAddress = reinterpret_cast<std::uintptr_t>(const_cast<std::int32_t*>(&probe));

    cw::EngineBufferWriter readPayload;
    readPayload.writeU64(probeAddress);
    readPayload.writeU8(3); // Int32
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::ReadValue, requestId++, readPayload.take(), response, error),
                 "ReadValue transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::ReadValueResult, "ReadValueResult response");
    cw::EngineBufferReader readReader(response.payload);
    std::uint8_t readOk{};
    std::uint8_t readType{};
    std::uint32_t readError{};
    std::uint8_t readSize{};
    std::array<std::byte, 4> readBytes{};
    ok &= expect(readReader.readU8(readOk) && readOk == 1, "remote read succeeded");
    ok &= expect(readReader.readU8(readType) && readType == 3, "remote read type");
    ok &= expect(readReader.readU32(readError) && readError == ERROR_SUCCESS, "remote read error code");
    ok &= expect(readReader.readU8(readSize) && readSize == 4, "remote read size");
    ok &= expect(readReader.readBytes(readBytes) && readReader.empty(), "remote read bytes");
    std::int32_t remoteValue{};
    std::memcpy(&remoteValue, readBytes.data(), sizeof(remoteValue));
    ok &= expect(remoteValue == probe, "remote read value matches");

    const std::int32_t wanted = 987654321;
    cw::EngineBufferWriter writePayload;
    writePayload.writeU64(probeAddress);
    writePayload.writeU8(3); // Int32
    writePayload.writeU8(sizeof(wanted));
    writePayload.writeBytes(std::as_bytes(std::span(&wanted, 1)));
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::WriteValue, requestId++, writePayload.take(), response, error),
                 "WriteValue transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::WriteValueResult, "WriteValueResult response");
    cw::EngineBufferReader writeReader(response.payload);
    std::uint8_t writeOk{};
    std::uint32_t written{};
    std::uint32_t writeError{};
    ok &= expect(writeReader.readU8(writeOk) && writeOk == 1, "remote write succeeded");
    ok &= expect(writeReader.readU32(written) && written == sizeof(wanted), "remote write size");
    ok &= expect(writeReader.readU32(writeError) && writeError == ERROR_SUCCESS && writeReader.empty(),
                 "remote write error code");
    ok &= expect(probe == wanted, "remote write changed owner memory");

    // Targeted exact scan around the probe address.
    cw::EngineBufferWriter firstScanPayload;
    firstScanPayload.writeU8(0); // exact
    firstScanPayload.writeU8(3); // Int32
    firstScanPayload.writeU8(1); // byte alignment
    firstScanPayload.writeU8(0x3); // writable + private
    firstScanPayload.writeU64(probeAddress - 64);
    firstScanPayload.writeU64(probeAddress + 64);
    firstScanPayload.writeU64(0); // float tolerance = 0.0 bits
    firstScanPayload.writeString(std::to_string(wanted));
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::FirstScan, requestId++, firstScanPayload.take(), response, error),
                 "FirstScan transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::FirstScanResult, "FirstScanResult response");
    cw::EngineBufferReader firstScanReader(response.payload);
    std::uint8_t hasScan{};
    std::uint8_t snapshotActive{};
    std::uint8_t mixedScan{};
    std::uint8_t primaryType{};
    std::uint64_t candidateCount{};
    std::uint64_t resultCount{};
    std::uint64_t scanBytes{};
    std::uint64_t scanRegions{};
    std::uint64_t scanElapsed{};
    std::uint8_t scanTruncated{};
    std::uint8_t scanCancelled{};
    ok &= expect(firstScanReader.readU8(hasScan) && hasScan == 1, "FirstScan active");
    ok &= expect(firstScanReader.readU8(snapshotActive) && snapshotActive == 0, "FirstScan materialized");
    ok &= expect(firstScanReader.readU8(mixedScan) && mixedScan == 0, "FirstScan typed");
    ok &= expect(firstScanReader.readU8(primaryType) && primaryType == 3, "FirstScan type");
    ok &= expect(firstScanReader.readU64(candidateCount) && candidateCount >= 1, "FirstScan candidates");
    ok &= expect(firstScanReader.readU64(resultCount) && resultCount >= 1, "FirstScan result count");
    ok &= expect(firstScanReader.readU64(scanBytes), "FirstScan bytes");
    ok &= expect(firstScanReader.readU64(scanRegions), "FirstScan regions");
    ok &= expect(firstScanReader.readU64(scanElapsed), "FirstScan elapsed");
    ok &= expect(firstScanReader.readU8(scanTruncated), "FirstScan truncated flag");
    ok &= expect(firstScanReader.readU8(scanCancelled) && scanCancelled == 0, "FirstScan completion flags");
    std::array<std::uint64_t, 6> firstTypeCounts{};
    for (auto& count : firstTypeCounts) ok &= expect(firstScanReader.readU64(count), "FirstScan type count");
    ok &= expect(firstTypeCounts[2] >= 1 && firstScanReader.empty(), "FirstScan type counts complete");

    cw::EngineBufferWriter scanResultsPayload;
    scanResultsPayload.writeU32(0);
    scanResultsPayload.writeU32(128);
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::GetScanResults, requestId++, scanResultsPayload.take(), response, error),
                 "GetScanResults transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::GetScanResultsResult, "GetScanResultsResult response");
    cw::EngineBufferReader scanResultsReader(response.payload);
    std::uint8_t resultsHasScan{};
    std::uint8_t resultsSnapshot{};
    std::uint8_t resultsMixed{};
    std::uint64_t resultsCandidates{};
    std::uint64_t totalResults{};
    std::uint32_t returnedResults{};
    ok &= expect(scanResultsReader.readU8(resultsHasScan) && resultsHasScan == 1, "results active");
    ok &= expect(scanResultsReader.readU8(resultsSnapshot) && resultsSnapshot == 0, "results materialized");
    ok &= expect(scanResultsReader.readU8(resultsMixed) && resultsMixed == 0, "results typed");
    ok &= expect(scanResultsReader.readU64(resultsCandidates), "results candidate count");
    ok &= expect(scanResultsReader.readU64(totalResults) && totalResults >= 1, "results total");
    ok &= expect(scanResultsReader.readU32(returnedResults) && returnedResults >= 1, "results page");
    bool foundProbeResult = false;
    for (std::uint32_t i = 0; i < returnedResults; ++i) {
        std::uint64_t resultIndex{};
        std::uint64_t resultAddress{};
        std::uint8_t resultType{};
        if (!scanResultsReader.readU64(resultIndex) || !scanResultsReader.readU64(resultAddress) ||
            !scanResultsReader.readU8(resultType) || !skipOptionalValue(scanResultsReader) ||
            !skipOptionalValue(scanResultsReader)) {
            ok = false;
            break;
        }
        if (resultAddress == probeAddress && resultType == 3) foundProbeResult = true;
    }
    ok &= expect(foundProbeResult && scanResultsReader.empty(), "scan page contains probe address");

    probe = wanted + 1;
    cw::EngineBufferWriter nextScanPayload;
    nextScanPayload.writeU8(1); // changed
    nextScanPayload.writeString("");
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::NextScan, requestId++, nextScanPayload.take(), response, error),
                 "NextScan transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::NextScanResult, "NextScanResult response");
    cw::EngineBufferReader nextScanReader(response.payload);
    ok &= expect(nextScanReader.readU8(hasScan) && hasScan == 1, "NextScan active");
    ok &= expect(nextScanReader.readU8(snapshotActive), "NextScan snapshot");
    ok &= expect(nextScanReader.readU8(mixedScan), "NextScan mixed");
    ok &= expect(nextScanReader.readU8(primaryType) && primaryType == 3, "NextScan type");
    ok &= expect(nextScanReader.readU64(candidateCount) && candidateCount >= 1, "NextScan candidates");
    ok &= expect(nextScanReader.readU64(resultCount) && resultCount >= 1, "NextScan result count");
    ok &= expect(nextScanReader.readU64(scanBytes), "NextScan bytes");
    ok &= expect(nextScanReader.readU64(scanRegions), "NextScan regions");
    ok &= expect(nextScanReader.readU64(scanElapsed), "NextScan elapsed");
    ok &= expect(nextScanReader.readU8(scanTruncated), "NextScan truncated flag");
    ok &= expect(nextScanReader.readU8(scanCancelled) && scanCancelled == 0, "NextScan completion");
    std::array<std::uint64_t, 6> nextTypeCounts{};
    for (auto& count : nextTypeCounts) ok &= expect(nextScanReader.readU64(count), "NextScan type count");
    ok &= expect(nextTypeCounts[2] >= 1 && nextScanReader.empty(), "NextScan type counts complete");

    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::NewScan, requestId++, {}, response, error),
                 "NewScan transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::NewScanResult, "NewScanResult response");

    // Freeze the same value and verify the worker keeps restoring it.
    const std::int32_t freezeWanted = 246813579;
    probe = 1;
    cw::EngineBufferWriter freezePayload;
    freezePayload.writeU64(probeAddress);
    freezePayload.writeU8(3); // Int32
    freezePayload.writeU8(sizeof(freezeWanted));
    freezePayload.writeBytes(std::as_bytes(std::span(&freezeWanted, 1)));
    freezePayload.writeU32(10);
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::SetFreeze, requestId++, freezePayload.take(), response, error),
                 "SetFreeze transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::SetFreezeResult, "SetFreezeResult response");
    cw::EngineBufferReader freezeReader(response.payload);
    std::uint8_t freezeOk{};
    std::uint64_t freezeId{};
    ok &= expect(freezeReader.readU8(freezeOk) && freezeOk == 1, "freeze created");
    ok &= expect(freezeReader.readU64(freezeId) && freezeId != 0 && freezeReader.empty(), "freeze id");
    Sleep(80);
    ok &= expect(probe == freezeWanted, "freeze worker restored target value");

    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::ListFreezes, requestId++, {}, response, error),
                 "ListFreezes transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::ListFreezesResult, "ListFreezesResult response");
    cw::EngineBufferReader freezeListReader(response.payload);
    std::uint32_t freezeCount{};
    ok &= expect(freezeListReader.readU32(freezeCount) && freezeCount == 1, "one freeze listed");
    std::uint64_t listedFreezeId{};
    std::uint64_t listedAddress{};
    std::uint8_t listedType{};
    std::uint8_t listedSize{};
    std::array<std::byte, 8> listedValue{};
    std::uint32_t listedInterval{};
    std::uint64_t listedWrites{};
    std::uint64_t listedFailures{};
    std::uint32_t listedError{};
    ok &= expect(freezeListReader.readU64(listedFreezeId) && listedFreezeId == freezeId, "listed freeze id");
    ok &= expect(freezeListReader.readU64(listedAddress) && listedAddress == probeAddress, "listed freeze address");
    ok &= expect(freezeListReader.readU8(listedType) && listedType == 3, "listed freeze type");
    ok &= expect(freezeListReader.readU8(listedSize) && listedSize == sizeof(freezeWanted), "listed freeze size");
    ok &= expect(freezeListReader.readBytes(std::span(listedValue.data(), listedSize)), "listed freeze value");
    ok &= expect(freezeListReader.readU32(listedInterval) && listedInterval == 10, "listed freeze interval");
    ok &= expect(freezeListReader.readU64(listedWrites) && listedWrites > 0, "freeze write count");
    ok &= expect(freezeListReader.readU64(listedFailures), "freeze failure count");
    ok &= expect(freezeListReader.readU32(listedError) && freezeListReader.empty(), "freeze last error");

    cw::EngineBufferWriter removeFreezePayload;
    removeFreezePayload.writeU64(freezeId);
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::RemoveFreeze, requestId++, removeFreezePayload.take(), response, error),
                 "RemoveFreeze transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::RemoveFreezeResult, "RemoveFreezeResult response");
    cw::EngineBufferReader removeFreezeReader(response.payload);
    std::uint8_t removed{};
    ok &= expect(removeFreezeReader.readU8(removed) && removed == 1 && removeFreezeReader.empty(), "freeze removed");
    probe = 777;
    Sleep(40);
    ok &= expect(probe == 777, "removed freeze no longer writes");

    // Load a deterministic one-hop pointer profile rooted in this executable.
    gPointerProbe = &probe;
    const auto moduleBase = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    wchar_t modulePath[MAX_PATH]{};
    const DWORD modulePathLength = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    std::wstring moduleName(modulePath, modulePathLength);
    const auto slash = moduleName.find_last_of(L"\\/");
    if (slash != std::wstring::npos) moduleName.erase(0, slash + 1);
    const std::string moduleNameUtf8 = wideToUtf8(moduleName);
    const auto rootAddress = reinterpret_cast<std::uintptr_t>(&gPointerProbe);
    const auto rootOffset = rootAddress - moduleBase;

    cw::EngineBufferWriter pointerDiscoverPayload;
    pointerDiscoverPayload.writeU64(probeAddress);
    pointerDiscoverPayload.writeU16(1); // max depth
    pointerDiscoverPayload.writeU64(0); // exact pointer only
    pointerDiscoverPayload.writeU64(0); // no negative offset
    pointerDiscoverPayload.writeU32(128); // max chains
    pointerDiscoverPayload.writeU32(500000); // max index entries
    pointerDiscoverPayload.writeU32(4096); // max candidates/node
    pointerDiscoverPayload.writeU32(100000); // max search candidates
    pointerDiscoverPayload.writeU16(pointerSize); // natural pointer alignment
    pointerDiscoverPayload.writeU8(0); // no memory-type filter
    pointerDiscoverPayload.writeString(moduleNameUtf8);
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::PointerDiscover, requestId++, pointerDiscoverPayload.take(), response, error),
                 "PointerDiscover transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::PointerDiscoverResult, "PointerDiscoverResult response");
    cw::EngineBufferReader pointerDiscoverReader(response.payload);
    std::uint16_t discoveredPointerSize{};
    std::uint64_t discoveredIndexEntries{};
    std::uint64_t discoveredChains{};
    std::uint64_t discoveredBytes{};
    std::uint64_t discoveredRegions{};
    std::uint64_t discoveredIndexMs{};
    std::uint64_t discoveredSearchMs{};
    std::uint8_t discoveredIndexTruncated{};
    std::uint8_t discoveredChainsTruncated{};
    std::uint8_t discoveredCancelled{};
    ok &= expect(pointerDiscoverReader.readU16(discoveredPointerSize) && discoveredPointerSize == pointerSize,
                 "pointer discover width");
    ok &= expect(pointerDiscoverReader.readU64(discoveredIndexEntries) && discoveredIndexEntries > 0,
                 "pointer discover index entries");
    ok &= expect(pointerDiscoverReader.readU64(discoveredChains), "pointer discover chain count");
    ok &= expect(pointerDiscoverReader.readU64(discoveredBytes) && discoveredBytes > 0, "pointer discover bytes");
    ok &= expect(pointerDiscoverReader.readU64(discoveredRegions) && discoveredRegions > 0, "pointer discover regions");
    ok &= expect(pointerDiscoverReader.readU64(discoveredIndexMs), "pointer discover index time");
    ok &= expect(pointerDiscoverReader.readU64(discoveredSearchMs), "pointer discover search time");
    ok &= expect(pointerDiscoverReader.readU8(discoveredIndexTruncated), "pointer discover index truncated flag");
    ok &= expect(pointerDiscoverReader.readU8(discoveredChainsTruncated), "pointer discover chains truncated flag");
    ok &= expect(pointerDiscoverReader.readU8(discoveredCancelled) && discoveredCancelled == 0 && pointerDiscoverReader.empty(),
                 "pointer discover completion");

    cw::EngineBufferWriter profilePayload;
    profilePayload.writeU16(pointerSize);
    profilePayload.writeU8(3); // Int32 value type
    profilePayload.writeString(moduleNameUtf8);
    profilePayload.writeU32(1); // one chain
    profilePayload.writeString(moduleNameUtf8);
    profilePayload.writeU64(rootOffset);
    profilePayload.writeU16(1); // one dereference
    profilePayload.writeI64(0);
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::SetPointerProfile, requestId++, profilePayload.take(), response, error),
                 "SetPointerProfile transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::SetPointerProfileResult, "SetPointerProfileResult response");
    cw::EngineBufferReader profileReader(response.payload);
    std::uint8_t profileOk{};
    std::uint16_t profilePointerSize{};
    std::uint8_t profileType{};
    std::uint64_t profileChains{};
    ok &= expect(profileReader.readU8(profileOk) && profileOk == 1, "profile loaded");
    ok &= expect(profileReader.readU16(profilePointerSize) && profilePointerSize == pointerSize, "profile pointer size");
    ok &= expect(profileReader.readU8(profileType) && profileType == 3, "profile type");
    ok &= expect(profileReader.readU64(profileChains) && profileChains == 1 && profileReader.empty(), "profile chain count");

    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::ResolvePointerProfile, requestId++, {}, response, error),
                 "ResolvePointerProfile transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::ResolvePointerProfileResult,
                 "ResolvePointerProfileResult response");
    cw::EngineBufferReader resolveReader(response.payload);
    std::uint8_t resolvedOk{};
    std::uint8_t resolvedType{};
    std::uint64_t resolvedAddress{};
    std::uint64_t agreementCount{};
    std::uint64_t resolvedCount{};
    ok &= expect(resolveReader.readU8(resolvedOk) && resolvedOk == 1, "profile resolved");
    ok &= expect(resolveReader.readU8(resolvedType) && resolvedType == 3, "resolved profile type");
    ok &= expect(resolveReader.readU64(resolvedAddress) && resolvedAddress == probeAddress, "resolved profile address");
    ok &= expect(resolveReader.readU64(agreementCount) && agreementCount == 1, "profile agreement count");
    ok &= expect(resolveReader.readU64(resolvedCount) && resolvedCount == 1 && resolveReader.empty(),
                 "profile resolved chain count");

    cw::EngineBufferWriter pointerResultsPayload;
    pointerResultsPayload.writeU32(0);
    pointerResultsPayload.writeU32(10);
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::PointerResults, requestId++, pointerResultsPayload.take(), response, error),
                 "PointerResults transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::PointerResultsResult, "PointerResultsResult response");
    cw::EngineBufferReader pointerResultsReader(response.payload);
    std::uint16_t livePointerSize{};
    std::uint16_t chainPointerSize{};
    std::uint64_t totalChains{};
    std::uint32_t returnedChains{};
    std::string returnedModule;
    std::uint64_t returnedRootOffset{};
    std::uint16_t returnedDepth{};
    std::int64_t returnedStep{};
    std::uint8_t returnedResolved{};
    std::uint64_t returnedAddress{};
    ok &= expect(pointerResultsReader.readU16(livePointerSize) && livePointerSize == pointerSize, "pointer results live width");
    ok &= expect(pointerResultsReader.readU16(chainPointerSize) && chainPointerSize == pointerSize, "pointer results chain width");
    ok &= expect(pointerResultsReader.readU64(totalChains) && totalChains == 1, "pointer results total");
    ok &= expect(pointerResultsReader.readU32(returnedChains) && returnedChains == 1, "pointer results page count");
    ok &= expect(pointerResultsReader.readString(returnedModule) && returnedModule == moduleNameUtf8, "pointer result module");
    ok &= expect(pointerResultsReader.readU64(returnedRootOffset) && returnedRootOffset == rootOffset, "pointer result root");
    ok &= expect(pointerResultsReader.readU16(returnedDepth) && returnedDepth == 1, "pointer result depth");
    ok &= expect(pointerResultsReader.readI64(returnedStep) && returnedStep == 0, "pointer result offset");
    ok &= expect(pointerResultsReader.readU8(returnedResolved) && returnedResolved == 1, "pointer result resolves");
    ok &= expect(pointerResultsReader.readU64(returnedAddress) && returnedAddress == probeAddress &&
                 pointerResultsReader.empty(), "pointer result address");

    cw::EngineBufferWriter pointerRescanPayload;
    pointerRescanPayload.writeU64(probeAddress);
    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::PointerRescan, requestId++, pointerRescanPayload.take(), response, error),
                 "PointerRescan transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::PointerRescanResult, "PointerRescanResult response");
    cw::EngineBufferReader pointerRescanReader(response.payload);
    std::uint64_t chainsBefore{};
    std::uint64_t chainsAfter{};
    ok &= expect(pointerRescanReader.readU64(chainsBefore) && chainsBefore == 1, "pointer rescan before");
    ok &= expect(pointerRescanReader.readU64(chainsAfter) && chainsAfter == 1 && pointerRescanReader.empty(),
                 "pointer rescan preserved chain");

    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::DetachProcess, requestId++, {}, response, error),
                 "DetachProcess transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::DetachProcessResult, "Detach result");

    response = {};
    ok &= expect(transact(client, cw::EngineMessageKind::Shutdown, requestId++, {}, response, error),
                 "Shutdown transaction");
    ok &= expect(response.header.kind == cw::EngineMessageKind::Shutdown, "Shutdown response");
    client.close();

    const DWORD wait = WaitForSingleObject(process.hProcess, 5000);
    ok &= expect(wait == WAIT_OBJECT_0, "engine exited after Shutdown");
    DWORD exitCode = 999;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &exitCode);
    ok &= expect(exitCode == 0, "engine exit code zero");
    if (wait != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 91);
    CloseHandle(process.hProcess);

    if (!ok) {
        if (!error.empty()) std::cerr << "Last IPC error: " << error << '\n';
        return 1;
    }
    std::cout << "Engine process RPC tests PASS\n";
    return 0;
}
