#include "cw/EnginePipe.hpp"

#include <Windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>

namespace {

bool expect(bool condition, const char* message) {
    if (condition) return true;
    std::cerr << "FAIL: " << message << '\n';
    return false;
}

} // namespace

int main() {
    bool ok = true;
    ok &= expect(!cw::isValidEnginePipeName(L"bad"), "invalid pipe name rejected");
    ok &= expect(cw::isValidEnginePipeName(L"\\\\.\\pipe\\CheatWizard.Engine.1.test"),
                 "valid pipe name accepted");

    const auto pid = GetCurrentProcessId();
    const std::wstring pipeName = L"\\\\.\\pipe\\CheatWizard.Engine.Test." +
        std::to_wstring(pid) + L"." + std::to_wstring(GetTickCount64());

    cw::EnginePipeServer server;
    std::string error;
    ok &= expect(server.create(pipeName, pid, error), "server create");
    if (!ok) { std::cerr << error << '\n'; return 1; }

    std::atomic_bool serverOk{true};
    std::string serverError;
    std::thread serverThread([&] {
        if (!server.accept(serverError)) { serverOk = false; return; }

        cw::EngineFrame hello;
        if (!server.receive(hello, serverError)) { serverOk = false; return; }
        if (hello.header.kind != cw::EngineMessageKind::Hello || hello.header.requestId != 42 ||
            hello.header.protocolMajor != cw::kEngineProtocolMajor) {
            serverError = "Unexpected Hello frame";
            serverOk = false;
            return;
        }

        cw::EngineBufferReader reader(hello.payload);
        std::string clientName;
        if (!reader.readString(clientName) || !reader.empty() || clientName != "pipe-test") {
            serverError = "Invalid Hello payload";
            serverOk = false;
            return;
        }

        cw::EngineBufferWriter ackPayload;
        ackPayload.writeU16(cw::kEngineProtocolMajor);
        ackPayload.writeU16(cw::kEngineProtocolMinor);
        ackPayload.writeString("engine-test");

        cw::EngineFrame ack;
        ack.header.kind = cw::EngineMessageKind::HelloAck;
        ack.header.flags = cw::EngineFrameFlagResponse;
        ack.header.requestId = hello.header.requestId;
        ack.payload = ackPayload.take();
        if (!server.send(ack, serverError)) { serverOk = false; return; }

        cw::EngineFrame ping;
        if (!server.receive(ping, serverError)) { serverOk = false; return; }
        if (ping.header.kind != cw::EngineMessageKind::Ping || ping.header.requestId != 43) {
            serverError = "Unexpected Ping frame";
            serverOk = false;
            return;
        }

        cw::EngineFrame pong;
        pong.header.kind = cw::EngineMessageKind::Pong;
        pong.header.flags = cw::EngineFrameFlagResponse;
        pong.header.requestId = ping.header.requestId;
        if (!server.send(pong, serverError)) { serverOk = false; return; }
    });

    cw::EnginePipeClient client;
    if (!client.connect(pipeName, 5000, error)) {
        std::cerr << "Client connect failed: " << error << '\n';
        server.close();
        serverThread.join();
        return 1;
    }

    cw::EngineBufferWriter helloPayload;
    helloPayload.writeString("pipe-test");
    cw::EngineFrame hello;
    hello.header.kind = cw::EngineMessageKind::Hello;
    hello.header.requestId = 42;
    hello.payload = helloPayload.take();
    ok &= expect(client.send(hello, error), "client send Hello");

    cw::EngineFrame ack;
    ok &= expect(client.receive(ack, error), "client receive HelloAck");
    ok &= expect(ack.header.kind == cw::EngineMessageKind::HelloAck, "HelloAck kind");
    ok &= expect(ack.header.requestId == 42, "HelloAck request id");
    cw::EngineBufferReader ackReader(ack.payload);
    std::uint16_t major{};
    std::uint16_t minor{};
    std::string serverName;
    ok &= expect(ackReader.readU16(major) && major == cw::kEngineProtocolMajor, "HelloAck major");
    ok &= expect(ackReader.readU16(minor) && minor == cw::kEngineProtocolMinor, "HelloAck minor");
    ok &= expect(ackReader.readString(serverName) && serverName == "engine-test", "HelloAck server name");
    ok &= expect(ackReader.empty(), "HelloAck payload fully consumed");

    cw::EngineFrame ping;
    ping.header.kind = cw::EngineMessageKind::Ping;
    ping.header.requestId = 43;
    ok &= expect(client.send(ping, error), "client send Ping");

    cw::EngineFrame pong;
    ok &= expect(client.receive(pong, error), "client receive Pong");
    ok &= expect(pong.header.kind == cw::EngineMessageKind::Pong, "Pong kind");
    ok &= expect(pong.header.requestId == 43, "Pong request id");

    client.close();
    serverThread.join();
    ok &= expect(serverOk.load(), "server path passed");
    if (!serverOk.load()) std::cerr << "Server error: " << serverError << '\n';

    if (!ok) return 1;
    std::cout << "EnginePipe tests PASS\n";
    return 0;
}
