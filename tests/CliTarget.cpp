#include <Windows.h>

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <string>

volatile std::int32_t gCliProbe = 0x1234ABCD;
volatile std::int32_t* gCliPointer = &gCliProbe;

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) return 2;

    std::ofstream out(argv[1], std::ios::binary | std::ios::trunc);
    if (!out) return 3;
    out << GetCurrentProcessId() << '\n';
    out << "0x" << std::hex << std::uppercase
        << reinterpret_cast<std::uintptr_t>(const_cast<std::int32_t*>(&gCliProbe)) << '\n';
    out << "0x" << std::hex << std::uppercase
        << reinterpret_cast<std::uintptr_t>(&gCliPointer) << '\n';
    out.flush();
    out.close();

    HANDLE stopEvent = OpenEventW(SYNCHRONIZE, FALSE, argv[2]);
    if (!stopEvent) return 4;
    const DWORD wait = WaitForSingleObject(stopEvent, 30000);
    CloseHandle(stopEvent);
    return wait == WAIT_OBJECT_0 ? 0 : 5;
}
