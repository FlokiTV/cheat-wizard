#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#ifndef WINAPI
#define WINAPI
#endif

using BOOL = int;
using BYTE = unsigned char;
using WORD = unsigned short;
using UINT = unsigned int;
using DWORD = unsigned long;
using SIZE_T = std::size_t;
using HANDLE = void*;
using HLOCAL = void*;
using LPVOID = void*;
using LPCVOID = const void*;
using LPSTR = char*;
using LPCSTR = const char*;
using WCHAR = wchar_t;
using LPWSTR = wchar_t*;
using LPCWSTR = const wchar_t*;
using LPCWCH = const wchar_t*;
using LPCCH = const char*;

constexpr BOOL FALSE = 0;
constexpr BOOL TRUE = 1;

constexpr DWORD MEM_COMMIT = 0x1000;
constexpr DWORD MEM_RESERVE = 0x2000;
constexpr DWORD MEM_RELEASE = 0x8000;
constexpr DWORD MEM_PRIVATE = 0x20000;
constexpr DWORD MEM_MAPPED = 0x40000;
constexpr DWORD MEM_IMAGE = 0x1000000;
constexpr DWORD PAGE_NOACCESS = 0x01;
constexpr DWORD PAGE_READONLY = 0x02;
constexpr DWORD PAGE_READWRITE = 0x04;
constexpr DWORD PAGE_WRITECOPY = 0x08;
constexpr DWORD PAGE_EXECUTE = 0x10;
constexpr DWORD PAGE_EXECUTE_READ = 0x20;
constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40;
constexpr DWORD PAGE_EXECUTE_WRITECOPY = 0x80;
constexpr DWORD PAGE_GUARD = 0x100;

constexpr DWORD PROCESS_VM_OPERATION = 0x0008;
constexpr DWORD PROCESS_VM_READ = 0x0010;
constexpr DWORD PROCESS_VM_WRITE = 0x0020;
constexpr DWORD PROCESS_QUERY_INFORMATION = 0x0400;
constexpr DWORD DUPLICATE_SAME_ACCESS = 0x00000002;

constexpr DWORD FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
constexpr DWORD FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
constexpr DWORD FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
constexpr WORD LANG_NEUTRAL = 0x00;
constexpr WORD SUBLANG_DEFAULT = 0x01;

constexpr DWORD ERROR_SUCCESS = 0;
constexpr DWORD ERROR_INVALID_HANDLE = 6;
constexpr UINT CP_UTF8 = 65001;
constexpr DWORD CTRL_C_EVENT = 0;
constexpr DWORD CTRL_BREAK_EVENT = 1;
constexpr std::size_t MAX_PATH = 260;

#define INVALID_HANDLE_VALUE ((HANDLE)(std::intptr_t)-1)
#define MAKELANGID(p, s) ((((WORD)(s)) << 10) | (WORD)(p))

struct LARGE_INTEGER {
    long long QuadPart{};
};

struct SYSTEM_INFO {
    void* lpMinimumApplicationAddress{};
    void* lpMaximumApplicationAddress{};
    DWORD dwPageSize{};
};

struct MEMORY_BASIC_INFORMATION {
    void* BaseAddress{};
    void* AllocationBase{};
    DWORD AllocationProtect{};
    SIZE_T RegionSize{};
    DWORD State{};
    DWORD Protect{};
    DWORD Type{};
};

namespace mockwin {
inline std::uintptr_t base = 0x10000;
inline std::vector<std::byte> memory(64 * 1024);
inline std::uint64_t readCalls = 0;
inline std::uint64_t bytesRead = 0;
inline DWORD protection = PAGE_READWRITE;
inline DWORD regionType = MEM_PRIVATE;

inline void reset(std::size_t bytes = 64 * 1024) {
    memory.assign(bytes, std::byte{0});
    readCalls = 0;
    bytesRead = 0;
    protection = PAGE_READWRITE;
    regionType = MEM_PRIVATE;
}

inline void resetCounters() {
    readCalls = 0;
    bytesRead = 0;
}

template <typename T>
inline void write(std::size_t offset, T value) {
    std::memcpy(memory.data() + offset, &value, sizeof(T));
}
} // namespace mockwin

inline void GetNativeSystemInfo(SYSTEM_INFO* info) {
    info->lpMinimumApplicationAddress = reinterpret_cast<void*>(mockwin::base);
    info->lpMaximumApplicationAddress = reinterpret_cast<void*>(mockwin::base + mockwin::memory.size());
    info->dwPageSize = 4096;
}

inline SIZE_T VirtualQueryEx(HANDLE, LPCVOID address, MEMORY_BASIC_INFORMATION* mbi, SIZE_T) {
    const auto current = reinterpret_cast<std::uintptr_t>(address);
    const auto end = mockwin::base + mockwin::memory.size();
    if (current < mockwin::base || current >= end) return 0;
    mbi->BaseAddress = reinterpret_cast<void*>(mockwin::base);
    mbi->RegionSize = mockwin::memory.size();
    mbi->State = MEM_COMMIT;
    mbi->Protect = mockwin::protection;
    mbi->Type = mockwin::regionType;
    return sizeof(MEMORY_BASIC_INFORMATION);
}

inline BOOL ReadProcessMemory(HANDLE, LPCVOID address, LPVOID buffer, SIZE_T size, SIZE_T* copied) {
    ++mockwin::readCalls;
    const auto current = reinterpret_cast<std::uintptr_t>(address);
    const auto end = mockwin::base + mockwin::memory.size();
    if (current < mockwin::base || current >= end) {
        if (copied) *copied = 0;
        return FALSE;
    }

    const auto offset = static_cast<std::size_t>(current - mockwin::base);
    const auto available = mockwin::memory.size() - offset;
    const auto count = (std::min)(size, available);
    std::memcpy(buffer, mockwin::memory.data() + offset, count);
    if (copied) *copied = count;
    mockwin::bytesRead += count;
    return count == size ? TRUE : FALSE;
}

// Declarations used only by syntax-only checks of the real Win32 translation units.
BOOL SetConsoleOutputCP(UINT);
using PHANDLER_ROUTINE = BOOL (WINAPI*)(DWORD);
BOOL SetConsoleCtrlHandler(PHANDLER_ROUTINE, BOOL);
int WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, BOOL*);
LPVOID VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
BOOL VirtualFree(LPVOID, SIZE_T, DWORD);
BOOL QueryPerformanceCounter(LARGE_INTEGER*);
DWORD GetCurrentProcessId();
DWORD GetLastError();
HANDLE GetCurrentProcess();
HANDLE OpenProcess(DWORD, BOOL, DWORD);
BOOL CloseHandle(HANDLE);
BOOL DuplicateHandle(HANDLE, HANDLE, HANDLE, HANDLE*, DWORD, BOOL, DWORD);
BOOL WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
DWORD FormatMessageA(DWORD, LPCVOID, DWORD, DWORD, LPSTR, DWORD, void*);
HLOCAL LocalFree(HLOCAL);

BOOL IsWow64Process(HANDLE, BOOL*);
