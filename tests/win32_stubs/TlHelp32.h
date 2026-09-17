#pragma once
#include <Windows.h>

constexpr DWORD TH32CS_SNAPPROCESS = 0x00000002;
constexpr DWORD TH32CS_SNAPMODULE = 0x00000008;
constexpr DWORD TH32CS_SNAPMODULE32 = 0x00000010;

struct PROCESSENTRY32W {
    DWORD dwSize{};
    DWORD cntUsage{};
    DWORD th32ProcessID{};
    std::uintptr_t th32DefaultHeapID{};
    DWORD th32ModuleID{};
    DWORD cntThreads{};
    DWORD th32ParentProcessID{};
    long pcPriClassBase{};
    DWORD dwFlags{};
    WCHAR szExeFile[MAX_PATH]{};
};

HANDLE CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL Process32FirstW(HANDLE, PROCESSENTRY32W*);
BOOL Process32NextW(HANDLE, PROCESSENTRY32W*);


struct MODULEENTRY32W {
    DWORD dwSize{};
    DWORD th32ModuleID{};
    DWORD th32ProcessID{};
    DWORD GlblcntUsage{};
    DWORD ProccntUsage{};
    BYTE* modBaseAddr{};
    DWORD modBaseSize{};
    void* hModule{};
    WCHAR szModule[256]{};
    WCHAR szExePath[MAX_PATH]{};
};

BOOL Module32FirstW(HANDLE, MODULEENTRY32W*);
BOOL Module32NextW(HANDLE, MODULEENTRY32W*);
