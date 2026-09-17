// Cheat Wizard portable Windows x64 build (no CRT/STL).
// Cross-compilable with clang-cl + lld-link using only kernel32 imports.
// This file intentionally mirrors the core interactive workflow of Cheat Wizard:
// process selection, value scans, AOB signatures, writes/freezes, modules, pointer chains, and chain persistence.

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;
using i8 = signed char;
using i16 = short;
using i32 = int;
using i64 = long long;
using usize = unsigned long long;
using uptr = unsigned long long;

#include "MdiIconMasks.hpp"
using HANDLE = void*;
using PVOID = void*;
using LPCVOID = const void*;
using LPVOID = void*;
using BOOL = int;
using DWORD = unsigned long;
using LONG = long;
using SIZE_T = unsigned long long;
using ULONG_PTR = unsigned long long;
using LPTHREAD_START_ROUTINE = DWORD (__stdcall *)(LPVOID);

#ifndef __stdcall
#define __stdcall
#endif

extern "C" {
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE, LPVOID, DWORD, DWORD*, LPVOID);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, LPCVOID, DWORD, DWORD*, LPVOID);
__declspec(dllimport) HANDLE __stdcall CreateFileA(const char*, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
__declspec(dllimport) BOOL __stdcall DeleteFileA(const char*);
__declspec(dllimport) DWORD __stdcall GetTempPathA(DWORD, char*);
__declspec(dllimport) unsigned int __stdcall GetTempFileNameA(const char*, const char*, unsigned int, char*);
__declspec(dllimport) DWORD __stdcall GetModuleFileNameA(void*, char*, DWORD);
__declspec(dllimport) u16 __stdcall GetUserDefaultUILanguage();
__declspec(dllimport) HANDLE __stdcall FindFirstFileA(const char*, LPVOID);
__declspec(dllimport) BOOL __stdcall FindNextFileA(HANDLE, LPVOID);
__declspec(dllimport) BOOL __stdcall FindClose(HANDLE);
__declspec(dllimport) DWORD __stdcall SetFilePointer(HANDLE, LONG, LONG*, DWORD);
__declspec(dllimport) DWORD __stdcall GetFileSize(HANDLE,DWORD*);
__declspec(dllimport) int __stdcall MultiByteToWideChar(unsigned int,DWORD,const char*,int,wchar_t*,int);
__declspec(dllimport) void __stdcall SetLastError(DWORD);
__declspec(dllimport) void __stdcall ExitProcess(u32);
__declspec(dllimport) DWORD __stdcall GetLastError();
__declspec(dllimport) HANDLE __stdcall GetProcessHeap();
__declspec(dllimport) LPVOID __stdcall HeapAlloc(HANDLE, DWORD, SIZE_T);
__declspec(dllimport) LPVOID __stdcall HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
__declspec(dllimport) BOOL __stdcall HeapFree(HANDLE, DWORD, LPVOID);
__declspec(dllimport) HANDLE __stdcall CreateToolhelp32Snapshot(DWORD, DWORD);
__declspec(dllimport) BOOL __stdcall Process32First(HANDLE, LPVOID);
__declspec(dllimport) BOOL __stdcall Process32Next(HANDLE, LPVOID);
__declspec(dllimport) BOOL __stdcall Module32FirstW(HANDLE, LPVOID);
__declspec(dllimport) BOOL __stdcall Module32NextW(HANDLE, LPVOID);
__declspec(dllimport) BOOL __stdcall IsWow64Process(HANDLE, BOOL*);
__declspec(dllimport) HANDLE __stdcall OpenProcess(DWORD, BOOL, DWORD);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE);
__declspec(dllimport) SIZE_T __stdcall VirtualQueryEx(HANDLE, LPCVOID, LPVOID, SIZE_T);
__declspec(dllimport) BOOL __stdcall ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
__declspec(dllimport) BOOL __stdcall WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
__declspec(dllimport) void __stdcall GetNativeSystemInfo(LPVOID);
__declspec(dllimport) HANDLE __stdcall CreateThread(LPVOID, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, DWORD*);
__declspec(dllimport) void __stdcall Sleep(DWORD);
}

extern "C" int _fltused = 0;
extern "C" void* memcpy(void* d, const void* s, usize n) { auto* dd=(u8*)d; auto* ss=(const u8*)s; for(usize i=0;i<n;++i) dd[i]=ss[i]; return d; }
extern "C" void* memset(void* d, int c, usize n) { auto* dd=(u8*)d; for(usize i=0;i<n;++i) dd[i]=(u8)c; return d; }

static constexpr DWORD STD_INPUT_HANDLE  = (DWORD)-10;
static constexpr DWORD STD_OUTPUT_HANDLE = (DWORD)-11;
static constexpr DWORD GENERIC_READ = 0x80000000UL;
static constexpr DWORD GENERIC_WRITE = 0x40000000UL;
static constexpr DWORD CREATE_ALWAYS = 2;
static constexpr DWORD OPEN_EXISTING = 3;
static constexpr DWORD FILE_BEGIN = 0;
static constexpr DWORD FILE_SHARE_READ_ = 0x00000001;
static constexpr DWORD FILE_SHARE_WRITE_ = 0x00000002;
static constexpr DWORD FILE_SHARE_DELETE_ = 0x00000004;
static constexpr DWORD FILE_ATTRIBUTE_NORMAL = 0x80;
static constexpr DWORD FILE_ATTRIBUTE_DIRECTORY_ = 0x10;
static constexpr DWORD FILE_ATTRIBUTE_TEMPORARY_ = 0x100;
static constexpr DWORD FILE_FLAG_DELETE_ON_CLOSE_ = 0x04000000;
static constexpr DWORD FILE_FLAG_SEQUENTIAL_SCAN_ = 0x08000000;
static constexpr DWORD INVALID_SET_FILE_POINTER_ = 0xFFFFFFFFUL;
static constexpr uptr INVALID_HANDLE_BITS = ~(uptr)0;
static constexpr DWORD TH32CS_SNAPPROCESS = 0x00000002;
static constexpr DWORD TH32CS_SNAPMODULE = 0x00000008;
static constexpr DWORD TH32CS_SNAPMODULE32 = 0x00000010;
static constexpr DWORD PROCESS_VM_OPERATION = 0x0008;
static constexpr DWORD PROCESS_VM_READ = 0x0010;
static constexpr DWORD PROCESS_VM_WRITE = 0x0020;
static constexpr DWORD PROCESS_QUERY_INFORMATION = 0x0400;
static constexpr DWORD MEM_COMMIT = 0x1000;
static constexpr DWORD MEM_PRIVATE = 0x20000;
static constexpr DWORD PAGE_READONLY = 0x02;
static constexpr DWORD PAGE_READWRITE = 0x04;
static constexpr DWORD PAGE_WRITECOPY = 0x08;
static constexpr DWORD PAGE_EXECUTE_READ = 0x20;
static constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40;
static constexpr DWORD PAGE_EXECUTE_WRITECOPY = 0x80;
static constexpr DWORD PAGE_GUARD = 0x100;
static constexpr usize MAX_RESULTS = 5000000ULL;
static constexpr usize SCAN_CHUNK = 4ULL * 1024ULL * 1024ULL;
static constexpr int MAX_FREEZES = 128;
static constexpr usize MAX_AOB_RESULTS = 1000000ULL;
static constexpr usize MAX_AOB_PATTERN = 4096ULL;
static constexpr usize MAX_POINTER_ENTRIES = 8000000ULL;
static constexpr usize MAX_POINTER_RANGES = 131072ULL;
static constexpr usize MAX_POINTER_CHAINS = 10000ULL;
static constexpr usize MAX_POINTER_DEPTH = 8ULL;
// Deep pointer discovery uses a layered/targeted reverse scan instead of
// materializing every pointer in the process. The frontier cap bounds memory
// while breadth-first traversal strongly prefers short, stable chains.
static constexpr usize MAX_POINTER_LAYER_NODES = 300000ULL;
static constexpr usize MAX_MODULES = 256ULL;
static constexpr usize MAX_POINTER_MAPS = 4ULL;
static constexpr u8 SNAP_MASK_NONE = 0;
static constexpr u8 SNAP_MASK_ALL = 1;
static constexpr u8 SNAP_MASK_EXPLICIT = 2;

struct PROCESSENTRY32A_ {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    char szExeFile[260];
};

struct FILETIME_ { DWORD dwLowDateTime; DWORD dwHighDateTime; };
struct WIN32_FIND_DATAA_ {
    DWORD dwFileAttributes;
    FILETIME_ ftCreationTime;
    FILETIME_ ftLastAccessTime;
    FILETIME_ ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    char cFileName[260];
    char cAlternateFileName[14];
};

struct MODULEENTRY32W_ {
    DWORD dwSize;
    DWORD th32ModuleID;
    DWORD th32ProcessID;
    DWORD GlblcntUsage;
    DWORD ProccntUsage;
    u8* modBaseAddr;
    DWORD modBaseSize;
    HANDLE hModule;
    wchar_t szModule[256];
    wchar_t szExePath[260];
};

struct SYSTEM_INFO_ {
    DWORD dwOemId;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    ULONG_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    u16 wProcessorLevel;
    u16 wProcessorRevision;
};

struct MEMORY_BASIC_INFORMATION_ {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    u16 PartitionId;
    // implicit 2-byte padding here on x64
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

struct Result {
    uptr address;
    u8 previous[8];
    u8 type;
};

struct SnapshotBlock_ {
    uptr base;
    u64 fileOffset;
    usize size;
    usize candidateBytes;
    u8* masks[6];
    usize candidateCounts[6];
    usize activeCounts[6];
    u8 maskModes[6];
};

enum class ValueType : u8 { Byte, Int16, Int32, Int64, Float, Double, Mixed, Invalid };
enum class NextMode : u8 { Exact, Changed, Unchanged, Increased, Decreased, Bigger, Smaller };
enum class GuidedGoal_ : u8 { Generic, Money, Health, Ammo };

struct GuidedStep_ {
    u8 mode;
    usize beforeCount;
    usize afterCount;
    usize beforeTypes[6];
    usize afterTypes[6];
};

struct FreezeEntry {
    volatile LONG active;
    volatile LONG lastWriteOk;
    uptr address;
    u8 bytes[8];
    u8 size;
    u8 type;
    u16 pad;
};
struct PointerEntry {
    uptr value;
    uptr address;
};

struct ModuleInfo_ {
    uptr base;
    u64 size;
    char name[256];
};

struct PointerChain_ {
    char module[256];
    uptr rootOffset;
    i64 offsets[MAX_POINTER_DEPTH];
    u8 depth;
};

struct PointerLayerNode_ {
    uptr address;
    i64 offsets[MAX_POINTER_DEPTH];
    u64 score;
    u32 parentsSeen;
    u8 depth;
    u8 pad[3];
};

struct PointerMap_ {
    u8 pointerSize;
    bool complete;
    bool entriesByAddress;
    u8 pad;
    uptr target;
    usize moduleCount;
    ModuleInfo_ modules[MAX_MODULES];
    PointerEntry* entries;
    usize entryCount;
    char path[260];
};

static HANDLE g_out = nullptr;
static HANDLE g_in = nullptr;
static HANDLE g_heap = nullptr;
static volatile HANDLE g_process = nullptr;
static DWORD g_pid = 0;
static Result* g_results = nullptr;
static usize g_resultCount = 0;
static usize g_resultCap = 0;
static usize g_resultTypeCounts[6] = {};
static constexpr usize MAX_GUIDED_STEPS = 32;
static constexpr usize MAX_UI_RANKED_RESULTS = 5000;
static GuidedStep_ g_guidedSteps[MAX_GUIDED_STEPS] = {};
static usize g_guidedCount = 0;
static GuidedGoal_ g_guidedGoal = GuidedGoal_::Generic;
static usize g_rankedIndices[MAX_UI_RANKED_RESULTS] = {};
static u16 g_rankedScores[MAX_UI_RANKED_RESULTS] = {};
static usize g_rankedCount = 0;
static bool g_rankingEnabled = false;
static bool g_rankingDirty = true;
static constexpr usize MAX_RANK_ANCHORS = 256;
struct RankAnchor_ { uptr address; int watchSlot; };
static RankAnchor_ g_rankAnchors[MAX_RANK_ANCHORS] = {};
static usize g_rankAnchorCount = 0;
static ValueType g_type = ValueType::Invalid;
static bool g_alignmentByte = false;
static FreezeEntry g_freezes[MAX_FREEZES] = {};
static PointerEntry* g_pointerIndex = nullptr;
static usize g_pointerCount = 0;
static usize g_pointerCap = 0;
static PointerChain_* g_pointerChains = nullptr;
static usize g_pointerChainCount = 0;
static usize g_pointerChainCap = 0;
static ModuleInfo_ g_modules[MAX_MODULES] = {};
static usize g_moduleCount = 0;
static u8 g_pointerSize = 8;
static u8 g_chainPointerSize = 0;
static bool g_pointerIndexTruncated = false;
static bool g_pointerChainsTruncated = false;
static volatile LONG g_pointerCancelRequested = 0;
static usize g_pointerIndexLimit = MAX_POINTER_ENTRIES;
static usize g_pointerAlignment = 0; // 0 = natural target-pointer alignment
static bool g_pointerWritableOnly = false;
static bool g_pointerPrivateOnly = false;
static usize g_pointerBranchCap = 4096;
// Reverse pointer searches can grow combinatorially. The GUI presets therefore
// use a hard work budget so every search terminates even on pointer-dense heaps.
static volatile u64 g_pointerSearchSteps = 0;
static u64 g_pointerSearchBudget = 1500000ULL;
static volatile LONG g_pointerSearchBudgetHit = 0;
static volatile u64 g_pointerLayerSlots = 0;
static volatile u64 g_pointerLayerMatches = 0;
static volatile u64 g_pointerLayerFrontier = 0;
static volatile u64 g_pointerLayerDepth = 0;
static volatile u64 g_pointerLayerMaxDepth = 0;
static volatile LONG g_pointerLayerTruncated = 0;
static char g_pointerRootModule[256] = {};
struct PointerRange_ { uptr begin; uptr end; };
static PointerRange_* g_pointerRanges = nullptr;
static usize g_pointerRangeCount = 0;
static usize g_pointerRangeCap = 0;
static PointerMap_ g_pointerMaps[MAX_POINTER_MAPS] = {};
static usize g_pointerMapCount = 0;
static SnapshotBlock_* g_snapshotBlocks = nullptr;
static usize g_snapshotCount = 0;
static usize g_snapshotCap = 0;
static HANDLE g_snapshotFile = nullptr;
static u64 g_snapshotBytes = 0;
static usize g_snapshotCandidates = 0;
static usize g_snapshotTypeCounts[6] = {};
static bool g_snapshotActive = false;
static uptr* g_aobResults = nullptr;
static usize g_aobCount = 0;
static usize g_aobCap = 0;
static u8 g_aobPatternValues[MAX_AOB_PATTERN] = {};
static u8 g_aobPatternMasks[MAX_AOB_PATTERN] = {};
static usize g_aobPatternCount = 0;
static u32 g_aobScope = 0; // 0=memory, 1=exec, 2=module, 3=module+exec
static char g_aobModule[256] = {};

static usize cstrlen(const char* s) { usize n=0; if(!s) return 0; while(s[n]) ++n; return n; }
static bool streq(const char* a,const char* b){ if(!a||!b) return false; while(*a&&*b){ if(*a!=*b)return false; ++a;++b;} return *a==0&&*b==0; }
static char ascii_lower(char c){ return (c>='A'&&c<='Z')?(char)(c-'A'+'a'):c; }
static bool strieq(const char* a,const char* b){ if(!a||!b)return false; while(*a&&*b){ if(ascii_lower(*a)!=ascii_lower(*b))return false; ++a;++b;} return *a==0&&*b==0; }
static void memcopy(void* d,const void* s,usize n){ auto* dd=(u8*)d; auto* ss=(const u8*)s; for(usize i=0;i<n;++i)dd[i]=ss[i]; }
static bool memequal(const void* a,const void* b,usize n){ auto* aa=(const u8*)a; auto* bb=(const u8*)b; for(usize i=0;i<n;++i)if(aa[i]!=bb[i])return false; return true; }
static void memzero(void* d,usize n){ auto* p=(u8*)d; for(usize i=0;i<n;++i)p[i]=0; }

static void strcopy(char* d,usize cap,const char* s){ if(!d||cap==0)return;usize i=0;if(s){while(s[i]&&i+1<cap){d[i]=s[i];++i;}}d[i]=0; }
static void narrow_wide(char* d,usize cap,const wchar_t* s){ if(!d||cap==0)return;usize i=0;if(s){while(s[i]&&i+1<cap){wchar_t c=s[i];d[i]=(c>=0&&c<128)?(char)c:'?';++i;}}d[i]=0; }

static void print_raw(const char* s, usize n){ DWORD w=0; if(n) WriteFile(g_out,s,(DWORD)n,&w,nullptr); }
static void print(const char* s){ print_raw(s,cstrlen(s)); }
static void println(const char* s){ print(s); print("\r\n"); }

static void append_char(char* b,usize cap,usize& n,char c){ if(n+1<cap)b[n++]=c; }
static void append_str(char* b,usize cap,usize& n,const char* s){ while(*s&&n+1<cap)b[n++]=*s++; }
static void append_u64_dec(char* b,usize cap,usize& n,u64 v){ char t[32];int k=0; if(v==0){append_char(b,cap,n,'0');return;} while(v&&k<31){t[k++]=(char)('0'+(v%10));v/=10;} while(k)append_char(b,cap,n,t[--k]); }
static void append_i64_dec(char* b,usize cap,usize& n,i64 v){ if(v<0){append_char(b,cap,n,'-'); u64 x=(u64)(-(v+1))+1; append_u64_dec(b,cap,n,x);} else append_u64_dec(b,cap,n,(u64)v); }
static void append_hex(char* b,usize cap,usize& n,u64 v,int digits=16){ static const char* h="0123456789ABCDEF"; append_str(b,cap,n,"0x"); bool started=false; for(int i=digits-1;i>=0;--i){u8 q=(u8)((v>>(i*4))&0xF); if(q||started||i==0){append_char(b,cap,n,h[q]);started=true;}} }
static void append_double(char* b,usize cap,usize& n,double v){ if(v<0){append_char(b,cap,n,'-');v=-v;} u64 whole=(u64)v; append_u64_dec(b,cap,n,whole); append_char(b,cap,n,'.'); double f=v-(double)whole; for(int i=0;i<6;++i){f*=10.0; int d=(int)f; if(d<0)d=0;if(d>9)d=9;append_char(b,cap,n,(char)('0'+d));f-=d;} }
static void flush_buf(char* b,usize n){ if(n<2048)b[n]=0; print_raw(b,n); }

static bool parse_u64(const char* s,u64& out){ if(!s||!*s)return false; u64 v=0; int base=10; if(s[0]=='0'&&(s[1]=='x'||s[1]=='X')){base=16;s+=2;if(!*s)return false;} bool any=false; while(*s){int d=-1; if(*s>='0'&&*s<='9')d=*s-'0'; else if(*s>='a'&&*s<='f')d=*s-'a'+10; else if(*s>='A'&&*s<='F')d=*s-'A'+10; else return false; if(d>=base)return false; v=v*(u64)base+(u64)d; any=true;++s;} out=v;return any; }
static bool parse_i64(const char* s,i64& out){ if(!s||!*s)return false; bool neg=false;if(*s=='-'){neg=true;++s;} u64 v=0;if(!parse_u64(s,v))return false; out=neg?-(i64)v:(i64)v;return true; }
static bool parse_double_simple(const char* s,double& out){ if(!s||!*s)return false; bool neg=false;if(*s=='-'){neg=true;++s;} else if(*s=='+')++s; double v=0.0;bool any=false;while(*s>='0'&&*s<='9'){v=v*10.0+(double)(*s-'0');++s;any=true;} if(*s=='.'){++s;double place=0.1;while(*s>='0'&&*s<='9'){v+=(double)(*s-'0')*place;place*=0.1;++s;any=true;}} if(!any)return false; if(*s=='e'||*s=='E'){++s;bool eneg=false;if(*s=='-'){eneg=true;++s;}else if(*s=='+')++s;int e=0;bool ea=false;while(*s>='0'&&*s<='9'){e=e*10+(*s-'0');++s;ea=true;if(e>308)e=308;}if(!ea)return false;double p=1.0;for(int i=0;i<e;++i)p*=10.0;v=eneg?v/p:v*p;} if(*s)return false;out=neg?-v:v;return true; }

static int tokenize(char* line,char** toks,int max){int c=0;char* p=line;while(*p&&c<max){while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n')++p;if(!*p)break;toks[c++]=p;while(*p&&*p!=' '&&*p!='\t'&&*p!='\r'&&*p!='\n')++p;if(*p)*p++=0;}return c;}

static bool read_line(char* out,usize cap){ usize n=0; while(n+1<cap){ char ch=0;DWORD r=0; if(!ReadFile(g_in,&ch,1,&r,nullptr)||r==0)return n>0; if(ch=='\r')continue; if(ch=='\n'){out[n]=0;return true;} if(ch==8){if(n)--n;continue;} out[n++]=ch;} out[n]=0; return true; }

static ValueType parse_type(const char* s){ if(streq(s,"byte")||streq(s,"int8"))return ValueType::Byte; if(streq(s,"int16")||streq(s,"2bytes"))return ValueType::Int16; if(streq(s,"int32")||streq(s,"4bytes"))return ValueType::Int32; if(streq(s,"int64")||streq(s,"8bytes"))return ValueType::Int64; if(streq(s,"float"))return ValueType::Float; if(streq(s,"double"))return ValueType::Double; return ValueType::Invalid; }
static u8 type_size(ValueType t){ switch(t){case ValueType::Byte:return 1;case ValueType::Int16:return 2;case ValueType::Int32:return 4;case ValueType::Int64:return 8;case ValueType::Float:return 4;case ValueType::Double:return 8;default:return 0;} }
static const char* type_name(ValueType t){ switch(t){case ValueType::Byte:return "byte";case ValueType::Int16:return "int16";case ValueType::Int32:return "int32";case ValueType::Int64:return "int64";case ValueType::Float:return "float";case ValueType::Double:return "double";case ValueType::Mixed:return "mixed";default:return "invalid";} }
static int value_type_index(ValueType t){switch(t){case ValueType::Byte:return 0;case ValueType::Int16:return 1;case ValueType::Int32:return 2;case ValueType::Int64:return 3;case ValueType::Float:return 4;case ValueType::Double:return 5;default:return -1;}}

static bool encode_value(ValueType t,const char* s,u8 out[8]){ memzero(out,8); i64 iv=0; double dv=0; switch(t){case ValueType::Byte: if(!parse_i64(s,iv)||iv<0||iv>255)return false; {u8 x=(u8)iv;memcopy(out,&x,1);}return true; case ValueType::Int16:if(!parse_i64(s,iv)||iv<-32768||iv>32767)return false;{i16 x=(i16)iv;memcopy(out,&x,2);}return true; case ValueType::Int32:if(!parse_i64(s,iv)||iv<(-2147483647LL-1)||iv>2147483647LL)return false;{i32 x=(i32)iv;memcopy(out,&x,4);}return true; case ValueType::Int64:if(!parse_i64(s,iv))return false;{i64 x=iv;memcopy(out,&x,8);}return true; case ValueType::Float:if(!parse_double_simple(s,dv))return false;{float x=(float)dv;memcopy(out,&x,4);}return true; case ValueType::Double:if(!parse_double_simple(s,dv))return false;{double x=dv;memcopy(out,&x,8);}return true; default:return false;} }

static void append_value(char* b,usize cap,usize& n,ValueType t,const u8* raw){ switch(t){case ValueType::Byte:{u8 x=0;memcopy(&x,raw,1);append_u64_dec(b,cap,n,x);break;}case ValueType::Int16:{i16 x=0;memcopy(&x,raw,2);append_i64_dec(b,cap,n,x);break;}case ValueType::Int32:{i32 x=0;memcopy(&x,raw,4);append_i64_dec(b,cap,n,x);break;}case ValueType::Int64:{i64 x=0;memcopy(&x,raw,8);append_i64_dec(b,cap,n,x);break;}case ValueType::Float:{float x=0;memcopy(&x,raw,4);append_double(b,cap,n,(double)x);break;}case ValueType::Double:{double x=0;memcopy(&x,raw,8);append_double(b,cap,n,x);break;}default:append_str(b,cap,n,"?");}}

static bool readable(DWORD p){ if(p&PAGE_GUARD)return false; DWORD x=p&0xFF; return x==PAGE_READONLY||x==PAGE_READWRITE||x==PAGE_WRITECOPY||x==PAGE_EXECUTE_READ||x==PAGE_EXECUTE_READWRITE||x==PAGE_EXECUTE_WRITECOPY; }
static bool writable(DWORD p){ if(p&PAGE_GUARD)return false; DWORD x=p&0xFF; return x==PAGE_READWRITE||x==PAGE_WRITECOPY||x==PAGE_EXECUTE_READWRITE||x==PAGE_EXECUTE_WRITECOPY; }
static bool executable(DWORD p){ if(p&PAGE_GUARD)return false; DWORD x=p&0xFF; return x==0x10||x==PAGE_EXECUTE_READ||x==PAGE_EXECUTE_READWRITE||x==PAGE_EXECUTE_WRITECOPY; }

static usize scan_start_offset(uptr base,usize alignment);
static void clear_results(){ g_resultCount=0;memzero(g_resultTypeCounts,sizeof(g_resultTypeCounts));g_rankedCount=0;g_rankingDirty=true; }
static bool reserve_results(usize need){ if(need<=g_resultCap)return true; usize nc=g_resultCap?g_resultCap:4096; while(nc<need){usize next=nc*2;if(next<nc){nc=need;break;}nc=next;if(nc>MAX_RESULTS){nc=MAX_RESULTS;break;}} if(nc<need)return false; SIZE_T bytes=nc*(SIZE_T)sizeof(Result); void* p=g_results?HeapReAlloc(g_heap,0,g_results,bytes):HeapAlloc(g_heap,0,bytes); if(!p)return false;g_results=(Result*)p;g_resultCap=nc;return true; }
static bool add_result(uptr addr,const u8* raw,u8 sz,ValueType t){ if(g_resultCount>=MAX_RESULTS)return false; if(!reserve_results(g_resultCount+1))return false; Result& r=g_results[g_resultCount++];r.address=addr;memzero(r.previous,8);memcopy(r.previous,raw,sz);r.type=(u8)t;int ti=value_type_index(t);if(ti>=0)++g_resultTypeCounts[ti];return true; }


static bool refresh_modules();
static void print_last_error(const char* prefix);
static void clear_aob(){g_aobCount=0;g_aobPatternCount=0;g_aobScope=0;g_aobModule[0]=0;}
static bool reserve_aob(usize need){if(need<=g_aobCap)return true;usize nc=g_aobCap?g_aobCap:4096;while(nc<need){usize next=nc*2;if(next<nc){nc=need;break;}nc=next;if(nc>MAX_AOB_RESULTS){nc=MAX_AOB_RESULTS;break;}}if(nc<need)return false;void* p=g_aobResults?HeapReAlloc(g_heap,0,g_aobResults,nc*sizeof(uptr)):HeapAlloc(g_heap,0,nc*sizeof(uptr));if(!p)return false;g_aobResults=(uptr*)p;g_aobCap=nc;return true;}
static bool add_aob(uptr a){if(g_aobCount>=MAX_AOB_RESULTS)return false;if(!reserve_aob(g_aobCount+1))return false;g_aobResults[g_aobCount++]=a;return true;}
static int hex_nibble(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static bool parse_aob_token(const char* in,u8& value,u8& mask){if(!in||!*in)return false;const char* t=in;usize len=cstrlen(t);if(len&&(*t=='"'||*t=='\'')){++t;--len;}if(len&&len>0&&(t[len-1]=='"'||t[len-1]=='\''))--len;if((len==1&&t[0]=='?')||(len==2&&t[0]=='?'&&t[1]=='?')){value=0;mask=0;return true;}if(len!=2)return false;bool hw=t[0]=='?',lw=t[1]=='?';int hi=hw?0:hex_nibble(t[0]);int lo=lw?0:hex_nibble(t[1]);if((!hw&&hi<0)||(!lw&&lo<0))return false;value=(u8)((hi<<4)|lo);mask=(u8)((hw?0:0xF0)|(lw?0:0x0F));return true;}
static bool aob_match(const u8* p,const u8* values,const u8* masks,usize count){for(usize i=0;i<count;++i)if((p[i]&masks[i])!=(values[i]&masks[i]))return false;return true;}
static bool scan_aob_pattern(const u8* values,const u8* masks,usize plen,bool execOnly,const char* moduleName,bool remember){
    if(!g_process){println("Attach to a process first.");return false;}if(!values||!masks||plen==0||plen>MAX_AOB_PATTERN){println("AOB pattern length is invalid.");return false;}
    g_aobCount=0;
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);uptr min=(uptr)si.lpMinimumApplicationAddress,max=(uptr)si.lpMaximumApplicationAddress;
    if(moduleName){if(!refresh_modules())return false;bool found=false;for(usize i=0;i<g_moduleCount;++i)if(strieq(g_modules[i].name,moduleName)){min=g_modules[i].base;max=g_modules[i].base+(uptr)g_modules[i].size;found=true;break;}if(!found){println("Module not found.");return false;}}
    usize alloc=SCAN_CHUNK+(plen?plen-1:0);u8* buf=(u8*)HeapAlloc(g_heap,0,alloc);if(!buf){println("Out of memory.");return false;}
    uptr cur=min;u64 total=0;bool truncated=false;
    while(cur<max&&!truncated){MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx((HANDLE)g_process,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;uptr base=(uptr)mbi.BaseAddress,end=base+(uptr)mbi.RegionSize;if(end<=cur)break;uptr cb=base<min?min:base,ce=end>max?max:end;
        if(cb<ce&&mbi.State==MEM_COMMIT&&readable(mbi.Protect)&&(!execOnly||executable(mbi.Protect))){for(uptr p=cb;p<ce&&!truncated;){usize primary=(usize)((ce-p)>SCAN_CHUNK?SCAN_CHUNK:(ce-p));usize extra=(p+primary<ce&&plen>1)?plen-1:0;usize toRead=primary+extra;if(p+toRead>ce)toRead=(usize)(ce-p);SIZE_T got=0;ReadProcessMemory((HANDLE)g_process,(LPCVOID)p,buf,toRead,&got);total+=got;if(got>=plen){usize starts=primary;if(starts>(usize)got)starts=(usize)got;usize maxStarts=(usize)got-plen+1;if(starts>maxStarts)starts=maxStarts;for(usize off=0;off<starts;++off){if(aob_match(buf+off,values,masks,plen)){if(!add_aob(p+off)){truncated=true;break;}}}}p+=primary;}}
        cur=end;
    }
    HeapFree(g_heap,0,buf);
    if(remember){g_aobPatternCount=plen;for(usize i=0;i<plen;++i){g_aobPatternValues[i]=values[i];g_aobPatternMasks[i]=masks[i];}g_aobScope=(moduleName?2u:0u)+(execOnly?1u:0u);strcopy(g_aobModule,sizeof(g_aobModule),moduleName?moduleName:"");}
    char b[256];usize n=0;append_str(b,sizeof(b),n,"AOB matches: ");append_u64_dec(b,sizeof(b),n,g_aobCount);append_str(b,sizeof(b),n," | read: ");append_u64_dec(b,sizeof(b),n,total/(1024*1024));append_str(b,sizeof(b),n," MiB");if(truncated)append_str(b,sizeof(b),n," [TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);return true;
}
static bool scan_aob_tokens(char** tok,int start,int count,bool execOnly,const char* moduleName){
    if(start>=count){println("Missing AOB pattern.");return false;}usize tokenCount=(usize)(count-start);if(tokenCount==0||tokenCount>MAX_AOB_PATTERN){println("AOB pattern length is invalid.");return false;}
    u8* patternMem=(u8*)HeapAlloc(g_heap,0,tokenCount*2);if(!patternMem){println("Out of memory.");return false;}u8* values=patternMem;u8* masks=patternMem+tokenCount;usize plen=0;
    for(int i=start;i<count;++i){if(!parse_aob_token(tok[i],values[plen],masks[plen])){HeapFree(g_heap,0,patternMem);println("Invalid AOB token. Use hex bytes, ??, A? or ?F.");return false;}++plen;}
    bool ok=scan_aob_pattern(values,masks,plen,execOnly,moduleName,true);HeapFree(g_heap,0,patternMem);return ok;
}
static void cmd_aob_results(const char* limitStr){usize limit=50;if(limitStr){u64 x=0;if(!parse_u64(limitStr,x)){println("Invalid limit.");return;}limit=(usize)x;}if(!g_aobCount){println("No stored AOB matches.");return;}refresh_modules();usize count=g_aobCount<limit?g_aobCount:limit;for(usize i=0;i<count;++i){char b[420];usize n=0;append_str(b,sizeof(b),n,"[A#");append_u64_dec(b,sizeof(b),n,i);append_str(b,sizeof(b),n,"] ");append_hex(b,sizeof(b),n,g_aobResults[i]);for(usize m=0;m<g_moduleCount;++m){uptr base=g_modules[m].base,end=base+(uptr)g_modules[m].size;if(g_aobResults[i]>=base&&g_aobResults[i]<end){append_str(b,sizeof(b),n,"  ");append_str(b,sizeof(b),n,g_modules[m].name);append_str(b,sizeof(b),n,"+");append_hex(b,sizeof(b),n,g_aobResults[i]-base);break;}}append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}char b[120];usize n=0;append_str(b,sizeof(b),n,"Total: ");append_u64_dec(b,sizeof(b),n,g_aobCount);append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);}
static bool parse_aob_target(const char* s,uptr& address){
    if(!s||!*s)return false;
    if(*s=='#'){u64 idx=0;if(!parse_u64(s+1,idx)||idx>=g_aobCount)return false;address=g_aobResults[idx];return true;}
    u64 value=0;if(!parse_u64(s,value))return false;address=(uptr)value;return true;
}
static void cmd_aob_resolve(const char* targetStr,const char* dispStr,const char* sizeStr){
    if(!g_process){println("Attach to a process first.");return;}
    uptr instruction=0;if(!parse_aob_target(targetStr,instruction)){println("Invalid AOB target. Use #0, #1, ... or an address.");return;}
    u64 dispOff=0,instSize=0;if(!parse_u64(dispStr,dispOff)||!parse_u64(sizeStr,instSize)){println("Invalid displacement offset/instruction size.");return;}
    if(instSize<4||instSize>64||dispOff+4>instSize){println("Require instruction_size 4..64 and disp_offset+4 <= instruction_size.");return;}
    if(instruction>~(uptr)0-(uptr)dispOff||instruction>~(uptr)0-(uptr)instSize){println("Address overflow.");return;}
    i32 displacement=0;SIZE_T got=0;uptr dispAddr=instruction+(uptr)dispOff;
    if(!ReadProcessMemory((HANDLE)g_process,(LPCVOID)dispAddr,&displacement,4,&got)||got!=4){print_last_error("Could not read rel32 displacement");return;}
    uptr next=instruction+(uptr)instSize,target=0;
    if(displacement>=0){uptr amount=(uptr)(u32)displacement;if(~(uptr)0-next<amount){println("rel32 target overflow.");return;}target=next+amount;}
    else{u64 magnitude=(u64)(-(i64)displacement);if(next<(uptr)magnitude){println("rel32 target underflow.");return;}target=next-(uptr)magnitude;}
    refresh_modules();char b[420];usize n=0;append_str(b,sizeof(b),n,"Instruction ");append_hex(b,sizeof(b),n,instruction);append_str(b,sizeof(b),n," | rel32 @ +");append_hex(b,sizeof(b),n,dispOff);append_str(b,sizeof(b),n," = ");append_i64_dec(b,sizeof(b),n,(i64)displacement);append_str(b,sizeof(b),n," | target ");append_hex(b,sizeof(b),n,target);
    for(usize m=0;m<g_moduleCount;++m){uptr base=g_modules[m].base,end=base+(uptr)g_modules[m].size;if(target>=base&&target<end){append_str(b,sizeof(b),n,"  ");append_str(b,sizeof(b),n,g_modules[m].name);append_str(b,sizeof(b),n,"+");append_hex(b,sizeof(b),n,target-base);break;}}
    append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);
}

static bool snapshot_file_valid(){return g_snapshotFile&&(uptr)g_snapshotFile!=INVALID_HANDLE_BITS;}
static bool snapshot_seek(u64 offset){
    if(!snapshot_file_valid()||offset>0x7FFFFFFFFFFFFFFFULL)return false;
    LONG high=(LONG)(u32)(offset>>32);LONG low=(LONG)(u32)offset;SetLastError(0);
    DWORD result=SetFilePointer(g_snapshotFile,low,&high,FILE_BEGIN);
    return result!=INVALID_SET_FILE_POINTER_||GetLastError()==0;
}
static bool snapshot_read_at(u64 offset,void* data,usize size){
    if(!size)return true;if(!data||!snapshot_seek(offset))return false;u8* p=(u8*)data;
    while(size){DWORD chunk=size>0x40000000ULL?0x40000000UL:(DWORD)size;DWORD got=0;if(!ReadFile(g_snapshotFile,p,chunk,&got,nullptr)||got!=chunk)return false;p+=got;size-=got;}return true;
}
static bool snapshot_write_at(u64 offset,const void* data,usize size){
    if(!size)return true;if(!data||!snapshot_seek(offset))return false;const u8* p=(const u8*)data;
    while(size){DWORD chunk=size>0x40000000ULL?0x40000000UL:(DWORD)size;DWORD wrote=0;if(!WriteFile(g_snapshotFile,p,chunk,&wrote,nullptr)||wrote!=chunk)return false;p+=wrote;size-=wrote;}return true;
}
static bool snapshot_open(){
    if(snapshot_file_valid())return true;char dir[260]{};char path[260]{};DWORD n=GetTempPathA((DWORD)sizeof(dir),dir);if(!n||n>=sizeof(dir))return false;
    if(!GetTempFileNameA(dir,"MCE",0,path))return false;
    HANDLE h=CreateFileA(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ_|FILE_SHARE_WRITE_|FILE_SHARE_DELETE_,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_TEMPORARY_|FILE_FLAG_DELETE_ON_CLOSE_|FILE_FLAG_SEQUENTIAL_SCAN_,nullptr);
    if((uptr)h==INVALID_HANDLE_BITS){DeleteFileA(path);return false;}g_snapshotFile=h;g_snapshotBytes=0;return true;
}
static void snapshot_close(){if(snapshot_file_valid())CloseHandle(g_snapshotFile);g_snapshotFile=nullptr;}
static bool snapshot_append(const void* data,usize size,u64& offset){if(!snapshot_open()||size>~(u64)0-g_snapshotBytes)return false;offset=g_snapshotBytes;if(!snapshot_write_at(offset,data,size))return false;g_snapshotBytes+=(u64)size;return true;}
static bool reserve_snapshot_blocks(usize need){
    if(need<=g_snapshotCap)return true;usize nc=g_snapshotCap?g_snapshotCap:256;while(nc<need){usize next=nc*2;if(next<=nc){nc=need;break;}nc=next;}if(nc>~(usize)0/sizeof(SnapshotBlock_))return false;
    SIZE_T bytes=nc*(SIZE_T)sizeof(SnapshotBlock_);void* p=g_snapshotBlocks?HeapReAlloc(g_heap,0,g_snapshotBlocks,bytes):HeapAlloc(g_heap,0,bytes);if(!p)return false;g_snapshotBlocks=(SnapshotBlock_*)p;for(usize i=g_snapshotCap;i<nc;++i)memzero(&g_snapshotBlocks[i],sizeof(SnapshotBlock_));g_snapshotCap=nc;return true;
}
static void clear_snapshot(){
    for(usize i=0;i<g_snapshotCount;++i){
        for(int ti=0;ti<6;++ti)if(g_snapshotBlocks[i].masks[ti])HeapFree(g_heap,0,g_snapshotBlocks[i].masks[ti]);
        memzero(&g_snapshotBlocks[i],sizeof(SnapshotBlock_));
    }
    snapshot_close();g_snapshotCount=0;g_snapshotBytes=0;g_snapshotCandidates=0;memzero(g_snapshotTypeCounts,sizeof(g_snapshotTypeCounts));g_snapshotActive=false;
}
static usize candidate_count_for(uptr base,usize available,usize candidateBytes,usize sz){
    if(!sz||available<sz||candidateBytes==0)return 0;
    candidateBytes=candidateBytes<available?candidateBytes:available;
    usize step=g_alignmentByte?1:sz;
    usize start=scan_start_offset(base,sz);
    if(start>=candidateBytes||start+sz>available)return 0;
    usize maxAvail=available-sz,maxCandidate=candidateBytes-1,maxStart=maxAvail<maxCandidate?maxAvail:maxCandidate;
    return 1+(maxStart-start)/step;
}
static bool add_snapshot_block(uptr base,const u8* data,usize size,usize candidateBytes,ValueType snapshotType){
    if(!data||!size||!reserve_snapshot_blocks(g_snapshotCount+1))return false;
    u64 fileOffset=0;if(!snapshot_append(data,size,fileOffset))return false;
    SnapshotBlock_& b=g_snapshotBlocks[g_snapshotCount++];memzero(&b,sizeof(b));b.base=base;b.fileOffset=fileOffset;b.size=size;b.candidateBytes=candidateBytes<size?candidateBytes:size;
    const ValueType types[6]={ValueType::Byte,ValueType::Int16,ValueType::Int32,ValueType::Int64,ValueType::Float,ValueType::Double};
    const usize sizes[6]={1,2,4,8,4,8};
    for(int i=0;i<6;++i){
        if(snapshotType!=ValueType::Mixed&&snapshotType!=types[i])continue;
        usize c=candidate_count_for(base,size,b.candidateBytes,sizes[i]);
        b.candidateCounts[i]=c;b.activeCounts[i]=c;b.maskModes[i]=c?SNAP_MASK_ALL:SNAP_MASK_NONE;
        usize max=(usize)-1;if(c>max-g_snapshotCandidates)g_snapshotCandidates=max;else g_snapshotCandidates+=c;if(c>max-g_snapshotTypeCounts[i])g_snapshotTypeCounts[i]=max;else g_snapshotTypeCounts[i]+=c;
    }
    return true;
}
static bool snapshot_mask_test(const SnapshotBlock_& b,int ti,usize index){
    if(ti<0||ti>=6||index>=b.candidateCounts[ti])return false;
    if(b.maskModes[ti]==SNAP_MASK_ALL)return true;
    if(b.maskModes[ti]!=SNAP_MASK_EXPLICIT||!b.masks[ti])return false;
    return (b.masks[ti][index>>3]&(u8)(1u<<(index&7)))!=0;
}
static void snapshot_mask_set(u8* mask,usize index){if(mask)mask[index>>3]|=(u8)(1u<<(index&7));}
static usize snapshot_mask_bytes(usize count){return (count+7)/8;}
static void refresh_snapshot_type_counts(){memzero(g_snapshotTypeCounts,sizeof(g_snapshotTypeCounts));g_snapshotCandidates=0;usize max=(usize)-1;for(usize bi=0;bi<g_snapshotCount;++bi){for(int ti=0;ti<6;++ti){usize c=g_snapshotBlocks[bi].activeCounts[ti];if(c>max-g_snapshotTypeCounts[ti])g_snapshotTypeCounts[ti]=max;else g_snapshotTypeCounts[ti]+=c;if(c>max-g_snapshotCandidates)g_snapshotCandidates=max;else g_snapshotCandidates+=c;}}}
static void refresh_result_type_counts(){memzero(g_resultTypeCounts,sizeof(g_resultTypeCounts));for(usize i=0;i<g_resultCount;++i){int ti=value_type_index((ValueType)g_results[i].type);if(ti>=0)++g_resultTypeCounts[ti];}}
static bool disable_mixed_type(ValueType t){if(g_type!=ValueType::Mixed)return false;int ti=value_type_index(t);if(ti<0)return false;bool changed=false;if(g_snapshotActive){for(usize bi=0;bi<g_snapshotCount;++bi){SnapshotBlock_& b=g_snapshotBlocks[bi];if(!b.activeCounts[ti])continue;if(b.masks[ti]){HeapFree(g_heap,0,b.masks[ti]);b.masks[ti]=nullptr;}b.activeCounts[ti]=0;b.maskModes[ti]=SNAP_MASK_NONE;changed=true;}if(changed)refresh_snapshot_type_counts();return changed;}usize out=0;for(usize i=0;i<g_resultCount;++i){if((ValueType)g_results[i].type==t){changed=true;continue;}if(out!=i)g_results[out]=g_results[i];++out;}g_resultCount=out;if(changed){refresh_result_type_counts();g_rankingDirty=true;}return changed;}

static void guided_reset(){g_guidedCount=0;memzero(g_guidedSteps,sizeof(g_guidedSteps));}
static usize guided_current_count(){return g_snapshotActive?g_snapshotCandidates:g_resultCount;}
static void guided_current_types(usize out[6]){for(int i=0;i<6;++i)out[i]=g_snapshotActive?g_snapshotTypeCounts[i]:g_resultTypeCounts[i];}
static void guided_record(NextMode mode,usize before,const usize beforeTypes[6]){if(g_guidedCount>=MAX_GUIDED_STEPS){for(usize i=1;i<MAX_GUIDED_STEPS;++i)memcopy(&g_guidedSteps[i-1],&g_guidedSteps[i],sizeof(GuidedStep_));g_guidedCount=MAX_GUIDED_STEPS-1;}GuidedStep_& s=g_guidedSteps[g_guidedCount++];memzero(&s,sizeof(s));s.mode=(u8)mode;s.beforeCount=before;s.afterCount=guided_current_count();for(int i=0;i<6;++i)s.beforeTypes[i]=beforeTypes[i];guided_current_types(s.afterTypes);}
static const char* ui_tr(const char* key);
static const char* guided_mode_name(NextMode mode){switch(mode){case NextMode::Changed:return ui_tr("guided.changed");case NextMode::Unchanged:return ui_tr("guided.unchanged");case NextMode::Increased:return ui_tr("guided.increased");case NextMode::Decreased:return ui_tr("guided.decreased");case NextMode::Exact:return ui_tr("guided.exact");case NextMode::Bigger:return ui_tr("guided.bigger");case NextMode::Smaller:return ui_tr("guided.smaller");}return "?";}
static const char* guided_goal_name(GuidedGoal_ goal){switch(goal){case GuidedGoal_::Generic:return ui_tr("guided.goal.generic");case GuidedGoal_::Money:return ui_tr("guided.goal.money");case GuidedGoal_::Health:return ui_tr("guided.goal.health");case GuidedGoal_::Ammo:return ui_tr("guided.goal.ammo");}return ui_tr("guided.goal.generic");}
static NextMode guided_recommended_mode(){if(g_guidedGoal==GuidedGoal_::Generic){if(!g_guidedCount||g_guidedSteps[g_guidedCount-1].mode==(u8)NextMode::Unchanged)return NextMode::Changed;return NextMode::Unchanged;}if(!g_guidedCount)return NextMode::Decreased;if(g_guidedSteps[g_guidedCount-1].mode!=(u8)NextMode::Unchanged)return NextMode::Unchanged;for(usize i=g_guidedCount;i>0;--i){NextMode m=(NextMode)g_guidedSteps[i-1].mode;if(m==NextMode::Decreased)return NextMode::Increased;if(m==NextMode::Increased)return NextMode::Decreased;}return NextMode::Decreased;}
static const char* guided_action_text(){NextMode mode=guided_recommended_mode();if(mode==NextMode::Unchanged)return ui_tr("guided.action.steady");switch(g_guidedGoal){case GuidedGoal_::Money:return mode==NextMode::Decreased?ui_tr("guided.action.moneyDown"):ui_tr("guided.action.moneyUp");case GuidedGoal_::Health:return mode==NextMode::Decreased?ui_tr("guided.action.healthDown"):ui_tr("guided.action.healthUp");case GuidedGoal_::Ammo:return mode==NextMode::Decreased?ui_tr("guided.action.ammoDown"):ui_tr("guided.action.ammoUp");case GuidedGoal_::Generic:return ui_tr("guided.action.generic");}return ui_tr("guided.action.fallback");}
static u16 result_type_rank(ValueType t){switch(t){case ValueType::Int32:case ValueType::Float:return 30;case ValueType::Int64:case ValueType::Double:return 18;case ValueType::Int16:return 10;case ValueType::Byte:return 4;default:return 0;}}
static u16 result_value_rank(const Result& r){switch((ValueType)r.type){case ValueType::Byte:{u8 v=0;memcopy(&v,r.previous,1);if(!v)return 0;return (u16)(2+(v<=100?4:0));}case ValueType::Int16:{i16 v=0;memcopy(&v,r.previous,2);if(!v)return 0;return (u16)(3+((v>=-10000&&v<=10000)?6:0));}case ValueType::Int32:{i32 v=0;memcopy(&v,r.previous,4);if(!v)return 0;u16 s=4;if(v>=-1000000000&&v<=1000000000)s+=6;if(v>=-10000000&&v<=10000000)s+=8;return s;}case ValueType::Int64:{i64 v=0;memcopy(&v,r.previous,8);if(!v)return 0;u16 s=4;if(v>=-1000000000LL&&v<=1000000000LL)s+=6;if(v>=-10000000LL&&v<=10000000LL)s+=8;return s;}case ValueType::Float:{u32 bits=0;float v=0;memcopy(&bits,r.previous,4);memcopy(&v,r.previous,4);u32 exp=(bits>>23)&0xFFu;if(exp==0xFFu||v==0.0f)return 0;float a=v<0.0f?-v:v;u16 s=4;if(exp!=0)s+=4;if(a>=1.0e-6f&&a<=1.0e9f)s+=8;if(a>=1.0e-3f&&a<=1.0e7f)s+=6;return s;}case ValueType::Double:{u64 bits=0;double v=0;memcopy(&bits,r.previous,8);memcopy(&v,r.previous,8);u64 exp=(bits>>52)&0x7FFULL;if(exp==0x7FFULL||v==0.0)return 0;double a=v<0.0?-v:v;u16 s=4;if(exp!=0)s+=4;if(a>=1.0e-6&&a<=1.0e9)s+=8;if(a>=1.0e-3&&a<=1.0e7)s+=6;return s;}default:return 0;}}
static u16 result_goal_type_rank(ValueType t){switch(g_guidedGoal){case GuidedGoal_::Generic:return 0;case GuidedGoal_::Money:switch(t){case ValueType::Int32:return 36;case ValueType::Int64:return 28;case ValueType::Int16:return 8;case ValueType::Float:return 4;case ValueType::Double:return 2;case ValueType::Byte:return 1;default:return 0;}case GuidedGoal_::Health:switch(t){case ValueType::Float:return 24;case ValueType::Int32:return 18;case ValueType::Double:return 12;case ValueType::Int16:return 10;case ValueType::Byte:return 6;case ValueType::Int64:return 4;default:return 0;}case GuidedGoal_::Ammo:switch(t){case ValueType::Int32:return 34;case ValueType::Int16:return 22;case ValueType::Byte:return 16;case ValueType::Int64:return 10;case ValueType::Float:return 2;default:return 0;}}return 0;}
static bool result_near_whole(double v){double a=v<0.0?-v:v;if(a>9000000000000000.0)return false;i64 q=(i64)(v>=0.0?v+0.5:v-0.5);double d=v-(double)q;if(d<0.0)d=-d;double tol=a*1.0e-5;if(tol<0.001)tol=0.001;return d<=tol;}
static u16 result_goal_value_rank(const Result& r){double v=0.0;bool integral=false;switch((ValueType)r.type){case ValueType::Byte:{u8 x=0;memcopy(&x,r.previous,1);v=(double)x;integral=true;break;}case ValueType::Int16:{i16 x=0;memcopy(&x,r.previous,2);v=(double)x;integral=true;break;}case ValueType::Int32:{i32 x=0;memcopy(&x,r.previous,4);v=(double)x;integral=true;break;}case ValueType::Int64:{i64 x=0;memcopy(&x,r.previous,8);v=(double)x;integral=true;break;}case ValueType::Float:{u32 bits=0;float x=0;memcopy(&bits,r.previous,4);memcopy(&x,r.previous,4);if(((bits>>23)&0xFFu)==0xFFu)return 0;v=(double)x;break;}case ValueType::Double:{u64 bits=0;double x=0;memcopy(&bits,r.previous,8);memcopy(&x,r.previous,8);if(((bits>>52)&0x7FFULL)==0x7FFULL)return 0;v=x;break;}default:return 0;}double a=v<0.0?-v:v;u16 s=0;if(v>0.0)s+=2;if(a>=0.001&&a<=1000.0)s+=4;if(a>=1.0&&a<=100000.0)s+=3;if(result_near_whole(v))s+=(u16)(integral?3:8);if(g_guidedGoal==GuidedGoal_::Money){if(v>=0.0)s+=10;if(v>=1.0&&v<=1.0e9)s+=6;if(v<=1.0e7)s+=4;if(!integral&&result_near_whole(v))s+=5;}else if(g_guidedGoal==GuidedGoal_::Health){if(v>=0.0&&v<=1000.0)s+=12;if(v>=0.0&&v<=250.0)s+=8;if(!integral&&v>=0.0&&v<=1.0)s+=5;}else if(g_guidedGoal==GuidedGoal_::Ammo){if(v>=0.0&&v<=1000.0)s+=12;if(v>=0.0&&v<=500.0)s+=8;if(v>=0.0&&v<=100.0)s+=4;if(integral)s+=4;}return s;}
static u16 result_isolation_rank(usize idx){if(idx>=g_resultCount)return 0;const Result& r=g_results[idx];uptr nearest=(uptr)-1;for(usize d=1;d<=8;++d){if(idx>=d){const Result& o=g_results[idx-d];if(o.type==r.type){uptr dist=o.address>r.address?o.address-r.address:r.address-o.address;if(dist&&dist<nearest)nearest=dist;}}if(idx+d<g_resultCount){const Result& o=g_results[idx+d];if(o.type==r.type){uptr dist=o.address>r.address?o.address-r.address:r.address-o.address;if(dist&&dist<nearest)nearest=dist;}}}if(nearest==(uptr)-1)return 8;uptr width=(uptr)type_size((ValueType)r.type);if(nearest>=width*256)return 12;if(nearest>=width*64)return 9;if(nearest>=width*16)return 6;if(nearest>=width*4)return 3;return 0;}
static bool rank_nearest_anchor(uptr address,uptr& distance,int& watchSlot,uptr* anchorAddress=nullptr){distance=(uptr)-1;watchSlot=-1;if(!g_rankAnchorCount)return false;usize lo=0,hi=g_rankAnchorCount;while(lo<hi){usize mid=lo+(hi-lo)/2;if(g_rankAnchors[mid].address<address)lo=mid+1;else hi=mid;}auto consider=[&](usize i){if(i>=g_rankAnchorCount)return;uptr a=g_rankAnchors[i].address;uptr d=a>address?a-address:address-a;if(d<distance||(d==distance&&g_rankAnchors[i].watchSlot<watchSlot)){distance=d;watchSlot=g_rankAnchors[i].watchSlot;if(anchorAddress)*anchorAddress=a;}};consider(lo);if(lo)consider(lo-1);return watchSlot>=0;}
static u16 result_watch_proximity_rank(uptr address,uptr regionBegin,uptr regionEnd,bool regionValid){uptr distance=0,anchor=0;int slot=-1;if(!rank_nearest_anchor(address,distance,slot,&anchor)||distance==0)return 0;u16 score=0;if(distance<=0x1000u)score=28;else if(distance<=0x10000u)score=22;else if(distance<=0x100000u)score=14;else if(distance<=0x1000000u)score=6;else return 0;if(regionValid&&anchor>=regionBegin&&anchor<regionEnd)score=(u16)(score+10);return score;}
static u16 result_rank_score(usize idx,MEMORY_BASIC_INFORMATION_& cached,uptr& begin,uptr& end,bool& valid){if(idx>=g_resultCount)return 0;uptr a=g_results[idx].address;if(!valid||a<begin||a>=end){MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx((HANDLE)g_process,(LPCVOID)a,&mbi,sizeof(mbi));if(q&&mbi.RegionSize){memcopy(&cached,&mbi,sizeof(mbi));begin=(uptr)mbi.BaseAddress;end=begin+(uptr)mbi.RegionSize;if(end<=begin)end=(uptr)-1;valid=a>=begin&&a<end;}else valid=false;}u16 score=(u16)(result_type_rank((ValueType)g_results[idx].type)+result_value_rank(g_results[idx])+result_goal_type_rank((ValueType)g_results[idx].type)+result_goal_value_rank(g_results[idx])+result_isolation_rank(idx)+result_watch_proximity_rank(a,begin,end,valid));if(valid){if(cached.Type==MEM_PRIVATE)score+=50;if(writable(cached.Protect))score+=30;if(!executable(cached.Protect))score+=10;}return score;}
static bool rank_entry_better(u16 scoreA,usize idxA,u16 scoreB,usize idxB){if(scoreA!=scoreB)return scoreA>scoreB;if(g_results[idxA].address!=g_results[idxB].address)return g_results[idxA].address<g_results[idxB].address;if(g_results[idxA].type!=g_results[idxB].type)return g_results[idxA].type<g_results[idxB].type;return idxA<idxB;}
static void rebuild_result_ranking(){g_rankedCount=0;g_rankingDirty=false;if(!g_rankingEnabled||g_snapshotActive||!g_process||!g_resultCount)return;usize histogram[256]{};MEMORY_BASIC_INFORMATION_ cache{};uptr begin=0,end=0;bool valid=false;for(usize i=0;i<g_resultCount;++i){u16 s=result_rank_score(i,cache,begin,end,valid);if(s>255)s=255;++histogram[s];}usize need=g_resultCount<MAX_UI_RANKED_RESULTS?g_resultCount:MAX_UI_RANKED_RESULTS;usize cumulative=0;int cutoff=0;for(int s=255;s>=0;--s){if(cumulative+histogram[s]>=need){cutoff=s;break;}cumulative+=histogram[s];}memzero(&cache,sizeof(cache));begin=end=0;valid=false;for(usize i=0;i<g_resultCount&&g_rankedCount<need;++i){u16 s=result_rank_score(i,cache,begin,end,valid);if((int)s<=cutoff)continue;g_rankedIndices[g_rankedCount]=i;g_rankedScores[g_rankedCount]=s;++g_rankedCount;}memzero(&cache,sizeof(cache));begin=end=0;valid=false;for(usize i=0;i<g_resultCount&&g_rankedCount<need;++i){u16 s=result_rank_score(i,cache,begin,end,valid);if((int)s!=cutoff)continue;g_rankedIndices[g_rankedCount]=i;g_rankedScores[g_rankedCount]=s;++g_rankedCount;}for(usize i=1;i<g_rankedCount;++i){usize idx=g_rankedIndices[i];u16 score=g_rankedScores[i];usize j=i;while(j>0&&rank_entry_better(score,idx,g_rankedScores[j-1],g_rankedIndices[j-1])){g_rankedIndices[j]=g_rankedIndices[j-1];g_rankedScores[j]=g_rankedScores[j-1];--j;}g_rankedIndices[j]=idx;g_rankedScores[j]=score;}}

static void print_last_error(const char* prefix){ char b[256];usize n=0;append_str(b,sizeof(b),n,prefix);append_str(b,sizeof(b),n," (Win32 error ");append_u64_dec(b,sizeof(b),n,(u64)GetLastError());append_str(b,sizeof(b),n,")\r\n");flush_buf(b,n); }

static void cmd_processes(){ HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); if(snap==(HANDLE)(uptr)-1){print_last_error("CreateToolhelp32Snapshot failed");return;} PROCESSENTRY32A_ e{};e.dwSize=(DWORD)sizeof(e); if(!Process32First(snap,&e)){print_last_error("Process32First failed");CloseHandle(snap);return;} println("PID       PROCESS"); do{char b[512];usize n=0;append_u64_dec(b,sizeof(b),n,e.th32ProcessID);while(n<10)append_char(b,sizeof(b),n,' ');append_str(b,sizeof(b),n,e.szExeFile);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}while(Process32Next(snap,&e));CloseHandle(snap); }


static bool parse_index(const char* s,usize& idx);
static void clear_pointer_index(){ g_pointerCount=0; g_pointerIndexTruncated=false; }
static void clear_pointer_chains(){ g_pointerChainCount=0; g_pointerChainsTruncated=false; g_chainPointerSize=0; }
static bool reserve_pointer_index(usize need){ if(need<=g_pointerCap)return true;usize nc=g_pointerCap?g_pointerCap:65536;while(nc<need){usize next=nc*2;if(next<nc){nc=need;break;}nc=next;if(nc>MAX_POINTER_ENTRIES){nc=MAX_POINTER_ENTRIES;break;}}if(nc<need)return false;SIZE_T bytes=nc*(SIZE_T)sizeof(PointerEntry);void* q=g_pointerIndex?HeapReAlloc(g_heap,0,g_pointerIndex,bytes):HeapAlloc(g_heap,0,bytes);if(!q)return false;g_pointerIndex=(PointerEntry*)q;g_pointerCap=nc;return true;}
static bool add_pointer_entry(uptr value,uptr address){if(g_pointerCount>=g_pointerIndexLimit){g_pointerIndexTruncated=true;return false;}if(!reserve_pointer_index(g_pointerCount+1)){g_pointerIndexTruncated=true;return false;}g_pointerIndex[g_pointerCount++]={value,address};return true;}
static bool reserve_pointer_chains(usize need){if(need<=g_pointerChainCap)return true;usize nc=g_pointerChainCap?g_pointerChainCap:256;while(nc<need){usize next=nc*2;if(next<nc){nc=need;break;}nc=next;if(nc>MAX_POINTER_CHAINS){nc=MAX_POINTER_CHAINS;break;}}if(nc<need)return false;SIZE_T bytes=nc*(SIZE_T)sizeof(PointerChain_);void* q=g_pointerChains?HeapReAlloc(g_heap,0,g_pointerChains,bytes):HeapAlloc(g_heap,0,bytes);if(!q)return false;g_pointerChains=(PointerChain_*)q;g_pointerChainCap=nc;return true;}
static bool ptr_less(const PointerEntry& a,const PointerEntry& b){return a.value<b.value||(a.value==b.value&&a.address<b.address);}
static void ptr_swap(PointerEntry& a,PointerEntry& b){PointerEntry t=a;a=b;b=t;}
static void heap_sift(usize start,usize count){usize root=start;for(;;){usize child=root*2+1;if(child>=count)return;usize best=root;if(ptr_less(g_pointerIndex[best],g_pointerIndex[child]))best=child;if(child+1<count&&ptr_less(g_pointerIndex[best],g_pointerIndex[child+1]))best=child+1;if(best==root)return;ptr_swap(g_pointerIndex[root],g_pointerIndex[best]);root=best;}}
static void sort_pointer_index(){if(g_pointerCount<2)return;for(usize i=g_pointerCount/2;i>0;--i)heap_sift(i-1,g_pointerCount);for(usize end=g_pointerCount;end>1;--end){ptr_swap(g_pointerIndex[0],g_pointerIndex[end-1]);usize root=0,count=end-1;for(;;){usize child=root*2+1;if(child>=count)break;usize best=root;if(ptr_less(g_pointerIndex[best],g_pointerIndex[child]))best=child;if(child+1<count&&ptr_less(g_pointerIndex[best],g_pointerIndex[child+1]))best=child+1;if(best==root)break;ptr_swap(g_pointerIndex[root],g_pointerIndex[best]);root=best;}}usize out=0;for(usize i=0;i<g_pointerCount;++i){if(out&&g_pointerIndex[i].value==g_pointerIndex[out-1].value&&g_pointerIndex[i].address==g_pointerIndex[out-1].address)continue;if(out!=i)g_pointerIndex[out]=g_pointerIndex[i];++out;}g_pointerCount=out;}
static usize lower_pointer_value(uptr value){usize lo=0,hi=g_pointerCount;while(lo<hi){usize mid=lo+(hi-lo)/2;if(g_pointerIndex[mid].value<value)lo=mid+1;else hi=mid;}return lo;}
static usize upper_pointer_value(uptr value){usize lo=0,hi=g_pointerCount;while(lo<hi){usize mid=lo+(hi-lo)/2;if(g_pointerIndex[mid].value<=value)lo=mid+1;else hi=mid;}return lo;}
static int module_for_address(uptr address){
    for(usize i=0;i<g_moduleCount;++i){
        if(address<g_modules[i].base||address-g_modules[i].base>=g_modules[i].size)continue;
        if(g_pointerRootModule[0]&&!strieq(g_modules[i].name,g_pointerRootModule))continue;
        return (int)i;
    }
    return -1;
}
static int module_by_name(const char* name){for(usize i=0;i<g_moduleCount;++i)if(strieq(g_modules[i].name,name))return (int)i;return -1;}
static bool refresh_modules(){g_moduleCount=0;if(!g_process)return false;HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,g_pid);if(snap==(HANDLE)(uptr)-1){print_last_error("Module snapshot failed");return false;}MODULEENTRY32W_ e{};e.dwSize=(DWORD)sizeof(e);if(!Module32FirstW(snap,&e)){print_last_error("Module32FirstW failed");CloseHandle(snap);return false;}do{if(g_moduleCount>=MAX_MODULES)break;ModuleInfo_& m=g_modules[g_moduleCount++];m.base=(uptr)e.modBaseAddr;m.size=(u64)e.modBaseSize;narrow_wide(m.name,sizeof(m.name),e.szModule);}while(Module32NextW(snap,&e));CloseHandle(snap);return g_moduleCount>0;}
static void cmd_modules(){if(!g_process){println("Attach to a process first.");return;}if(!refresh_modules())return;println("BASE                SIZE        MODULE");for(usize i=0;i<g_moduleCount;++i){char b[420];usize n=0;append_hex(b,sizeof(b),n,g_modules[i].base);while(n<20)append_char(b,sizeof(b),n,' ');append_hex(b,sizeof(b),n,g_modules[i].size,8);while(n<32)append_char(b,sizeof(b),n,' ');append_str(b,sizeof(b),n,g_modules[i].name);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}char b[128];usize n=0;append_str(b,sizeof(b),n,"Total modules: ");append_u64_dec(b,sizeof(b),n,g_moduleCount);append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);}
static bool parse_target_address(const char* s,uptr& address){if(!s)return false;if(*s=='#'){usize idx=0;if(!parse_index(s,idx))return false;address=g_results[idx].address;return true;}u64 v=0;if(!parse_u64(s,v))return false;address=(uptr)v;return true;}
static bool reserve_pointer_ranges(usize need){
    if(need<=g_pointerRangeCap)return true;
    usize nc=g_pointerRangeCap?g_pointerRangeCap:4096;
    while(nc<need){usize next=nc*2;if(next<nc){nc=need;break;}nc=next;if(nc>MAX_POINTER_RANGES){nc=MAX_POINTER_RANGES;break;}}
    if(nc<need)return false;
    SIZE_T bytes=nc*(SIZE_T)sizeof(PointerRange_);
    void* q=g_pointerRanges?HeapReAlloc(g_heap,0,g_pointerRanges,bytes):HeapAlloc(g_heap,0,bytes);
    if(!q)return false;g_pointerRanges=(PointerRange_*)q;g_pointerRangeCap=nc;return true;
}
static bool collect_pointer_target_ranges(){
    g_pointerRangeCount=0;SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);uptr cur=(uptr)si.lpMinimumApplicationAddress,max=(uptr)si.lpMaximumApplicationAddress;
    while(cur<max){MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx((HANDLE)g_process,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;uptr base=(uptr)mbi.BaseAddress,end=base+(uptr)mbi.RegionSize;if(end<=cur)break;
        if(mbi.State==MEM_COMMIT&&readable(mbi.Protect)){if(!reserve_pointer_ranges(g_pointerRangeCount+1))return false;g_pointerRanges[g_pointerRangeCount++]={base,end};}
        cur=end;
    }
    return g_pointerRangeCount>0;
}
static bool pointer_value_targets_readable(uptr value){
    usize lo=0,hi=g_pointerRangeCount;while(lo<hi){usize mid=lo+(hi-lo)/2;PointerRange_ r=g_pointerRanges[mid];if(value<r.begin)hi=mid;else if(value>=r.end)lo=mid+1;else return true;}return false;
}
static usize pointer_near_target_count(uptr target,uptr maxOffset,uptr maxNegative){
    uptr low=target>=maxOffset?target-maxOffset:0;uptr high=(~(uptr)0-target<maxNegative)?~(uptr)0:target+maxNegative;usize b=lower_pointer_value(low),e=upper_pointer_value(high);return e>=b?e-b:0;
}

static bool build_pointer_index(){
    if(!g_process){println("Attach to a process first.");return false;}
    clear_pointer_index();
    if(!collect_pointer_target_ranges()){println("Could not build readable target-region map for pointer scan.");return false;}
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);
    uptr min=(uptr)si.lpMinimumApplicationAddress,max=(uptr)si.lpMaximumApplicationAddress;
    usize alignment=g_pointerAlignment?g_pointerAlignment:(usize)g_pointerSize;
    if(!(alignment==1||alignment==2||alignment==4||alignment==8)){println("Invalid pointer alignment setting.");return false;}
    u8* buf=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!buf){println("Out of memory.");return false;}
    uptr cur=min;usize regions=0;
    while(cur<max&&!g_pointerIndexTruncated&&!g_pointerCancelRequested){
        MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx((HANDLE)g_process,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;
        uptr base=(uptr)mbi.BaseAddress,end=base+(uptr)mbi.RegionSize;if(end<=cur)break;
        bool allowed=mbi.State==MEM_COMMIT&&readable(mbi.Protect);
        if(allowed&&g_pointerWritableOnly&&!writable(mbi.Protect))allowed=false;
        if(allowed&&g_pointerPrivateOnly&&mbi.Type!=MEM_PRIVATE)allowed=false;
        if(allowed){
            ++regions;
            for(uptr p=base;p<end&&!g_pointerIndexTruncated&&!g_pointerCancelRequested;){
                usize primary=(usize)((end-p)>SCAN_CHUNK?SCAN_CHUNK:(end-p));
                usize extra=(p+primary<end)?(usize)(g_pointerSize-1):0;
                usize toRead=primary+extra;if(p+toRead>end)toRead=(usize)(end-p);
                SIZE_T got=0;ReadProcessMemory((HANDLE)g_process,(LPCVOID)p,buf,toRead,&got);
                if(got>=g_pointerSize){
                    usize startOff=0;usize rem=(usize)(p%alignment);if(rem)startOff=alignment-rem;
                    for(usize off=startOff;off<primary&&off+g_pointerSize<=(usize)got&&!g_pointerCancelRequested;off+=alignment){
                        uptr value=0;
                        if(g_pointerSize==4){u32 v=0;memcopy(&v,buf+off,4);value=(uptr)v;}
                        else{u64 v=0;memcopy(&v,buf+off,8);value=(uptr)v;}
                        if(value>=min&&value<max&&pointer_value_targets_readable(value)){if(!add_pointer_entry(value,p+off))break;}
                    }
                }
                p+=primary;
            }
        }
        cur=end;
    }
    HeapFree(g_heap,0,buf);if(g_pointerCancelRequested){clear_pointer_index();return false;}sort_pointer_index();
    char b[360];usize n=0;append_str(b,sizeof(b),n,"Pointer index: ");append_u64_dec(b,sizeof(b),n,g_pointerCount);
    append_str(b,sizeof(b),n," entries across ");append_u64_dec(b,sizeof(b),n,regions);append_str(b,sizeof(b),n," region(s), alignment ");
    if(g_pointerAlignment==0)append_str(b,sizeof(b),n,"natural");else append_u64_dec(b,sizeof(b),n,alignment);
    if(g_pointerWritableOnly)append_str(b,sizeof(b),n," | writable-only");if(g_pointerPrivateOnly)append_str(b,sizeof(b),n," | private-only");
    if(g_pointerIndexTruncated)append_str(b,sizeof(b),n," [TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);
    return g_pointerCount>0;
}
static bool path_has(const uptr* path,u8 count,uptr value){for(u8 i=0;i<count;++i)if(path[i]==value)return true;return false;}
static bool add_signed_offset(uptr base,i64 offset,uptr& out){
    if(offset>=0){uptr mag=(uptr)offset;if(~(uptr)0-base<mag)return false;out=base+mag;return true;}
    u64 mag=(u64)(-(offset+1))+1ULL;if(base<(uptr)mag)return false;out=base-(uptr)mag;return true;
}
static bool add_pointer_chain(int moduleIndex,uptr slot,uptr rootOffset,const i64* rev,u8 revCount,i64 currentOffset,usize maxChains){
    if(g_pointerChainCount>=maxChains||g_pointerChainCount>=MAX_POINTER_CHAINS){g_pointerChainsTruncated=true;return false;}
    if(!reserve_pointer_chains(g_pointerChainCount+1)){g_pointerChainsTruncated=true;return false;}
    PointerChain_& c=g_pointerChains[g_pointerChainCount++];memzero(&c,sizeof(c));strcopy(c.module,sizeof(c.module),g_modules[moduleIndex].name);c.rootOffset=rootOffset;c.depth=(u8)(revCount+1);c.offsets[0]=currentOffset;for(u8 i=0;i<revCount;++i)c.offsets[i+1]=rev[revCount-1-i];(void)slot;return true;
}
static void pointer_dfs(uptr current,u8 maxDepth,uptr maxOffset,uptr maxNegativeOffset,usize maxChains,i64* rev,u8 revCount,uptr* path,u8 pathCount){
    if(g_pointerCancelRequested||g_pointerSearchBudgetHit||revCount>=maxDepth||g_pointerChainCount>=maxChains)return;
    uptr low=current>=maxOffset?current-maxOffset:0;
    uptr high=(~(uptr)0-current<maxNegativeOffset)?~(uptr)0:current+maxNegativeOffset;
    usize begin=lower_pointer_value(low),end=upper_pointer_value(high);
    if(begin>=end)return;

    // Visit candidates from the smallest absolute offset outward. Real object
    // layouts overwhelmingly use small field offsets; this reaches useful
    // chains earlier and avoids spending the whole budget on distant values.
    usize right=lower_pointer_value(current);
    if(right<begin)right=begin;if(right>end)right=end;
    usize left=right;
    usize candidates=0;
    while((left>begin||right<end)&&!g_pointerCancelRequested&&!g_pointerSearchBudgetHit){
        if(++candidates>g_pointerBranchCap){g_pointerChainsTruncated=true;break;}
        if(++g_pointerSearchSteps>g_pointerSearchBudget){g_pointerSearchBudgetHit=1;g_pointerChainsTruncated=true;break;}

        bool takeLeft=false;
        if(left>begin&&right<end){
            uptr lv=g_pointerIndex[left-1].value,rv=g_pointerIndex[right].value;
            uptr ld=current>=lv?current-lv:lv-current;
            uptr rd=current>=rv?current-rv:rv-current;
            takeLeft=ld<=rd;
        }else takeLeft=left>begin;
        usize i=takeLeft?--left:right++;
        const PointerEntry& e=g_pointerIndex[i];i64 offset=0;
        if(e.value<=current){uptr diff=current-e.value;if(diff>maxOffset||diff>0x7FFFFFFFFFFFFFFFULL)continue;offset=(i64)diff;}
        else{uptr diff=e.value-current;if(diff>maxNegativeOffset||diff>0x7FFFFFFFFFFFFFFFULL)continue;offset=-(i64)diff;}
        uptr slot=e.address;if(path_has(path,pathCount,slot))continue;int mi=module_for_address(slot);
        if(mi>=0){if(!add_pointer_chain(mi,slot,slot-g_modules[mi].base,rev,revCount,offset,maxChains))return;continue;}
        if(revCount+1<maxDepth){rev[revCount]=offset;path[pathCount]=slot;pointer_dfs(slot,maxDepth,maxOffset,maxNegativeOffset,maxChains,rev,(u8)(revCount+1),path,(u8)(pathCount+1));if(g_pointerChainCount>=maxChains||g_pointerSearchBudgetHit)return;}
    }
}
static u64 abs_i64_u64(i64 v){return v<0?(u64)(-(v+1))+1ULL:(u64)v;}
static bool layer_less(const PointerLayerNode_& a,const PointerLayerNode_& b){return a.address<b.address||(a.address==b.address&&a.score<b.score);}
static void layer_swap(PointerLayerNode_& a,PointerLayerNode_& b){PointerLayerNode_ t=a;a=b;b=t;}
static void layer_sift(PointerLayerNode_* a,usize start,usize count){usize root=start;for(;;){usize child=root*2+1;if(child>=count)return;usize best=root;if(layer_less(a[best],a[child]))best=child;if(child+1<count&&layer_less(a[best],a[child+1]))best=child+1;if(best==root)return;layer_swap(a[root],a[best]);root=best;}}
static void layer_sort(PointerLayerNode_* a,usize count){if(count<2)return;for(usize i=count/2;i>0;--i)layer_sift(a,i-1,count);for(usize end=count;end>1;--end){layer_swap(a[0],a[end-1]);usize root=0,n=end-1;for(;;){usize child=root*2+1;if(child>=n)break;usize best=root;if(layer_less(a[best],a[child]))best=child;if(child+1<n&&layer_less(a[best],a[child+1]))best=child+1;if(best==root)break;layer_swap(a[root],a[best]);root=best;}}}
static usize layer_lower(PointerLayerNode_* a,usize count,uptr address){usize lo=0,hi=count;while(lo<hi){usize mid=lo+(hi-lo)/2;if(a[mid].address<address)lo=mid+1;else hi=mid;}return lo;}
static usize layer_upper(PointerLayerNode_* a,usize count,uptr address){usize lo=0,hi=count;while(lo<hi){usize mid=lo+(hi-lo)/2;if(a[mid].address<=address)lo=mid+1;else hi=mid;}return lo;}
static usize layer_dedup(PointerLayerNode_* a,usize count){if(!count)return 0;layer_sort(a,count);usize out=0;for(usize i=0;i<count;++i){if(out&&a[i].address==a[out-1].address)continue;if(out!=i)a[out]=a[i];++out;}return out;}
static bool range_overlaps_any_module(uptr begin,uptr end){for(usize i=0;i<g_moduleCount;++i){uptr mb=g_modules[i].base;uptr me=mb+(uptr)g_modules[i].size;if(me<mb)me=~(uptr)0;if(begin<me&&end>mb)return true;}return false;}
static bool layer_pick_target(PointerLayerNode_* nodes,usize count,uptr value,uptr maxOffset,uptr maxNegative,usize& idx,i64& offset){
    if(!count)return false;uptr low=value>=maxNegative?value-maxNegative:0;uptr high=(~(uptr)0-value<maxOffset)?~(uptr)0:value+maxOffset;usize b=layer_lower(nodes,count,low),e=layer_upper(nodes,count,high);if(b>=e)return false;
    usize r=layer_lower(nodes,count,value);if(r<b)r=b;if(r>e)r=e;bool have=false;usize best=0;u64 bestDist=~0ULL;
    if(r<e){u64 d=nodes[r].address>=value?(u64)(nodes[r].address-value):(u64)(value-nodes[r].address);best=r;bestDist=d;have=true;}
    if(r>b){usize l=r-1;u64 d=nodes[l].address>=value?(u64)(nodes[l].address-value):(u64)(value-nodes[l].address);if(!have||d<=bestDist){best=l;bestDist=d;have=true;}}
    if(!have)return false;uptr target=nodes[best].address;if(target>=value){uptr d=target-value;if(d>maxOffset||d>0x7FFFFFFFFFFFFFFFULL)return false;offset=(i64)d;}else{uptr d=value-target;if(d>maxNegative||d>0x7FFFFFFFFFFFFFFFULL)return false;offset=-(i64)d;}idx=best;return true;
}
static bool add_layer_chain(int moduleIndex,uptr slot,i64 firstOffset,const PointerLayerNode_& tail,usize maxChains){
    if(g_pointerChainCount>=maxChains||g_pointerChainCount>=MAX_POINTER_CHAINS){g_pointerChainsTruncated=true;return false;}if(tail.depth+1>MAX_POINTER_DEPTH)return true;if(!reserve_pointer_chains(g_pointerChainCount+1)){g_pointerChainsTruncated=true;return false;}
    PointerChain_& c=g_pointerChains[g_pointerChainCount++];memzero(&c,sizeof(c));strcopy(c.module,sizeof(c.module),g_modules[moduleIndex].name);c.rootOffset=slot-g_modules[moduleIndex].base;c.depth=(u8)(tail.depth+1);c.offsets[0]=firstOffset;for(u8 i=0;i<tail.depth;++i)c.offsets[i+1]=tail.offsets[i];return true;
}
static bool pointer_layered_search_once(uptr target,u8 maxDepth,uptr maxOffset,uptr maxNegative,usize maxChains,usize alignment,usize parentCap){
    if(!g_process||!maxDepth)return false;if(!collect_pointer_target_ranges())return false;if(!(alignment==1||alignment==2||alignment==4||alignment==8))alignment=(usize)g_pointerSize;
    SIZE_T nodeBytes=(SIZE_T)MAX_POINTER_LAYER_NODES*sizeof(PointerLayerNode_);PointerLayerNode_* current=(PointerLayerNode_*)HeapAlloc(g_heap,0,nodeBytes);PointerLayerNode_* next=(PointerLayerNode_*)HeapAlloc(g_heap,0,nodeBytes);u8* buf=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!current||!next||!buf){if(current)HeapFree(g_heap,0,current);if(next)HeapFree(g_heap,0,next);if(buf)HeapFree(g_heap,0,buf);return false;}
    memzero(&current[0],sizeof(PointerLayerNode_));current[0].address=target;current[0].depth=0;usize currentCount=1;bool ok=true;g_pointerLayerTruncated=0;g_pointerLayerSlots=0;g_pointerLayerMatches=0;g_pointerLayerFrontier=1;g_pointerLayerDepth=0;g_pointerLayerMaxDepth=maxDepth;
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);uptr min=(uptr)si.lpMinimumApplicationAddress,max=(uptr)si.lpMaximumApplicationAddress;
    for(u8 level=0;level<maxDepth&&!g_pointerCancelRequested&&g_pointerChainCount<maxChains;++level){
        currentCount=layer_dedup(current,currentCount);for(usize i=0;i<currentCount;++i)current[i].parentsSeen=0;g_pointerLayerDepth=(u64)(level+1);g_pointerLayerFrontier=currentCount;usize nextCount=0;uptr cur=min;
        while(cur<max&&!g_pointerCancelRequested){MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx((HANDLE)g_process,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;uptr base=(uptr)mbi.BaseAddress,end=base+(uptr)mbi.RegionSize;if(end<=cur)break;bool allowed=mbi.State==MEM_COMMIT&&readable(mbi.Protect);if(allowed&&!writable(mbi.Protect)&&!range_overlaps_any_module(base,end))allowed=false;
            if(allowed){for(uptr p=base;p<end&&!g_pointerCancelRequested;){usize primary=(usize)((end-p)>SCAN_CHUNK?SCAN_CHUNK:(end-p));usize extra=(p+primary<end)?(usize)(g_pointerSize-1):0;usize toRead=primary+extra;if(p+toRead>end)toRead=(usize)(end-p);SIZE_T got=0;ReadProcessMemory((HANDLE)g_process,(LPCVOID)p,buf,toRead,&got);if(got>=g_pointerSize){usize startOff=0;usize rem=(usize)(p%alignment);if(rem)startOff=alignment-rem;for(usize off=startOff;off<primary&&off+g_pointerSize<=(usize)got&&!g_pointerCancelRequested;off+=alignment){uptr value=0;if(g_pointerSize==4){u32 v=0;memcopy(&v,buf+off,4);value=(uptr)v;}else{u64 v=0;memcopy(&v,buf+off,8);value=(uptr)v;}++g_pointerLayerSlots;usize ti=0;i64 delta=0;if(!layer_pick_target(current,currentCount,value,maxOffset,maxNegative,ti,delta))continue;PointerLayerNode_& tail=current[ti];if(tail.parentsSeen>=parentCap)continue;++tail.parentsSeen;++g_pointerLayerMatches;uptr slot=p+off;int mi=module_for_address(slot);if(mi>=0){if(!add_layer_chain(mi,slot,delta,tail,maxChains)){ok=false;break;}continue;}if(level+1>=maxDepth)continue;if(nextCount>=MAX_POINTER_LAYER_NODES){g_pointerLayerTruncated=1;continue;}PointerLayerNode_& nn=next[nextCount++];memzero(&nn,sizeof(nn));nn.address=slot;nn.depth=(u8)(tail.depth+1);nn.offsets[0]=delta;for(u8 j=0;j<tail.depth;++j)nn.offsets[j+1]=tail.offsets[j];nn.score=tail.score+abs_i64_u64(delta);}}
                    p+=primary;if(g_pointerChainCount>=maxChains)break;}}
            cur=end;if(g_pointerChainCount>=maxChains)break;}
        if(!ok||g_pointerCancelRequested||g_pointerChainCount)break;if(!nextCount)break;nextCount=layer_dedup(next,nextCount);PointerLayerNode_* tmp=current;current=next;next=tmp;currentCount=nextCount;
    }
    HeapFree(g_heap,0,buf);HeapFree(g_heap,0,current);HeapFree(g_heap,0,next);return ok&&!g_pointerCancelRequested;
}
static bool pointer_layered_search(uptr target,u8 maxDepth,uptr maxOffset,uptr maxNegative,usize maxChains,usize alignment,usize parentCap){
    g_pointerChainCount=0;g_pointerChainsTruncated=false;g_pointerLayerMatches=0;return pointer_layered_search_once(target,maxDepth,maxOffset,maxNegative,maxChains,alignment,parentCap);
}

static void append_signed_hex_offset(char* b,usize cap,usize& n,i64 offset){
    if(offset<0){append_str(b,cap,n," -> -");u64 mag=(u64)(-(offset+1))+1ULL;append_hex(b,cap,n,(uptr)mag);}else{append_str(b,cap,n," -> +");append_hex(b,cap,n,(uptr)offset);}
}
static void print_pointer_chain(usize i){
    if(i>=g_pointerChainCount)return;PointerChain_& c=g_pointerChains[i];char b[768];usize n=0;append_str(b,sizeof(b),n,"P#");append_u64_dec(b,sizeof(b),n,i);append_str(b,sizeof(b),n,"  ");append_str(b,sizeof(b),n,c.module);append_str(b,sizeof(b),n,"+");append_hex(b,sizeof(b),n,c.rootOffset);for(u8 j=0;j<c.depth;++j)append_signed_hex_offset(b,sizeof(b),n,c.offsets[j]);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);
}
static bool read_target_pointer(uptr address,uptr& value){SIZE_T got=0;if(g_pointerSize==4){u32 v=0;if(!ReadProcessMemory((HANDLE)g_process,(LPCVOID)address,&v,4,&got)||got!=4)return false;value=(uptr)v;return true;}u64 v=0;if(!ReadProcessMemory((HANDLE)g_process,(LPCVOID)address,&v,8,&got)||got!=8)return false;value=(uptr)v;return true;}
static bool resolve_pointer_chain(const PointerChain_& c,uptr& resolved){
    int mi=module_by_name(c.module);if(mi<0)return false;uptr addr=g_modules[mi].base+c.rootOffset;
    for(u8 i=0;i<c.depth;++i){uptr pv=0;if(!read_target_pointer(addr,pv))return false;if(!add_signed_offset(pv,c.offsets[i],addr))return false;}
    resolved=addr;return true;
}
static bool parse_onoff(const char* s,bool& value){if(!s)return false;if(strieq(s,"on")||streq(s,"1")||strieq(s,"true")||strieq(s,"yes")){value=true;return true;}if(strieq(s,"off")||streq(s,"0")||strieq(s,"false")||strieq(s,"no")){value=false;return true;}return false;}
static void print_pointer_settings(){
    char b[520];usize n=0;append_str(b,sizeof(b),n,"Pointer settings: alignment=");
    if(g_pointerAlignment==0)append_str(b,sizeof(b),n,"natural");else if(g_pointerAlignment==1)append_str(b,sizeof(b),n,"byte");else append_u64_dec(b,sizeof(b),n,g_pointerAlignment);
    append_str(b,sizeof(b),n," | writable=");append_str(b,sizeof(b),n,g_pointerWritableOnly?"on":"off");
    append_str(b,sizeof(b),n," | private=");append_str(b,sizeof(b),n,g_pointerPrivateOnly?"on":"off");
    append_str(b,sizeof(b),n," | branch=");append_u64_dec(b,sizeof(b),n,g_pointerBranchCap);
    append_str(b,sizeof(b),n," | root=");append_str(b,sizeof(b),n,g_pointerRootModule[0]?g_pointerRootModule:"any module");append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);
}
static void cmd_pointer_settings(const char* key,const char* value){
    if(!key){print_pointer_settings();return;}if(!value){println("Usage: pointer-settings <alignment|writable|private|branch|root> <value>");return;}
    if(strieq(key,"alignment")){
        if(strieq(value,"natural")||strieq(value,"aligned"))g_pointerAlignment=0;
        else if(strieq(value,"byte")||streq(value,"1")||strieq(value,"unaligned"))g_pointerAlignment=1;
        else{u64 x=0;if(!parse_u64(value,x)||(x!=2&&x!=4&&x!=8)){println("Alignment must be natural, byte, 2, 4 or 8.");return;}g_pointerAlignment=(usize)x;}
    }else if(strieq(key,"writable")){bool v=false;if(!parse_onoff(value,v)){println("Writable must be on/off.");return;}g_pointerWritableOnly=v;
    }else if(strieq(key,"private")){bool v=false;if(!parse_onoff(value,v)){println("Private must be on/off.");return;}g_pointerPrivateOnly=v;
    }else if(strieq(key,"branch")||strieq(key,"branching")){u64 x=0;if(!parse_u64(value,x)||x<1||x>65536){println("Branch cap must be 1..65536.");return;}g_pointerBranchCap=(usize)x;
    }else if(strieq(key,"root")){if(strieq(value,"any")||streq(value,"*"))g_pointerRootModule[0]=0;else strcopy(g_pointerRootModule,sizeof(g_pointerRootModule),value);
    }else{println("Unknown pointer setting.");return;}
    clear_pointer_index();println("Pointer settings updated. Existing chains were kept.");print_pointer_settings();
}

static void cmd_pointer_scan(const char* targetStr,const char* depthStr,const char* offsetStr,const char* chainsStr,const char* negativeStr){
    if(!g_process){println("Attach to a process first.");return;}uptr target=0;if(!parse_target_address(targetStr,target)){println("Invalid target. Use #result or address.");return;}
    u64 depth=3,maxOffset=0x1000,maxNegativeOffset=0,maxChains=MAX_POINTER_CHAINS;
    if(depthStr&&!parse_u64(depthStr,depth)){println("Invalid depth.");return;}if(offsetStr&&!parse_u64(offsetStr,maxOffset)){println("Invalid max_offset.");return;}if(chainsStr&&!parse_u64(chainsStr,maxChains)){println("Invalid max_chains.");return;}if(negativeStr&&!parse_u64(negativeStr,maxNegativeOffset)){println("Invalid max_negative_offset.");return;}
    if(depth<1||depth>MAX_POINTER_DEPTH||maxOffset>0x1000000ULL||maxNegativeOffset>0x1000000ULL||maxChains<1||maxChains>MAX_POINTER_CHAINS){println("Limits: depth 1..8, offsets <= 0x1000000, max_chains <= 10000.");return;}
    if(!refresh_modules())return;BOOL wow=0;if(IsWow64Process((HANDLE)g_process,&wow))g_pointerSize=wow?4:8;clear_pointer_chains();g_chainPointerSize=g_pointerSize;if(!build_pointer_index())return;
    i64 rev[MAX_POINTER_DEPTH]={};uptr path[MAX_POINTER_DEPTH+1]={};path[0]=target;pointer_dfs(target,(u8)depth,(uptr)maxOffset,(uptr)maxNegativeOffset,(usize)maxChains,rev,0,path,1);
    char b[320];usize n=0;append_str(b,sizeof(b),n,"Pointer scan found ");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n," chain(s), pointer width ");append_u64_dec(b,sizeof(b),n,(u64)g_pointerSize*8);append_str(b,sizeof(b),n,"-bit, max negative offset ");append_hex(b,sizeof(b),n,(uptr)maxNegativeOffset);if(g_pointerChainsTruncated)append_str(b,sizeof(b),n," [TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);usize preview=g_pointerChainCount<20?g_pointerChainCount:20;for(usize i=0;i<preview;++i)print_pointer_chain(i);
}
static void cmd_pointer_results(const char* limitStr){usize limit=50;if(limitStr){u64 x=0;if(!parse_u64(limitStr,x)){println("Invalid limit.");return;}limit=(usize)x;}if(limit>g_pointerChainCount)limit=g_pointerChainCount;for(usize i=0;i<limit;++i)print_pointer_chain(i);char b[128];usize n=0;append_str(b,sizeof(b),n,"Total pointer chains: ");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);}
static void cmd_pointer_resolve(const char* idxStr){if(!g_process){println("Attach to a process first.");return;}if(g_chainPointerSize&&g_chainPointerSize!=g_pointerSize){println("Stored chains use a different pointer width than the attached target.");return;}u64 x=0;if(!parse_u64(idxStr,x)||x>=g_pointerChainCount){println("Invalid pointer chain index.");return;}if(!refresh_modules())return;uptr resolved=0;print_pointer_chain((usize)x);if(resolve_pointer_chain(g_pointerChains[x],resolved)){char b[128];usize n=0;append_str(b,sizeof(b),n,"Resolved address: ");append_hex(b,sizeof(b),n,resolved);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}else println("Chain could not be resolved in the current process.");}
static void cmd_pointer_rescan(const char* targetStr){if(!g_process){println("Attach to a process first.");return;}if(!g_pointerChainCount){println("No stored pointer chains.");return;}if(g_chainPointerSize&&g_chainPointerSize!=g_pointerSize){println("Stored chains use a different pointer width than the attached target.");return;}uptr target=0;if(!parse_target_address(targetStr,target)){println("Invalid target.");return;}if(!refresh_modules())return;usize before=g_pointerChainCount,out=0;for(usize i=0;i<before;++i){uptr resolved=0;if(resolve_pointer_chain(g_pointerChains[i],resolved)&&resolved==target){if(out!=i)g_pointerChains[out]=g_pointerChains[i];++out;}}g_pointerChainCount=out;char b[180];usize n=0;append_str(b,sizeof(b),n,"Pointer rescan: ");append_u64_dec(b,sizeof(b),n,before);append_str(b,sizeof(b),n," -> ");append_u64_dec(b,sizeof(b),n,out);append_str(b,sizeof(b),n," chain(s).\r\n");flush_buf(b,n);}
static bool file_write_all(HANDLE h,const void* data,usize size){const u8* p=(const u8*)data;while(size){DWORD chunk=size>0x7FFFFFFFULL?0x7FFFFFFFUL:(DWORD)size;DWORD wrote=0;if(!WriteFile(h,p,chunk,&wrote,nullptr)||wrote==0)return false;p+=wrote;size-=wrote;}return true;}
static bool file_read_exact(HANDLE h,void* data,usize size){u8* p=(u8*)data;while(size){DWORD chunk=size>0x7FFFFFFFULL?0x7FFFFFFFUL:(DWORD)size;DWORD got=0;if(!ReadFile(h,p,chunk,&got,nullptr)||got==0)return false;p+=got;size-=got;}return true;}

static u32 scan_type_code(ValueType t){switch(t){case ValueType::Byte:return 1;case ValueType::Int16:return 2;case ValueType::Int32:return 3;case ValueType::Int64:return 4;case ValueType::Float:return 5;case ValueType::Double:return 6;default:return 0;}}
static ValueType scan_type_from_code(u32 c){switch(c){case 1:return ValueType::Byte;case 2:return ValueType::Int16;case 3:return ValueType::Int32;case 4:return ValueType::Int64;case 5:return ValueType::Float;case 6:return ValueType::Double;default:return ValueType::Invalid;}}
static void cmd_scan_save(const char* path){
    if(!path||!*path){println("Usage: scan-save <file.cwscan>");return;}
    if(g_type==ValueType::Invalid){println("No active value scan to save.");return;}
    if(g_snapshotActive){println("Unknown snapshot/refinement is not persisted. Keep using Next Scan until results are materialized.");return;}
    HANDLE h=CreateFileA(path,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if((uptr)h==INVALID_HANDLE_BITS){print_last_error("Scan-session open failed");return;}
    const char magic[8]={'C','W','S','C','A','N','0','1'};u32 ver=1,flags=g_type==ValueType::Mixed?1u:0u;
    u32 primary=scan_type_code(g_type==ValueType::Mixed?ValueType::Int32:g_type),alignment=g_alignmentByte?1u:0u,writableOnly=0,privateOnly=0;
    u64 sourcePid=g_pid,minAddress=0,maxAddress=~(u64)0,toleranceBits=0,resultCount=g_resultCount;
    bool ok=primary!=0&&file_write_all(h,magic,8)&&file_write_all(h,&ver,4)&&file_write_all(h,&flags,4)&&file_write_all(h,&primary,4)&&file_write_all(h,&alignment,4)&&file_write_all(h,&writableOnly,4)&&file_write_all(h,&privateOnly,4)&&file_write_all(h,&sourcePid,8)&&file_write_all(h,&minAddress,8)&&file_write_all(h,&maxAddress,8)&&file_write_all(h,&toleranceBits,8)&&file_write_all(h,&resultCount,8);
    for(usize i=0;ok&&i<g_resultCount;++i){ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[i].type:g_type;u32 tc=scan_type_code(t),reserved=0;u64 address=g_results[i].address,previous=0;memcopy(&previous,g_results[i].previous,8);if(!tc){ok=false;break;}ok=file_write_all(h,&address,8)&&file_write_all(h,&previous,8)&&file_write_all(h,&tc,4)&&file_write_all(h,&reserved,4);}
    CloseHandle(h);if(!ok){println("Scan-session save failed while writing file.");return;}
    char b[320];usize n=0;append_str(b,sizeof(b),n,"Saved ");append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n," scan result(s) to '");append_str(b,sizeof(b),n,path);append_str(b,sizeof(b),n,"' with source PID ");append_u64_dec(b,sizeof(b),n,g_pid);append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);
}
static void cmd_scan_load(const char* path,bool force){
    if(!path||!*path){println("Usage: scan-load <file.cwscan> [force]");return;}
    if(!g_process){println("Attach to the process that owns these addresses before loading the scan session.");return;}
    HANDLE h=CreateFileA(path,GENERIC_READ,1,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if((uptr)h==INVALID_HANDLE_BITS){print_last_error("Scan-session open failed");return;}
    char magic[8]={};u32 ver=0,flags=0,primary=0,alignment=0,writableOnly=0,privateOnly=0;u64 sourcePid=0,minAddress=0,maxAddress=0,toleranceBits=0,resultCount=0;
    bool ok=file_read_exact(h,magic,8)&&file_read_exact(h,&ver,4)&&file_read_exact(h,&flags,4)&&file_read_exact(h,&primary,4)&&file_read_exact(h,&alignment,4)&&file_read_exact(h,&writableOnly,4)&&file_read_exact(h,&privateOnly,4)&&file_read_exact(h,&sourcePid,8)&&file_read_exact(h,&minAddress,8)&&file_read_exact(h,&maxAddress,8)&&file_read_exact(h,&toleranceBits,8)&&file_read_exact(h,&resultCount,8);
    const char expect[8]={'C','W','S','C','A','N','0','1'};const char legacy[8]={'M','C','E','S','C','A','N','1'};ValueType primaryType=scan_type_from_code(primary);
    if(!ok||(!memequal(magic,expect,8)&&!memequal(magic,legacy,8))||ver!=1||(flags&~1u)||alignment>1||writableOnly>1||privateOnly>1||primaryType==ValueType::Invalid||resultCount>MAX_RESULTS||minAddress>maxAddress){CloseHandle(h);println("Invalid/unsupported scan-session file.");return;}
    if(toleranceBits!=0){CloseHandle(h);println("Portable build cannot restore scan sessions with non-zero float tolerance.");return;}
    if(!force&&sourcePid&&sourcePid!=(u64)g_pid){CloseHandle(h);char b[360];usize n=0;append_str(b,sizeof(b),n,"Refusing scan session: saved PID ");append_u64_dec(b,sizeof(b),n,sourcePid);append_str(b,sizeof(b),n," != attached PID ");append_u64_dec(b,sizeof(b),n,g_pid);append_str(b,sizeof(b),n,". Use scan-load <file> force only for intentional stale-address testing.\r\n");flush_buf(b,n);return;}
    clear_results();clear_snapshot();if(resultCount&&!reserve_results((usize)resultCount)){CloseHandle(h);println("Out of memory loading scan session.");return;}
    bool mixed=(flags&1)!=0;for(u64 i=0;ok&&i<resultCount;++i){u64 address=0,previous=0;u32 tc=0,reserved=0;ok=file_read_exact(h,&address,8)&&file_read_exact(h,&previous,8)&&file_read_exact(h,&tc,4)&&file_read_exact(h,&reserved,4);ValueType t=scan_type_from_code(tc);if(!ok||reserved||t==ValueType::Invalid||(!mixed&&t!=primaryType)){ok=false;break;}Result& r=g_results[g_resultCount++];r.address=(uptr)address;memzero(r.previous,8);memcopy(r.previous,&previous,8);r.type=(u8)t;}
    if(ok){u8 extra=0;DWORD got=0;if(!ReadFile(h,&extra,1,&got,nullptr)||got!=0)ok=false;}CloseHandle(h);
    if(!ok){clear_results();g_type=ValueType::Invalid;println("Scan-session load failed: malformed/truncated result list.");return;}
    g_type=mixed?ValueType::Mixed:primaryType;g_alignmentByte=alignment!=0;refresh_result_type_counts();
    char b[420];usize n=0;append_str(b,sizeof(b),n,"Loaded ");append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n," scan result(s) from '");append_str(b,sizeof(b),n,path);append_str(b,sizeof(b),n,"'");if(force&&sourcePid&&sourcePid!=(u64)g_pid)append_str(b,sizeof(b),n," [FORCED PID MISMATCH]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);
}

static bool load_aob_session_file(const char* path,bool restoreResults,bool verbose){
    if(!path||!*path)return false;if(restoreResults&&!g_process){println("Attach to a process first so module-relative AOB matches can be rebased.");return false;}
    HANDLE h=CreateFileA(path,GENERIC_READ,1,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS){print_last_error("AOB session open failed");return false;}
    const char expect[8]={'C','W','A','O','B','0','0','1'};const char legacy[8]={'M','C','E','A','O','B','0','1'};char magic[8]={};u32 ver=0,scope=0,pc=0;u16 moduleLen=0;u64 resultCount=0;
    bool ok=file_read_exact(h,magic,8)&&file_read_exact(h,&ver,4)&&file_read_exact(h,&scope,4)&&file_read_exact(h,&pc,4)&&file_read_exact(h,&moduleLen,2)&&file_read_exact(h,&resultCount,8);
    if(!ok||(!memequal(magic,expect,8)&&!memequal(magic,legacy,8))||ver!=1||scope>3||pc==0||pc>MAX_AOB_PATTERN||moduleLen>=sizeof(g_aobModule)||resultCount>MAX_AOB_RESULTS){CloseHandle(h);println("Invalid/unsupported AOB session file.");return false;}
    u8* pattern=(u8*)HeapAlloc(g_heap,0,(usize)pc*2);if(!pattern){CloseHandle(h);println("Out of memory.");return false;}u8* values=pattern;u8* masks=pattern+pc;
    for(u32 i=0;ok&&i<pc;++i){ok=file_read_exact(h,&values[i],1)&&file_read_exact(h,&masks[i],1);if(ok&&masks[i]!=0&&masks[i]!=0x0F&&masks[i]!=0xF0&&masks[i]!=0xFF)ok=false;}
    char moduleName[256]={};if(ok&&moduleLen){ok=file_read_exact(h,moduleName,moduleLen);moduleName[moduleLen]=0;}if(ok&&(scope>=2)&&moduleLen==0)ok=false;
    if(!ok){HeapFree(g_heap,0,pattern);CloseHandle(h);println("AOB session file is truncated or malformed.");return false;}
    if(restoreResults){g_aobCount=0;if(!refresh_modules()){HeapFree(g_heap,0,pattern);CloseHandle(h);return false;}}
    usize skipped=0,absolute=0;
    for(u64 i=0;ok&&i<resultCount;++i){u8 kind=0;u16 nameLen=0;u64 value=0;ok=file_read_exact(h,&kind,1)&&file_read_exact(h,&nameLen,2)&&file_read_exact(h,&value,8);if(!ok||kind>1||nameLen>=256||(kind==0&&nameLen!=0)){ok=false;break;}char resultModule[256]={};if(nameLen){ok=file_read_exact(h,resultModule,nameLen);if(!ok)break;resultModule[nameLen]=0;}if(kind==1&&nameLen==0){ok=false;break;}
        if(restoreResults){if(kind==0){if(!add_aob((uptr)value)){ok=false;break;}++absolute;}else{int mi=module_by_name(resultModule);if(mi<0||value>=g_modules[mi].size||g_modules[mi].base>~(uptr)0-(uptr)value){++skipped;}else if(!add_aob(g_modules[mi].base+(uptr)value)){ok=false;break;}}}
    }
    if(ok){u8 extra=0;DWORD got=0;if(!ReadFile(h,&extra,1,&got,nullptr)||got!=0)ok=false;}CloseHandle(h);
    if(!ok){HeapFree(g_heap,0,pattern);if(restoreResults)g_aobCount=0;println("AOB session load failed: malformed/truncated file.");return false;}
    g_aobPatternCount=pc;for(usize i=0;i<pc;++i){g_aobPatternValues[i]=values[i];g_aobPatternMasks[i]=masks[i];}g_aobScope=scope;strcopy(g_aobModule,sizeof(g_aobModule),moduleName);HeapFree(g_heap,0,pattern);
    if(verbose){char b[420];usize n=0;append_str(b,sizeof(b),n,"Loaded AOB session '");append_str(b,sizeof(b),n,path);append_str(b,sizeof(b),n,"': ");append_u64_dec(b,sizeof(b),n,g_aobCount);append_str(b,sizeof(b),n," match(es)");if(skipped){append_str(b,sizeof(b),n,", ");append_u64_dec(b,sizeof(b),n,skipped);append_str(b,sizeof(b),n," module-relative skipped");}if(absolute){append_str(b,sizeof(b),n,", ");append_u64_dec(b,sizeof(b),n,absolute);append_str(b,sizeof(b),n," absolute may be stale");}append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);}return true;
}
static void cmd_aob_save(const char* path){
    if(!path||!*path){println("Usage: aob-save <file.cwaob>");return;}if(!g_process){println("Attach to the process that produced the AOB results before saving.");return;}if(!g_aobPatternCount){println("No active AOB signature to save.");return;}if(!refresh_modules())return;
    HANDLE h=CreateFileA(path,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS){print_last_error("AOB save open failed");return;}const char magic[8]={'C','W','A','O','B','0','0','1'};u32 ver=1,scope=g_aobScope,pc=(u32)g_aobPatternCount;usize ml=cstrlen(g_aobModule);u16 moduleLen=(u16)ml;u64 rc=(u64)g_aobCount;
    bool ok=file_write_all(h,magic,8)&&file_write_all(h,&ver,4)&&file_write_all(h,&scope,4)&&file_write_all(h,&pc,4)&&file_write_all(h,&moduleLen,2)&&file_write_all(h,&rc,8);for(usize i=0;ok&&i<g_aobPatternCount;++i)ok=file_write_all(h,&g_aobPatternValues[i],1)&&file_write_all(h,&g_aobPatternMasks[i],1);if(ok&&moduleLen)ok=file_write_all(h,g_aobModule,moduleLen);
    for(usize i=0;ok&&i<g_aobCount;++i){u8 kind=0;u16 nameLen=0;u64 value=(u64)g_aobResults[i];const char* name=nullptr;for(usize m=0;m<g_moduleCount;++m){uptr base=g_modules[m].base;if(g_aobResults[i]>=base&&g_aobResults[i]-base<g_modules[m].size){kind=1;name=g_modules[m].name;nameLen=(u16)cstrlen(name);value=(u64)(g_aobResults[i]-base);break;}}ok=file_write_all(h,&kind,1)&&file_write_all(h,&nameLen,2)&&file_write_all(h,&value,8);if(ok&&nameLen)ok=file_write_all(h,name,nameLen);}
    CloseHandle(h);if(!ok){println("AOB save failed while writing file.");return;}char b[360];usize n=0;append_str(b,sizeof(b),n,"Saved AOB session '");append_str(b,sizeof(b),n,path);append_str(b,sizeof(b),n,"': ");append_u64_dec(b,sizeof(b),n,g_aobCount);append_str(b,sizeof(b),n," match(es).\r\n");flush_buf(b,n);
}
static void cmd_aob_load(const char* path){if(!path||!*path){println("Usage: aob-load <file.cwaob>");return;}load_aob_session_file(path,true,true);}
static void cmd_aob_rerun(const char* path){if(!path||!*path){println("Usage: aob-rerun <file.cwaob>");return;}if(!g_process){println("Attach to a process first.");return;}if(!load_aob_session_file(path,false,false))return;bool execOnly=(g_aobScope==1||g_aobScope==3);const char* module=(g_aobScope>=2)?g_aobModule:nullptr;char savedModule[256];strcopy(savedModule,sizeof(savedModule),g_aobModule);u32 savedScope=g_aobScope;usize savedCount=g_aobPatternCount;u8* pattern=(u8*)HeapAlloc(g_heap,0,savedCount*2);if(!pattern){println("Out of memory.");return;}u8* values=pattern;u8* masks=pattern+savedCount;for(usize i=0;i<savedCount;++i){values[i]=g_aobPatternValues[i];masks[i]=g_aobPatternMasks[i];}bool ok=scan_aob_pattern(values,masks,savedCount,execOnly,module,true);HeapFree(g_heap,0,pattern);if(ok){g_aobScope=savedScope;strcopy(g_aobModule,sizeof(g_aobModule),savedModule);}}

static bool resolve_signed_relative(uptr instruction,usize size,i64 displacement,uptr& target){if(instruction>~(uptr)0-(uptr)size)return false;uptr next=instruction+(uptr)size;if(displacement>=0){u64 amount=(u64)displacement;if(amount>(u64)(~(uptr)0-next))return false;target=next+(uptr)amount;return true;}u64 mag=(u64)(-(displacement+1))+1;if(mag>(u64)next)return false;target=next-(uptr)mag;return true;}
static void append_module_for_address(char* b,usize cap,usize& n,uptr address){for(usize m=0;m<g_moduleCount;++m){uptr base=g_modules[m].base;if(address>=base&&address-base<g_modules[m].size){append_str(b,cap,n,"  ");append_str(b,cap,n,g_modules[m].name);append_str(b,cap,n,"+");append_hex(b,cap,n,address-base);break;}}}
static void cmd_aob_decode(const char* targetStr){
    if(!g_process){println("Attach to a process first.");return;}uptr instruction=0;if(!parse_aob_target(targetStr,instruction)){println("Invalid AOB target. Use #0, #1, ... or an address.");return;}u8 bytes[16]={};SIZE_T got=0;if(!ReadProcessMemory((HANDLE)g_process,(LPCVOID)instruction,bytes,sizeof(bytes),&got)||got<2){print_last_error("Could not read instruction bytes");return;}BOOL wow=0;IsWow64Process((HANDLE)g_process,&wow);bool x64=!wow;const char* kind=nullptr;usize size=0,dispOff=0,dispSize=0;bool indirect=false;uptr target=0;i64 disp=0;
    if(bytes[0]==0xE8&&got>=5){kind="CALL rel32";size=5;dispOff=1;dispSize=4;i32 d=0;memcopy(&d,bytes+1,4);disp=d;}
    else if(bytes[0]==0xE9&&got>=5){kind="JMP rel32";size=5;dispOff=1;dispSize=4;i32 d=0;memcopy(&d,bytes+1,4);disp=d;}
    else if(bytes[0]==0xEB&&got>=2){kind="JMP rel8";size=2;dispOff=1;dispSize=1;i8 d=0;memcopy(&d,bytes+1,1);disp=d;}
    else if(bytes[0]>=0x70&&bytes[0]<=0x7F&&got>=2){kind="Jcc rel8";size=2;dispOff=1;dispSize=1;i8 d=0;memcopy(&d,bytes+1,1);disp=d;}
    else if(bytes[0]==0x0F&&got>=6&&bytes[1]>=0x80&&bytes[1]<=0x8F){kind="Jcc rel32";size=6;dispOff=2;dispSize=4;i32 d=0;memcopy(&d,bytes+2,4);disp=d;}
    else if(x64&&bytes[0]==0xFF&&got>=6&&(bytes[1]==0x15||bytes[1]==0x25)){kind=bytes[1]==0x15?"CALL [RIP+disp32]":"JMP [RIP+disp32]";size=6;dispOff=2;dispSize=4;indirect=true;i32 d=0;memcopy(&d,bytes+2,4);disp=d;}
    else if(x64){usize pre=(bytes[0]>=0x40&&bytes[0]<=0x4F)?1:0;if(got>=pre+6){u8 op=bytes[pre],modrm=bytes[pre+1];bool common=op==0x8B||op==0x89||op==0x8D||op==0x39||op==0x3B||op==0x85;if(common&&(modrm&0xC7)==0x05){kind="RIP-relative memory";size=pre+6;dispOff=pre+2;dispSize=4;i32 d=0;memcopy(&d,bytes+dispOff,4);disp=d;}}}
    if(!kind){println("No supported relative instruction form recognized.");return;}if(!resolve_signed_relative(instruction,size,disp,target)){println("Relative target overflow/underflow.");return;}refresh_modules();char b[520];usize n=0;append_str(b,sizeof(b),n,kind);append_str(b,sizeof(b),n," @ ");append_hex(b,sizeof(b),n,instruction);append_str(b,sizeof(b),n," | size=");append_u64_dec(b,sizeof(b),n,size);append_str(b,sizeof(b),n," | disp@+");append_hex(b,sizeof(b),n,dispOff);append_str(b,sizeof(b),n,indirect?" | slot=":" | target=");append_hex(b,sizeof(b),n,target);append_module_for_address(b,sizeof(b),n,target);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);(void)dispSize;
    if(indirect){u64 raw=0;SIZE_T r=0;usize ps=wow?4:8;if(ReadProcessMemory((HANDLE)g_process,(LPCVOID)target,&raw,ps,&r)&&r==ps){uptr destination=ps==4?(uptr)(u32)raw:(uptr)raw;char c[360];usize cn=0;append_str(c,sizeof(c),cn,"Indirect destination: ");append_hex(c,sizeof(c),cn,destination);append_module_for_address(c,sizeof(c),cn,destination);append_str(c,sizeof(c),cn,"\r\n");flush_buf(c,cn);}else println("Pointer slot could not be dereferenced.");}
}
static void cmd_pointer_save(const char* path){
    if(!path||!*path){println("Usage: pointer-save <file.cwchain>");return;}if(!g_pointerChainCount){println("No stored pointer chains to save.");return;}if(g_chainPointerSize!=4&&g_chainPointerSize!=8){println("Stored chains have invalid pointer-width metadata.");return;}
    HANDLE h=CreateFileA(path,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS){print_last_error("Pointer save open failed");return;}
    const char magic[8]={'C','W','C','H','A','I','N','1'};u32 ver=2;u32 ps=g_chainPointerSize;u64 count=(u64)g_pointerChainCount;bool ok=file_write_all(h,magic,8)&&file_write_all(h,&ver,4)&&file_write_all(h,&ps,4)&&file_write_all(h,&count,8);
    for(usize i=0;ok&&i<g_pointerChainCount;++i){PointerChain_& c=g_pointerChains[i];usize ml=cstrlen(c.module);if(ml==0||ml>255||c.depth==0||c.depth>MAX_POINTER_DEPTH){ok=false;break;}u16 mlen=(u16)ml;u64 root=(u64)c.rootOffset;u32 depth=(u32)c.depth;ok=file_write_all(h,&mlen,2)&&file_write_all(h,c.module,ml)&&file_write_all(h,&root,8)&&file_write_all(h,&depth,4);for(u32 j=0;ok&&j<depth;++j){u64 raw=0;memcopy(&raw,&c.offsets[j],8);ok=file_write_all(h,&raw,8);}}
    CloseHandle(h);if(!ok){println("Pointer save failed while writing file.");return;}char b[300];usize n=0;append_str(b,sizeof(b),n,"Saved ");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n," pointer chain(s) to '");append_str(b,sizeof(b),n,path);append_str(b,sizeof(b),n,"' (format v2).\r\n");flush_buf(b,n);
}
static void cmd_pointer_load(const char* path){
    if(!path||!*path){println("Usage: pointer-load <file.cwchain>");return;}HANDLE h=CreateFileA(path,GENERIC_READ,1,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS){print_last_error("Pointer load open failed");return;}
    char magic[8]={};u32 ver=0,ps=0;u64 count=0;bool ok=file_read_exact(h,magic,8)&&file_read_exact(h,&ver,4)&&file_read_exact(h,&ps,4)&&file_read_exact(h,&count,8);const char expect[8]={'C','W','C','H','A','I','N','1'};const char legacy[8]={'M','C','E','P','T','R','0','1'};
    if(!ok||(!memequal(magic,expect,8)&&!memequal(magic,legacy,8))||(ver!=1&&ver!=2)||(ps!=4&&ps!=8)||count>MAX_POINTER_CHAINS){CloseHandle(h);println("Invalid or unsupported pointer-chain file.");return;}if(g_process&&ps!=g_pointerSize){CloseHandle(h);println("Pointer file width does not match attached target.");return;}
    clear_pointer_index();g_pointerChainCount=0;if(!reserve_pointer_chains((usize)count)){CloseHandle(h);println("Could not allocate pointer chains.");return;}
    for(u64 i=0;i<count;++i){u16 mlen=0;u64 root=0;u32 depth=0;if(!file_read_exact(h,&mlen,2)||mlen==0||mlen>=256){ok=false;break;}PointerChain_ c{};if(!file_read_exact(h,c.module,mlen)){ok=false;break;}c.module[mlen]=0;if(!file_read_exact(h,&root,8)||!file_read_exact(h,&depth,4)||depth==0||depth>MAX_POINTER_DEPTH){ok=false;break;}c.rootOffset=(uptr)root;c.depth=(u8)depth;
        for(u32 j=0;j<depth;++j){u64 raw=0;if(!file_read_exact(h,&raw,8)){ok=false;break;}if(ver==1){if(raw>0x7FFFFFFFFFFFFFFFULL){ok=false;break;}c.offsets[j]=(i64)raw;}else memcopy(&c.offsets[j],&raw,8);}if(!ok)break;g_pointerChains[g_pointerChainCount++]=c;}
    if(ok){u8 extra=0;DWORD got=0;if(!ReadFile(h,&extra,1,&got,nullptr))ok=false;else if(got!=0)ok=false;}CloseHandle(h);if(!ok){g_pointerChainCount=0;g_chainPointerSize=0;println("Pointer load failed: truncated or malformed file.");return;}
    g_chainPointerSize=(u8)ps;g_pointerChainsTruncated=false;char b[340];usize n=0;append_str(b,sizeof(b),n,"Loaded ");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n," pointer chain(s) from '");append_str(b,sizeof(b),n,path);append_str(b,sizeof(b),n,"' (");append_u64_dec(b,sizeof(b),n,(u64)g_chainPointerSize*8);append_str(b,sizeof(b),n,"-bit, format v");append_u64_dec(b,sizeof(b),n,ver);append_str(b,sizeof(b),n,").\r\n");flush_buf(b,n);
}
static bool ptr_addr_less(const PointerEntry& a,const PointerEntry& b){return a.address<b.address||(a.address==b.address&&a.value<b.value);}
static void sort_entries_by_address(PointerEntry* a,usize count){if(!a||count<2)return;auto sift=[&](usize start,usize n){usize root=start;for(;;){usize child=root*2+1;if(child>=n)return;usize best=root;if(ptr_addr_less(a[best],a[child]))best=child;if(child+1<n&&ptr_addr_less(a[best],a[child+1]))best=child+1;if(best==root)return;PointerEntry t=a[root];a[root]=a[best];a[best]=t;root=best;}};for(usize i=count/2;i>0;--i)sift(i-1,count);for(usize end=count;end>1;--end){PointerEntry t=a[0];a[0]=a[end-1];a[end-1]=t;sift(0,end-1);}}
static bool map_pointer_at(PointerMap_& m,uptr address,uptr& value){if(!m.entriesByAddress){sort_entries_by_address(m.entries,m.entryCount);m.entriesByAddress=true;}usize lo=0,hi=m.entryCount;while(lo<hi){usize mid=lo+(hi-lo)/2;if(m.entries[mid].address<address)lo=mid+1;else hi=mid;}if(lo>=m.entryCount||m.entries[lo].address!=address)return false;value=m.entries[lo].value;return true;}
static int map_module_by_name(PointerMap_& m,const char* name){for(usize i=0;i<m.moduleCount;++i)if(strieq(m.modules[i].name,name))return (int)i;return -1;}
static bool resolve_chain_map(PointerMap_& m,const PointerChain_& c,uptr& resolved){int mi=map_module_by_name(m,c.module);if(mi<0||c.rootOffset>=m.modules[mi].size)return false;uptr addr=m.modules[mi].base+c.rootOffset;for(u8 i=0;i<c.depth;++i){uptr pv=0;if(!map_pointer_at(m,addr,pv))return false;if(!add_signed_offset(pv,c.offsets[i],addr))return false;}resolved=addr;return true;}
static void free_pointer_maps(){for(usize i=0;i<g_pointerMapCount;++i){if(g_pointerMaps[i].entries)HeapFree(g_heap,0,g_pointerMaps[i].entries);memzero(&g_pointerMaps[i],sizeof(g_pointerMaps[i]));}g_pointerMapCount=0;}
static void cmd_pmap_clear(){free_pointer_maps();println("Loaded pointer maps cleared.");}
static void cmd_pmap_capture(const char* path,const char* targetStr,const char* maxStr){if(!g_process){println("Attach to a process first.");return;}if(!path||!*path||!targetStr){println("Usage: pmap-capture <file.cwmap> <#result|address> [max_entries]");return;}uptr target=0;if(!parse_target_address(targetStr,target)){println("Invalid target.");return;}u64 limit=MAX_POINTER_ENTRIES;if(maxStr&&!parse_u64(maxStr,limit)){println("Invalid max_entries.");return;}if(limit<1||limit>MAX_POINTER_ENTRIES){println("Portable build limit: max_entries 1..8000000.");return;}if(!refresh_modules())return;BOOL wow=0;if(IsWow64Process((HANDLE)g_process,&wow))g_pointerSize=wow?4:8;usize oldLimit=g_pointerIndexLimit;g_pointerIndexLimit=(usize)limit;bool built=build_pointer_index();g_pointerIndexLimit=oldLimit;if(!built&&g_pointerCount==0){println("Pointer-map capture found no pointer entries.");return;}HANDLE h=CreateFileA(path,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS){print_last_error("Pointer-map open failed");return;}const char magic[8]={'C','W','M','A','P','0','0','1'};u32 ver=1,ps=g_pointerSize,mc=(u32)g_moduleCount,flags=g_pointerIndexTruncated?0u:1u;u64 tgt=(u64)target,ec=(u64)g_pointerCount;bool ok=file_write_all(h,magic,8)&&file_write_all(h,&ver,4)&&file_write_all(h,&ps,4)&&file_write_all(h,&tgt,8)&&file_write_all(h,&mc,4)&&file_write_all(h,&ec,8)&&file_write_all(h,&flags,4);for(usize i=0;ok&&i<g_moduleCount;++i){usize nl=cstrlen(g_modules[i].name);if(nl==0||nl>255){ok=false;break;}u64 base=(u64)g_modules[i].base,size=g_modules[i].size;u16 nlen=(u16)nl;ok=file_write_all(h,&base,8)&&file_write_all(h,&size,8)&&file_write_all(h,&nlen,2)&&file_write_all(h,g_modules[i].name,nl);}for(usize i=0;ok&&i<g_pointerCount;++i){u64 v=(u64)g_pointerIndex[i].value,a=(u64)g_pointerIndex[i].address;ok=file_write_all(h,&v,8)&&file_write_all(h,&a,8);}CloseHandle(h);if(!ok){println("Pointer-map save failed while writing file.");return;}char b[360];usize n=0;append_str(b,sizeof(b),n,"Saved pointer map '");append_str(b,sizeof(b),n,path);append_str(b,sizeof(b),n,"': ");append_u64_dec(b,sizeof(b),n,g_pointerCount);append_str(b,sizeof(b),n," entries, target ");append_hex(b,sizeof(b),n,target);if(g_pointerIndexTruncated)append_str(b,sizeof(b),n," [PARTIAL/TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);clear_pointer_index();}
static void free_pointer_map_one(PointerMap_& m){if(m.entries)HeapFree(g_heap,0,m.entries);memzero(&m,sizeof(m));}
static bool load_pointer_map_file(const char* path,PointerMap_& m,u8 expectedWidth,bool quiet){
    memzero(&m,sizeof(m));
    if(!path||!*path){if(!quiet)println("Pointer-map path is required.");return false;}
    HANDLE h=CreateFileA(path,GENERIC_READ,1,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if((uptr)h==INVALID_HANDLE_BITS){if(!quiet)print_last_error("Pointer-map open failed");return false;}
    char magic[8]={};u32 ver=0,ps=0,mc=0,flags=0;u64 target=0,ec=0;
    bool ok=file_read_exact(h,magic,8)&&file_read_exact(h,&ver,4)&&file_read_exact(h,&ps,4)&&file_read_exact(h,&target,8)&&file_read_exact(h,&mc,4)&&file_read_exact(h,&ec,8)&&file_read_exact(h,&flags,4);
    const char expect[8]={'C','W','M','A','P','0','0','1'};const char legacy[8]={'M','C','E','P','M','A','P','1'};
    if(!ok||(!memequal(magic,expect,8)&&!memequal(magic,legacy,8))||ver!=1||(ps!=4&&ps!=8)||mc>MAX_MODULES||ec>MAX_POINTER_ENTRIES||(expectedWidth&&ps!=expectedWidth)){
        CloseHandle(h);if(!quiet)println(expectedWidth&&ps!=expectedWidth?"Pointer-map width mismatch.":"Invalid/unsupported pointer map or exceeds portable limits.");return false;
    }
    m.pointerSize=(u8)ps;m.complete=(flags&1)!=0;m.target=(uptr)target;m.moduleCount=mc;strcopy(m.path,sizeof(m.path),path);
    for(usize i=0;ok&&i<m.moduleCount;++i){u64 base=0,size=0;u16 nl=0;if(!file_read_exact(h,&base,8)||!file_read_exact(h,&size,8)||!file_read_exact(h,&nl,2)||nl==0||nl>=256){ok=false;break;}m.modules[i].base=(uptr)base;m.modules[i].size=size;if(!file_read_exact(h,m.modules[i].name,nl)){ok=false;break;}m.modules[i].name[nl]=0;}
    m.entryCount=(usize)ec;if(ok&&m.entryCount){m.entries=(PointerEntry*)HeapAlloc(g_heap,0,m.entryCount*sizeof(PointerEntry));if(!m.entries)ok=false;}
    for(usize i=0;ok&&i<m.entryCount;++i){u64 v=0,a=0;if(!file_read_exact(h,&v,8)||!file_read_exact(h,&a,8)){ok=false;break;}m.entries[i]={(uptr)v,(uptr)a};}
    if(ok){u8 extra=0;DWORD got=0;if(!ReadFile(h,&extra,1,&got,nullptr)||got!=0)ok=false;}
    CloseHandle(h);
    if(!ok){free_pointer_map_one(m);if(!quiet)println("Pointer-map load failed: malformed/truncated file.");return false;}
    return true;
}
static void cmd_pmap_load(const char* path){
    if(!path||!*path){println("Usage: pmap-load <file.cwmap>");return;}
    if(g_pointerMapCount>=MAX_POINTER_MAPS){println("Portable build supports at most 4 loaded pointer maps.");return;}
    PointerMap_& m=g_pointerMaps[g_pointerMapCount];u8 expected=g_pointerMapCount?g_pointerMaps[0].pointerSize:0;
    if(!load_pointer_map_file(path,m,expected,false))return;
    ++g_pointerMapCount;char b[360];usize n=0;append_str(b,sizeof(b),n,"Loaded pointer map #");append_u64_dec(b,sizeof(b),n,g_pointerMapCount-1);append_str(b,sizeof(b),n," '");append_str(b,sizeof(b),n,path);append_str(b,sizeof(b),n,"': ");append_u64_dec(b,sizeof(b),n,m.entryCount);append_str(b,sizeof(b),n," entries, target ");append_hex(b,sizeof(b),n,m.target);if(!m.complete)append_str(b,sizeof(b),n," [PARTIAL]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);
}
static void cmd_pmap_list(){if(!g_pointerMapCount){println("No pointer maps loaded.");return;}for(usize i=0;i<g_pointerMapCount;++i){PointerMap_& m=g_pointerMaps[i];char b[480];usize n=0;append_str(b,sizeof(b),n,"M#");append_u64_dec(b,sizeof(b),n,i);append_str(b,sizeof(b),n,"  ");append_str(b,sizeof(b),n,m.path);append_str(b,sizeof(b),n," | ");append_u64_dec(b,sizeof(b),n,(u64)m.pointerSize*8);append_str(b,sizeof(b),n,"-bit | entries ");append_u64_dec(b,sizeof(b),n,m.entryCount);append_str(b,sizeof(b),n," | target ");append_hex(b,sizeof(b),n,m.target);append_str(b,sizeof(b),n,m.complete?" | complete\r\n":" | PARTIAL\r\n");flush_buf(b,n);}}
static void cmd_pmap_compare(const char* depthStr,const char* offsetStr,const char* chainsStr,const char* negativeStr){
    if(!g_pointerMapCount){println("Load at least one pointer map first.");return;}u64 depth=3,maxOffset=0x1000,maxNegativeOffset=0,maxChains=MAX_POINTER_CHAINS;
    if(depthStr&&!parse_u64(depthStr,depth)){println("Invalid depth.");return;}if(offsetStr&&!parse_u64(offsetStr,maxOffset)){println("Invalid max_offset.");return;}if(chainsStr&&!parse_u64(chainsStr,maxChains)){println("Invalid max_chains.");return;}if(negativeStr&&!parse_u64(negativeStr,maxNegativeOffset)){println("Invalid max_negative_offset.");return;}
    if(depth<1||depth>MAX_POINTER_DEPTH||maxOffset>0x1000000ULL||maxNegativeOffset>0x1000000ULL||maxChains<1||maxChains>MAX_POINTER_CHAINS){println("Limits: depth 1..8, offsets <= 0x1000000, max_chains <= 10000.");return;}
    PointerMap_& first=g_pointerMaps[0];if(first.entriesByAddress){println("First loaded map was reordered by a previous operation; reload maps before comparing again.");return;}
    PointerEntry* savedIndex=g_pointerIndex;usize savedCount=g_pointerCount,savedCap=g_pointerCap;bool savedTrunc=g_pointerIndexTruncated;u8 savedPS=g_pointerSize;usize savedMC=g_moduleCount;ModuleInfo_* savedModules=(ModuleInfo_*)HeapAlloc(g_heap,0,MAX_MODULES*sizeof(ModuleInfo_));if(!savedModules){println("Out of memory.");return;}for(usize i=0;i<savedMC;++i)savedModules[i]=g_modules[i];
    g_pointerIndex=first.entries;g_pointerCount=first.entryCount;g_pointerCap=first.entryCount;g_pointerIndexTruncated=false;g_pointerSize=first.pointerSize;g_moduleCount=first.moduleCount;for(usize i=0;i<g_moduleCount;++i)g_modules[i]=first.modules[i];clear_pointer_chains();g_chainPointerSize=first.pointerSize;
    i64 rev[MAX_POINTER_DEPTH]={};uptr path[MAX_POINTER_DEPTH+1]={};path[0]=first.target;pointer_dfs(first.target,(u8)depth,(uptr)maxOffset,(uptr)maxNegativeOffset,(usize)maxChains,rev,0,path,1);usize initial=g_pointerChainCount;
    g_pointerIndex=savedIndex;g_pointerCount=savedCount;g_pointerCap=savedCap;g_pointerIndexTruncated=savedTrunc;g_pointerSize=savedPS;g_moduleCount=savedMC;for(usize i=0;i<savedMC;++i)g_modules[i]=savedModules[i];HeapFree(g_heap,0,savedModules);
    for(usize mi=1;mi<g_pointerMapCount&&g_pointerChainCount;++mi){PointerMap_& m=g_pointerMaps[mi];usize out=0;for(usize ci=0;ci<g_pointerChainCount;++ci){uptr resolved=0;if(resolve_chain_map(m,g_pointerChains[ci],resolved)&&resolved==m.target){if(out!=ci)g_pointerChains[out]=g_pointerChains[ci];++out;}}g_pointerChainCount=out;}
    char b[380];usize n=0;append_str(b,sizeof(b),n,"Pointer-map compare: ");append_u64_dec(b,sizeof(b),n,initial);append_str(b,sizeof(b),n," initial -> ");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n," common chain(s) across ");append_u64_dec(b,sizeof(b),n,g_pointerMapCount);append_str(b,sizeof(b),n," map(s), max negative offset ");append_hex(b,sizeof(b),n,(uptr)maxNegativeOffset);if(g_pointerChainsTruncated)append_str(b,sizeof(b),n," [INITIAL SEARCH TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);usize preview=g_pointerChainCount<20?g_pointerChainCount:20;for(usize i=0;i<preview;++i)print_pointer_chain(i);
}
static void cmd_pmap_compare_files(char** paths,int count){
    if(count<2){println("Usage: pmap-compare-files <file1> <file2> [file3 ...]");return;}
    if(count>16){println("At most 16 pointer-map files may be compared at once.");return;}
    const u8 depth=3;const uptr maxOffset=0x1000;const uptr maxNegativeOffset=0;const usize maxChains=MAX_POINTER_CHAINS;
    PointerMap_* first=(PointerMap_*)HeapAlloc(g_heap,0,sizeof(PointerMap_));if(!first){println("Out of memory.");return;}memzero(first,sizeof(PointerMap_));
    if(!load_pointer_map_file(paths[0],*first,0,false)){HeapFree(g_heap,0,first);return;}u8 width=first->pointerSize;usize peak=first->entryCount;usize partial=first->complete?0:1;
    if(first->entriesByAddress){free_pointer_map_one(*first);HeapFree(g_heap,0,first);println("First map is not value-sorted.");return;}
    PointerEntry* savedIndex=g_pointerIndex;usize savedCount=g_pointerCount,savedCap=g_pointerCap;bool savedTrunc=g_pointerIndexTruncated;u8 savedPS=g_pointerSize;usize savedMC=g_moduleCount;
    ModuleInfo_* savedModules=(ModuleInfo_*)HeapAlloc(g_heap,0,MAX_MODULES*sizeof(ModuleInfo_));if(!savedModules){free_pointer_map_one(*first);HeapFree(g_heap,0,first);println("Out of memory.");return;}for(usize i=0;i<savedMC;++i)savedModules[i]=g_modules[i];
    g_pointerIndex=first->entries;g_pointerCount=first->entryCount;g_pointerCap=first->entryCount;g_pointerIndexTruncated=false;g_pointerSize=first->pointerSize;g_moduleCount=first->moduleCount;for(usize i=0;i<g_moduleCount;++i)g_modules[i]=first->modules[i];clear_pointer_chains();g_chainPointerSize=width;
    i64 rev[MAX_POINTER_DEPTH]={};uptr path[MAX_POINTER_DEPTH+1]={};path[0]=first->target;pointer_dfs(first->target,depth,maxOffset,maxNegativeOffset,maxChains,rev,0,path,1);usize initial=g_pointerChainCount;
    g_pointerIndex=savedIndex;g_pointerCount=savedCount;g_pointerCap=savedCap;g_pointerIndexTruncated=savedTrunc;g_pointerSize=savedPS;g_moduleCount=savedMC;for(usize i=0;i<savedMC;++i)g_modules[i]=savedModules[i];HeapFree(g_heap,0,savedModules);free_pointer_map_one(*first);HeapFree(g_heap,0,first);
    PointerMap_* current=(PointerMap_*)HeapAlloc(g_heap,0,sizeof(PointerMap_));if(!current){clear_pointer_chains();println("Out of memory.");return;}
    for(int pi=1;pi<count;++pi){memzero(current,sizeof(PointerMap_));if(!load_pointer_map_file(paths[pi],*current,width,false)){free_pointer_map_one(*current);HeapFree(g_heap,0,current);clear_pointer_chains();return;}if(current->entryCount>peak)peak=current->entryCount;if(!current->complete)++partial;if(g_pointerChainCount){usize out=0;for(usize ci=0;ci<g_pointerChainCount;++ci){uptr resolved=0;if(resolve_chain_map(*current,g_pointerChains[ci],resolved)&&resolved==current->target){if(out!=ci)g_pointerChains[out]=g_pointerChains[ci];++out;}}g_pointerChainCount=out;}free_pointer_map_one(*current);}
    HeapFree(g_heap,0,current);
    char b[520];usize n=0;append_str(b,sizeof(b),n,"Streaming pointer-map compare: ");append_u64_dec(b,sizeof(b),n,initial);append_str(b,sizeof(b),n," initial -> ");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n," common chain(s) across ");append_u64_dec(b,sizeof(b),n,count);append_str(b,sizeof(b),n," map(s) | peak loaded entries ");append_u64_dec(b,sizeof(b),n,peak);if(partial){append_str(b,sizeof(b),n," | WARNING partial maps: ");append_u64_dec(b,sizeof(b),n,partial);}if(g_pointerChainsTruncated)append_str(b,sizeof(b),n," | INITIAL SEARCH TRUNCATED");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);usize preview=g_pointerChainCount<20?g_pointerChainCount:20;for(usize i=0;i<preview;++i)print_pointer_chain(i);
}
static void cmd_pointer_clear(){clear_pointer_index();clear_pointer_chains();println("Pointer index and chains cleared.");}
static void clear_freezes(){ for(int i=0;i<MAX_FREEZES;++i)g_freezes[i].active=0; }
static void close_target(){ clear_freezes(); HANDLE old=(HANDLE)g_process; g_process=nullptr; if(old)CloseHandle(old); g_pid=0; clear_results(); clear_snapshot(); guided_reset(); clear_pointer_index(); g_moduleCount=0; g_type=ValueType::Invalid; }
static bool attach_pid(DWORD pid){
    close_target();
    HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION,0,pid);
    if(!h){print_last_error("OpenProcess failed");return false;}
    g_process=h; g_pid=pid; BOOL wow=0; if(IsWow64Process(h,&wow))g_pointerSize=wow?4:8; else g_pointerSize=8;
    char b[180];usize n=0;append_str(b,sizeof(b),n,"Attached to PID ");append_u64_dec(b,sizeof(b),n,pid);append_str(b,sizeof(b),n," (pointer width ");append_u64_dec(b,sizeof(b),n,(u64)g_pointerSize*8);append_str(b,sizeof(b),n,"-bit).\r\n");flush_buf(b,n);
    return true;
}
static void cmd_attach(const char* s){ u64 pid=0;if(!parse_u64(s,pid)||pid>0xFFFFFFFFULL){println("Invalid PID.");return;} attach_pid((DWORD)pid); }
static void cmd_attach_name(const char* name){
    if(!name||!*name){println("Process name is required.");return;}
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==(HANDLE)(uptr)-1){print_last_error("CreateToolhelp32Snapshot failed");return;}
    PROCESSENTRY32A_ e{}; e.dwSize=(DWORD)sizeof(e);
    bool found=false; DWORD pid=0;
    if(Process32First(snap,&e)){
        do{ if(strieq(e.szExeFile,name)){ found=true; pid=e.th32ProcessID; break; } }while(Process32Next(snap,&e));
    }
    CloseHandle(snap);
    if(!found){println("Process name not found.");return;}
    attach_pid(pid);
}
static void cmd_detach(){ if(!g_process){println("No process attached.");return;} close_target(); println("Detached."); }
static void cmd_clear(){ clear_results(); clear_snapshot(); guided_reset(); clear_aob(); g_type=ValueType::Invalid; println("Value scan/snapshot and AOB results cleared."); }

static usize scan_start_offset(uptr base,usize alignment){if(g_alignmentByte||alignment<=1)return 0;usize rem=(usize)(base%alignment);return rem?alignment-rem:0;}

static bool scan_exact(ValueType t,const u8* wanted){
    HANDLE proc=(HANDLE)g_process;if(!proc){println("Attach to a process first.");return false;}
    clear_results();clear_snapshot();g_type=t;u8 sz=type_size(t);usize step=g_alignmentByte?1:sz;
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);uptr cur=(uptr)si.lpMinimumApplicationAddress;uptr max=(uptr)si.lpMaximumApplicationAddress;
    u8* buf=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!buf){println("Out of memory.");return false;}
    usize regions=0;bool truncated=false;
    while(cur<max){
        MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx(proc,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;
        uptr base=(uptr)mbi.BaseAddress;uptr end=base+(uptr)mbi.RegionSize;if(end<=cur)break;
        if(mbi.State==MEM_COMMIT&&readable(mbi.Protect)){
            ++regions;uptr p=base;
            while(p<end){
                usize primary=(usize)((end-p)>SCAN_CHUNK?SCAN_CHUNK:(end-p));usize extra=(p+primary<end)?(usize)(sz-1):0;
                usize toRead=primary+extra;if(p+toRead>end)toRead=(usize)(end-p);SIZE_T got=0;
                if(ReadProcessMemory(proc,(LPCVOID)p,buf,toRead,&got)&&got>=sz){
                    usize startOff=scan_start_offset(p,sz);
                    for(usize off=startOff;off<primary&&off+sz<=(usize)got;off+=step){
                        if(memequal(buf+off,wanted,sz)&&!add_result(p+off,buf+off,sz,t)){truncated=true;break;}
                    }
                }
                if(truncated)break;p+=primary;
            }
        }
        if(truncated)break;cur=end;
    }
    HeapFree(g_heap,0,buf);
    char b[256];usize n=0;append_str(b,sizeof(b),n,"Scan complete. Found ");append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n," result(s) across ");append_u64_dec(b,sizeof(b),n,regions);append_str(b,sizeof(b),n," readable region(s)");if(truncated)append_str(b,sizeof(b),n," [TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);return true;
}

static bool scan_all_exact(const char* text){
    HANDLE proc=(HANDLE)g_process;if(!proc){println("Attach to a process first.");return false;}
    const ValueType types[6]={ValueType::Byte,ValueType::Int16,ValueType::Int32,ValueType::Int64,ValueType::Float,ValueType::Double};
    u8 wanted[6][8]{};bool enabled[6]{};usize enabledCount=0;
    for(usize i=0;i<6;++i){enabled[i]=encode_value(types[i],text,wanted[i]);if(enabled[i])++enabledCount;}
    if(!enabledCount){println("Value is not valid for any supported numeric type.");return false;}
    clear_results();clear_snapshot();g_type=ValueType::Mixed;
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);uptr cur=(uptr)si.lpMinimumApplicationAddress;uptr max=(uptr)si.lpMaximumApplicationAddress;
    u8* buf=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!buf){println("Out of memory.");return false;}
    usize regions=0;bool truncated=false;
    while(cur<max){
        MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx(proc,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;
        uptr base=(uptr)mbi.BaseAddress;uptr end=base+(uptr)mbi.RegionSize;if(end<=cur)break;
        if(mbi.State==MEM_COMMIT&&readable(mbi.Protect)){
            ++regions;uptr p=base;
            while(p<end){
                usize primary=(usize)((end-p)>SCAN_CHUNK?SCAN_CHUNK:(end-p));usize extra=(p+primary<end)?7:0;
                usize toRead=primary+extra;if(p+toRead>end)toRead=(usize)(end-p);SIZE_T got=0;
                if(ReadProcessMemory(proc,(LPCVOID)p,buf,toRead,&got)&&got>0){
                    for(usize ti=0;ti<6&&!truncated;++ti){
                        if(!enabled[ti])continue;ValueType t=types[ti];u8 sz=type_size(t);if(got<sz)continue;usize step=g_alignmentByte?1:sz;usize startOff=scan_start_offset(p,sz);
                        for(usize off=startOff;off<primary&&off+sz<=(usize)got;off+=step){
                            if(memequal(buf+off,wanted[ti],sz)&&!add_result(p+off,buf+off,sz,t)){truncated=true;break;}
                        }
                    }
                }
                if(truncated)break;p+=primary;
            }
        }
        if(truncated)break;cur=end;
    }
    HeapFree(g_heap,0,buf);
    char b[320];usize n=0;append_str(b,sizeof(b),n,"Mixed scan complete. ");append_u64_dec(b,sizeof(b),n,enabledCount);append_str(b,sizeof(b),n," compatible type(s), ");append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n," result(s) across ");append_u64_dec(b,sizeof(b),n,regions);append_str(b,sizeof(b),n," readable region(s)");if(truncated)append_str(b,sizeof(b),n," [TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);return true;
}


static bool scan_all_unknown(bool smart){
    HANDLE proc=(HANDLE)g_process;if(!proc){println("Attach to a process first.");return false;}
    clear_results();clear_snapshot();g_type=ValueType::Mixed;
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);uptr cur=(uptr)si.lpMinimumApplicationAddress,max=(uptr)si.lpMaximumApplicationAddress;
    u8* buf=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!buf){println("Out of memory.");return false;}
    usize regions=0;bool truncated=false;
    while(cur<max&&!truncated){
        MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx(proc,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;
        uptr base=(uptr)mbi.BaseAddress,end=base+(uptr)mbi.RegionSize;if(end<=cur)break;
        bool allowed=mbi.State==MEM_COMMIT&&readable(mbi.Protect);if(allowed&&smart&&(mbi.Type!=MEM_PRIVATE||!writable(mbi.Protect)))allowed=false;
        if(allowed){
            ++regions;uptr p=base;
            while(p<end){
                usize primary=(usize)((end-p)>SCAN_CHUNK?SCAN_CHUNK:(end-p));usize extra=(p+primary<end)?7:0;
                usize toRead=primary+extra;if(p+toRead>end)toRead=(usize)(end-p);SIZE_T got=0;
                ReadProcessMemory(proc,(LPCVOID)p,buf,toRead,&got);
                if(got>0){
                    usize candidateBytes=primary<(usize)got?primary:(usize)got;
                    if(!add_snapshot_block(p,buf,(usize)got,candidateBytes,ValueType::Mixed)){truncated=true;break;}
                }
                p+=primary;
            }
        }
        cur=end;
    }
    HeapFree(g_heap,0,buf);if(truncated){clear_snapshot();g_type=ValueType::Invalid;println("Unknown snapshot storage failed. Scan state cleared.");return false;}g_snapshotActive=g_snapshotCount>0;
    char b[440];usize n=0;append_str(b,sizeof(b),n,"Mixed unknown snapshot: ");append_u64_dec(b,sizeof(b),n,g_snapshotCount);append_str(b,sizeof(b),n," block(s), ");append_u64_dec(b,sizeof(b),n,g_snapshotBytes);append_str(b,sizeof(b),n," byte(s), ");append_u64_dec(b,sizeof(b),n,g_snapshotCandidates);append_str(b,sizeof(b),n," typed candidate(s) across ");append_u64_dec(b,sizeof(b),n,regions);append_str(b,sizeof(b),n," readable region(s) [TEMP DISK BACKING]. Change/refine the value, then run Next Scan.\r\n");flush_buf(b,n);
    return g_snapshotActive;
}

static bool scan_unknown(ValueType t,bool smart){
    HANDLE proc=(HANDLE)g_process;if(!proc){println("Attach to a process first.");return false;}
    clear_results();clear_snapshot();g_type=t;u8 sz=type_size(t);if(!sz)return false;
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);uptr cur=(uptr)si.lpMinimumApplicationAddress,max=(uptr)si.lpMaximumApplicationAddress;
    u8* buf=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!buf){println("Out of memory.");return false;}
    usize regions=0;bool truncated=false;
    while(cur<max&&!truncated){
        MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx(proc,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;
        uptr base=(uptr)mbi.BaseAddress,end=base+(uptr)mbi.RegionSize;if(end<=cur)break;
        bool allowed=mbi.State==MEM_COMMIT&&readable(mbi.Protect);if(allowed&&smart&&(mbi.Type!=MEM_PRIVATE||!writable(mbi.Protect)))allowed=false;
        if(allowed){
            ++regions;uptr p=base;
            while(p<end){
                usize primary=(usize)((end-p)>SCAN_CHUNK?SCAN_CHUNK:(end-p));usize extra=(p+primary<end)?(usize)(sz-1):0;
                usize toRead=primary+extra;if(p+toRead>end)toRead=(usize)(end-p);SIZE_T got=0;
                ReadProcessMemory(proc,(LPCVOID)p,buf,toRead,&got);
                if(got>0){usize candidateBytes=primary<(usize)got?primary:(usize)got;if(!add_snapshot_block(p,buf,(usize)got,candidateBytes,t)){truncated=true;break;}}
                p+=primary;
            }
        }
        cur=end;
    }
    HeapFree(g_heap,0,buf);if(truncated){clear_snapshot();g_type=ValueType::Invalid;println("Unknown snapshot storage failed. Scan state cleared.");return false;}g_snapshotActive=g_snapshotCount>0;
    char b[420];usize n=0;append_str(b,sizeof(b),n,"Unknown snapshot [");append_str(b,sizeof(b),n,type_name(t));append_str(b,sizeof(b),n,"]: ");append_u64_dec(b,sizeof(b),n,g_snapshotCandidates);append_str(b,sizeof(b),n," candidate(s), ");append_u64_dec(b,sizeof(b),n,g_snapshotBytes);append_str(b,sizeof(b),n," byte(s) across ");append_u64_dec(b,sizeof(b),n,regions);append_str(b,sizeof(b),n," readable region(s) [TEMP DISK BACKING]. Run Next Scan to refine.\r\n");flush_buf(b,n);return g_snapshotActive;
}

static int cmp_numeric(ValueType t,const u8* a,const u8* b){ switch(t){case ValueType::Byte:{u8 x=0,y=0;memcopy(&x,a,1);memcopy(&y,b,1);return x<y?-1:x>y?1:0;}case ValueType::Int16:{i16 x=0,y=0;memcopy(&x,a,2);memcopy(&y,b,2);return x<y?-1:x>y?1:0;}case ValueType::Int32:{i32 x=0,y=0;memcopy(&x,a,4);memcopy(&y,b,4);return x<y?-1:x>y?1:0;}case ValueType::Int64:{i64 x=0,y=0;memcopy(&x,a,8);memcopy(&y,b,8);return x<y?-1:x>y?1:0;}case ValueType::Float:{float x=0,y=0;memcopy(&x,a,4);memcopy(&y,b,4);return x<y?-1:x>y?1:0;}case ValueType::Double:{double x=0,y=0;memcopy(&x,a,8);memcopy(&y,b,8);return x<y?-1:x>y?1:0;}default:return 0;} }


static void next_scan_unknown_snapshot(NextMode mode,const char* wantedText,bool hasWanted){
    HANDLE proc=(HANDLE)g_process;if(!proc||!g_snapshotActive){println("No unknown snapshot is active.");return;}
    clear_results();
    const ValueType types[6]={ValueType::Byte,ValueType::Int16,ValueType::Int32,ValueType::Int64,ValueType::Float,ValueType::Double};
    usize bufferSize=SCAN_CHUNK+8;u8* buffers=(u8*)HeapAlloc(g_heap,0,bufferSize*2);if(!buffers){println("Out of memory.");return;}u8* previous=buffers;u8* current=buffers+bufferSize;
    usize survivors=0;bool failed=false;
    for(usize bi=0;bi<g_snapshotCount&&!failed;++bi){
        SnapshotBlock_& block=g_snapshotBlocks[bi];if(!block.size)continue;
        if(block.size>bufferSize||!snapshot_read_at(block.fileOffset,previous,block.size)){failed=true;break;}
        memcopy(current,previous,block.size);SIZE_T got=0;BOOL readOk=ReadProcessMemory(proc,(LPCVOID)block.base,current,block.size,&got);
        usize available=(usize)got;bool fullEqual=readOk&&available==block.size&&memequal(current,previous,block.size);
        u8* nextMasks[6]{};usize nextCounts[6]{};u8 nextModes[6]{};bool preserve[6]{};bool evaluate[6]{};
        for(int ti=0;ti<6;++ti){
            ValueType t=types[ti];if(g_type!=ValueType::Mixed&&g_type!=t)continue;if(!block.activeCounts[ti])continue;
            u8 wanted[8]{};bool wantedOk=!hasWanted||encode_value(t,wantedText,wanted);if(hasWanted&&!wantedOk)continue;
            if(fullEqual&&mode==NextMode::Unchanged){preserve[ti]=true;continue;}
            if(fullEqual&&(mode==NextMode::Changed||mode==NextMode::Increased||mode==NextMode::Decreased))continue;
            evaluate[ti]=true;usize mb=snapshot_mask_bytes(block.candidateCounts[ti]);if(mb){nextMasks[ti]=(u8*)HeapAlloc(g_heap,0,mb);if(!nextMasks[ti]){failed=true;break;}memzero(nextMasks[ti],mb);nextModes[ti]=SNAP_MASK_EXPLICIT;}
        }
        if(failed){for(int ti=0;ti<6;++ti)if(nextMasks[ti])HeapFree(g_heap,0,nextMasks[ti]);break;}
        for(int ti=0;ti<6;++ti){
            if(!evaluate[ti])continue;ValueType t=types[ti];u8 sz=type_size(t);if(available<sz)continue;
            u8 wanted[8]{};if(hasWanted&&!encode_value(t,wantedText,wanted))continue;
            usize step=g_alignmentByte?1:sz,start=scan_start_offset(block.base,sz),candidateBytes=block.candidateBytes<available?block.candidateBytes:available;
            for(usize off=start;off<candidateBytes&&off+sz<=available&&off+sz<=block.size;off+=step){
                usize index=(off-start)/step;if(!snapshot_mask_test(block,ti,index))continue;
                const u8* now=current+off;const u8* oldValue=previous+off;bool keep=false;int prevCmp=cmp_numeric(t,now,oldValue);
                switch(mode){
                    case NextMode::Exact:keep=hasWanted&&memequal(now,wanted,sz);break;
                    case NextMode::Changed:keep=!memequal(now,oldValue,sz);break;
                    case NextMode::Unchanged:keep=memequal(now,oldValue,sz);break;
                    case NextMode::Increased:keep=prevCmp>0;break;
                    case NextMode::Decreased:keep=prevCmp<0;break;
                    case NextMode::Bigger:keep=hasWanted&&cmp_numeric(t,now,wanted)>0;break;
                    case NextMode::Smaller:keep=hasWanted&&cmp_numeric(t,now,wanted)<0;break;
                }
                if(keep){snapshot_mask_set(nextMasks[ti],index);++nextCounts[ti];}
            }
        }
        for(int ti=0;ti<6;++ti){
            if(preserve[ti]){usize max=(usize)-1;if(block.activeCounts[ti]>max-survivors)survivors=max;else survivors+=block.activeCounts[ti];continue;}
            if(block.masks[ti]){HeapFree(g_heap,0,block.masks[ti]);block.masks[ti]=nullptr;}
            block.activeCounts[ti]=nextCounts[ti];
            if(!nextCounts[ti]){if(nextMasks[ti])HeapFree(g_heap,0,nextMasks[ti]);block.maskModes[ti]=SNAP_MASK_NONE;block.masks[ti]=nullptr;}
            else if(nextCounts[ti]==block.candidateCounts[ti]){if(nextMasks[ti])HeapFree(g_heap,0,nextMasks[ti]);block.maskModes[ti]=SNAP_MASK_ALL;block.masks[ti]=nullptr;}
            else{block.maskModes[ti]=nextModes[ti];block.masks[ti]=nextMasks[ti];nextMasks[ti]=nullptr;}
            usize max=(usize)-1;if(block.activeCounts[ti]>max-survivors)survivors=max;else survivors+=block.activeCounts[ti];
        }
        if(!fullEqual&&!snapshot_write_at(block.fileOffset,current,block.size)){failed=true;break;}
    }
    if(failed){HeapFree(g_heap,0,buffers);clear_results();clear_snapshot();g_type=ValueType::Invalid;println("Unknown refinement failed (memory or temporary snapshot I/O). Scan state cleared.");return;}
    refresh_snapshot_type_counts();survivors=g_snapshotCandidates;
    if(survivors>MAX_RESULTS){
        char b[380];usize n=0;append_str(b,sizeof(b),n,"Unknown refinement snapshot: ");append_u64_dec(b,sizeof(b),n,survivors);append_str(b,sizeof(b),n," candidate(s) remain. Continue with Next Scan; none were discarded by the 5,000,000 result cap [TEMP DISK BACKING].\r\n");flush_buf(b,n);HeapFree(g_heap,0,buffers);return;
    }
    if(survivors&&!reserve_results(survivors)){HeapFree(g_heap,0,buffers);println("Not enough memory to materialize refined results; snapshot was preserved.");return;}
    bool materializeOk=true;
    for(usize bi=0;bi<g_snapshotCount&&materializeOk;++bi){
        SnapshotBlock_& block=g_snapshotBlocks[bi];
        if(block.size>bufferSize||!snapshot_read_at(block.fileOffset,current,block.size)){materializeOk=false;break;}
        for(int ti=0;ti<6&&materializeOk;++ti){
            ValueType t=types[ti];if(g_type!=ValueType::Mixed&&g_type!=t)continue;if(!block.activeCounts[ti])continue;
            u8 sz=type_size(t);usize step=g_alignmentByte?1:sz,start=scan_start_offset(block.base,sz);
            if(block.maskModes[ti]==SNAP_MASK_ALL){
                for(usize index=0;index<block.candidateCounts[ti];++index){usize off=start+index*step;if(off>=block.candidateBytes||off+sz>block.size)break;if(!add_result(block.base+off,current+off,sz,t)){materializeOk=false;break;}}
            }else if(block.maskModes[ti]==SNAP_MASK_EXPLICIT&&block.masks[ti]){
                usize mb=snapshot_mask_bytes(block.candidateCounts[ti]);for(usize byteIndex=0;byteIndex<mb&&materializeOk;++byteIndex){u8 bits=block.masks[ti][byteIndex];if(!bits)continue;for(unsigned bit=0;bit<8;++bit){if(!(bits&(u8)(1u<<bit)))continue;usize index=byteIndex*8+bit;if(index>=block.candidateCounts[ti])break;usize off=start+index*step;if(off>=block.candidateBytes||off+sz>block.size)continue;if(!add_result(block.base+off,current+off,sz,t)){materializeOk=false;break;}}}
            }
        }
    }
    if(!materializeOk){HeapFree(g_heap,0,buffers);clear_results();println("Could not materialize refined results; snapshot was preserved.");return;}
    HeapFree(g_heap,0,buffers);clear_snapshot();
    char b[300];usize n=0;append_str(b,sizeof(b),n,"Unknown refinement materialized ");append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n," result(s) from the complete temporary snapshot.\r\n");flush_buf(b,n);
}

static void next_scan_text(NextMode mode,const char* wantedText,bool hasWanted){
    HANDLE proc=(HANDLE)g_process;if(!proc||g_type==ValueType::Invalid){println("Run a scan first.");return;}
    if(g_snapshotActive){next_scan_unknown_snapshot(mode,wantedText,hasWanted);return;}
    usize out=0;u8 current[8];u8 wanted[8];memzero(g_resultTypeCounts,sizeof(g_resultTypeCounts));
    for(usize i=0;i<g_resultCount;++i){
        ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[i].type:g_type;u8 sz=type_size(t);if(!sz)continue;
        if(hasWanted&&!encode_value(t,wantedText,wanted))continue;
        SIZE_T got=0;memzero(current,8);if(!ReadProcessMemory(proc,(LPCVOID)g_results[i].address,current,sz,&got)||got!=sz)continue;
        bool keep=false;int prevCmp=cmp_numeric(t,current,g_results[i].previous);
        switch(mode){case NextMode::Exact:keep=hasWanted&&memequal(current,wanted,sz);break;case NextMode::Changed:keep=!memequal(current,g_results[i].previous,sz);break;case NextMode::Unchanged:keep=memequal(current,g_results[i].previous,sz);break;case NextMode::Increased:keep=prevCmp>0;break;case NextMode::Decreased:keep=prevCmp<0;break;case NextMode::Bigger:keep=hasWanted&&cmp_numeric(t,current,wanted)>0;break;case NextMode::Smaller:keep=hasWanted&&cmp_numeric(t,current,wanted)<0;break;}
        if(keep){if(out!=i)g_results[out]=g_results[i];memcopy(g_results[out].previous,current,sz);g_results[out].type=(u8)t;int ti=value_type_index(t);if(ti>=0)++g_resultTypeCounts[ti];++out;}
    }
    g_resultCount=out;if(g_type==ValueType::Mixed)refresh_result_type_counts();g_rankingDirty=true;char b[128];usize n=0;append_str(b,sizeof(b),n,"Next scan: ");append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n," result(s).\r\n");flush_buf(b,n);
}

static bool parse_index(const char* s,usize& idx){if(!s)return false;if(*s=='#')++s;u64 v=0;if(!parse_u64(s,v))return false;if(v>=g_resultCount)return false;idx=(usize)v;return true;}

static void cmd_results(const char* countStr){
    if(g_snapshotActive){println("Unknown snapshot/refinement is active. Keep using Next Scan until candidates are <= 5,000,000; no candidates above that cap are discarded.");return;}
    usize limit=50;if(countStr){u64 x=0;if(parse_u64(countStr,x))limit=(usize)x;}if(limit>g_resultCount)limit=g_resultCount;HANDLE proc=(HANDLE)g_process;
    for(usize i=0;i<limit;++i){ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[i].type:g_type;u8 sz=type_size(t);u8 cur[8];memzero(cur,8);SIZE_T got=0;bool ok=proc&&sz&&ReadProcessMemory(proc,(LPCVOID)g_results[i].address,cur,sz,&got)&&got==sz;char b[320];usize n=0;append_char(b,sizeof(b),n,'#');append_u64_dec(b,sizeof(b),n,i);append_str(b,sizeof(b),n,"  ");append_hex(b,sizeof(b),n,g_results[i].address);append_str(b,sizeof(b),n,"  [");append_str(b,sizeof(b),n,type_name(t));append_str(b,sizeof(b),n,"]  ");if(ok)append_value(b,sizeof(b),n,t,cur);else append_str(b,sizeof(b),n,"<unreadable>");append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}
    if(g_resultCount>limit){char b[128];usize n=0;append_str(b,sizeof(b),n,"... ");append_u64_dec(b,sizeof(b),n,g_resultCount-limit);append_str(b,sizeof(b),n," more result(s).\r\n");flush_buf(b,n);}
}

static void cmd_inspect(const char* targetStr){if(!g_process){println("Attach to a process first.");return;}uptr address=0;if(!parse_target_address(targetStr,address)){println("Invalid target. Use #result or address.");return;}u8 raw[8]={};SIZE_T got=0;BOOL ok=ReadProcessMemory((HANDLE)g_process,(LPCVOID)address,raw,8,&got);if((!ok&&got==0)||got==0){print_last_error("Inspect read failed");return;}char b[1024];usize n=0;append_str(b,sizeof(b),n,"Address: ");append_hex(b,sizeof(b),n,address);append_str(b,sizeof(b),n," | bytes read: ");append_u64_dec(b,sizeof(b),n,got);append_str(b,sizeof(b),n,"\r\nRaw: ");static const char* hx="0123456789ABCDEF";for(usize i=0;i<got;++i){append_char(b,sizeof(b),n,hx[(raw[i]>>4)&0xF]);append_char(b,sizeof(b),n,hx[raw[i]&0xF]);if(i+1<got)append_char(b,sizeof(b),n,' ');}append_str(b,sizeof(b),n,"\r\n");
#define INS_LABEL(x) append_str(b,sizeof(b),n,x);append_str(b,sizeof(b),n," : ")
if(got>=1){INS_LABEL("uint8  ");append_u64_dec(b,sizeof(b),n,(u64)raw[0]);append_str(b,sizeof(b),n,"\r\n");i8 v=0;memcopy(&v,raw,1);INS_LABEL("int8   ");append_i64_dec(b,sizeof(b),n,(i64)v);append_str(b,sizeof(b),n,"\r\n");}
if(got>=2){u16 u=0;i16 v=0;memcopy(&u,raw,2);memcopy(&v,raw,2);INS_LABEL("uint16 ");append_u64_dec(b,sizeof(b),n,(u64)u);append_str(b,sizeof(b),n,"\r\n");INS_LABEL("int16  ");append_i64_dec(b,sizeof(b),n,(i64)v);append_str(b,sizeof(b),n,"\r\n");}
if(got>=4){u32 u=0;i32 v=0;float f=0;memcopy(&u,raw,4);memcopy(&v,raw,4);memcopy(&f,raw,4);INS_LABEL("uint32 ");append_u64_dec(b,sizeof(b),n,(u64)u);append_str(b,sizeof(b),n,"\r\n");INS_LABEL("int32  ");append_i64_dec(b,sizeof(b),n,(i64)v);append_str(b,sizeof(b),n,"\r\n");INS_LABEL("float  ");append_double(b,sizeof(b),n,(double)f);append_str(b,sizeof(b),n,"\r\n");}
if(got>=8){u64 u=0;i64 v=0;double d=0;memcopy(&u,raw,8);memcopy(&v,raw,8);memcopy(&d,raw,8);INS_LABEL("uint64 ");append_u64_dec(b,sizeof(b),n,u);append_str(b,sizeof(b),n,"\r\n");INS_LABEL("int64  ");append_i64_dec(b,sizeof(b),n,v);append_str(b,sizeof(b),n,"\r\n");INS_LABEL("double ");append_double(b,sizeof(b),n,d);append_str(b,sizeof(b),n,"\r\n");}
#undef INS_LABEL
flush_buf(b,n);}

static bool write_address(uptr addr,ValueType t,const char* value){HANDLE proc=(HANDLE)g_process;if(!proc)return false;u8 raw[8];if(!encode_value(t,value,raw))return false;u8 sz=type_size(t);SIZE_T wrote=0;return WriteProcessMemory(proc,(LPVOID)addr,raw,sz,&wrote)&&wrote==sz;}
static void cmd_read_at(const char* addressStr,const char* typeStr){if(!g_process){println("Attach to a process first.");return;}u64 a=0;if(!parse_u64(addressStr,a)){println("Invalid address.");return;}ValueType t=parse_type(typeStr);if(t==ValueType::Invalid){println("Invalid type.");return;}u8 raw[8]={};u8 sz=type_size(t);SIZE_T got=0;if(!ReadProcessMemory((HANDLE)g_process,(LPCVOID)(uptr)a,raw,sz,&got)||got!=sz){print_last_error("Read failed");return;}char b[260];usize n=0;append_hex(b,sizeof(b),n,(uptr)a);append_str(b,sizeof(b),n," [");append_str(b,sizeof(b),n,type_name(t));append_str(b,sizeof(b),n,"] = ");append_value(b,sizeof(b),n,t,raw);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}
static void cmd_write_at(const char* addressStr,const char* typeStr,const char* value){if(!g_process){println("Attach to a process first.");return;}u64 a=0;if(!parse_u64(addressStr,a)){println("Invalid address.");return;}ValueType t=parse_type(typeStr);if(t==ValueType::Invalid){println("Invalid type.");return;}u8 raw[8];if(!encode_value(t,value,raw)){println("Invalid value for type.");return;}if(!write_address((uptr)a,t,value)){print_last_error("Write failed");return;}println("Typed value written.");}
static void cmd_freeze_at(const char* addressStr,const char* typeStr,const char* value){if(!g_process){println("Attach to a process first.");return;}u64 a=0;if(!parse_u64(addressStr,a)){println("Invalid address.");return;}ValueType t=parse_type(typeStr);if(t==ValueType::Invalid){println("Invalid type.");return;}u8 raw[8];if(!encode_value(t,value,raw)){println("Invalid value for type.");return;}int slot=-1;for(int i=0;i<MAX_FREEZES;++i)if(!g_freezes[i].active){slot=i;break;}if(slot<0){println("Freeze table full.");return;}FreezeEntry& f=g_freezes[slot];f.address=(uptr)a;f.size=type_size(t);f.type=(u8)t;memzero(f.bytes,8);memcopy(f.bytes,raw,f.size);f.active=1;f.lastWriteOk=write_address(f.address,t,value)?1:0;char b[220];usize n=0;append_str(b,sizeof(b),n,"Freeze #");append_u64_dec(b,sizeof(b),n,(u64)slot);append_str(b,sizeof(b),n," active at ");append_hex(b,sizeof(b),n,f.address);append_str(b,sizeof(b),n," [");append_str(b,sizeof(b),n,type_name(t));append_str(b,sizeof(b),n,"] (10 ms worker).\r\n");flush_buf(b,n);}
static void cmd_set(const char* idxStr,const char* value){usize idx=0;if(!parse_index(idxStr,idx)){println("Invalid result index.");return;}ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[idx].type:g_type;u8 raw[8];if(!encode_value(t,value,raw)){println("Invalid value for this result type.");return;}if(!write_address(g_results[idx].address,t,value)){print_last_error("Write failed");return;}memcopy(g_results[idx].previous,raw,type_size(t));println("Value written.");}

static DWORD __stdcall freeze_thread(LPVOID){for(;;){HANDLE proc=(HANDLE)g_process;if(proc){for(int i=0;i<MAX_FREEZES;++i){if(g_freezes[i].active){SIZE_T wrote=0;BOOL ok=WriteProcessMemory(proc,(LPVOID)g_freezes[i].address,g_freezes[i].bytes,g_freezes[i].size,&wrote);g_freezes[i].lastWriteOk=(ok&&wrote==g_freezes[i].size)?1:0;}}}Sleep(10);} }
static void cmd_freeze(const char* idxStr,const char* value){usize idx=0;if(!parse_index(idxStr,idx)){println("Invalid result index.");return;}ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[idx].type:g_type;u8 raw[8];if(!encode_value(t,value,raw)){println("Invalid value for this result type.");return;}int slot=-1;for(int i=0;i<MAX_FREEZES;++i)if(!g_freezes[i].active){slot=i;break;}if(slot<0){println("Freeze table full.");return;}FreezeEntry& f=g_freezes[slot];f.address=g_results[idx].address;f.size=type_size(t);f.type=(u8)t;memzero(f.bytes,8);memcopy(f.bytes,raw,f.size);f.active=1;f.lastWriteOk=write_address(f.address,t,value)?1:0;char b[160];usize n=0;append_str(b,sizeof(b),n,"Freeze #");append_u64_dec(b,sizeof(b),n,(u64)slot);append_str(b,sizeof(b),n," active at ");append_hex(b,sizeof(b),n,f.address);append_str(b,sizeof(b),n," [");append_str(b,sizeof(b),n,type_name(t));append_str(b,sizeof(b),n,"].\r\n");flush_buf(b,n);}
static void cmd_freezes(){bool any=false;for(int i=0;i<MAX_FREEZES;++i){if(!g_freezes[i].active)continue;any=true;char b[256];usize n=0;append_char(b,sizeof(b),n,'#');append_u64_dec(b,sizeof(b),n,(u64)i);append_str(b,sizeof(b),n,"  ");append_hex(b,sizeof(b),n,g_freezes[i].address);append_str(b,sizeof(b),n,"  ");append_value(b,sizeof(b),n,(ValueType)g_freezes[i].type,g_freezes[i].bytes);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}if(!any)println("No active freezes.");}
static void cmd_unfreeze(const char* s){if(streq(s,"all")){clear_freezes();println("All freezes removed.");return;}u64 x=0;if(!parse_u64(s,x)||x>=MAX_FREEZES){println("Invalid freeze id.");return;}g_freezes[x].active=0;println("Freeze removed.");}

static void show_help(){
    println("Cheat Wizard v1.7.0 x64 - scanner + scan sessions + AOB + pointer maps");
    println("  processes | ps");println("  attach <pid>");println("  attach-name <exe-name>");println("  detach");
    println("  scan <byte|int16|int32|int64|float|double> <value|unknown|unknown-smart>");println("  scan all <value|unknown|unknown-smart>");
    println("  next <value> | next exact <value>");println("  next changed | unchanged | increased | decreased");println("  next bigger <value> | smaller <value>");
    println("  results [count] | inspect <#index|address>");println("  read-at <address> <type> | write-at <address> <type> <value>");println("  freeze-at <address> <type> <value> (50 ms)");println("  scan-save <file.cwscan> | scan-load <file.cwscan> [force]");println("  set <#index> <value> | freeze <#index> <value>");println("  freezes | unfreeze <id|all>");
    println("  modules");println("  aob <byte...> | aob-code <byte...>");println("  aob-module <module> <byte...> | aob-module-code <module> <byte...>");println("  aob-results [count]");
    println("  aob-resolve <#aob-index|address> <disp_offset> <instruction_size>");println("      CALL/JMP E8/E9: aob-resolve #0 1 5");println("      RIP-relative example: aob-resolve #0 3 7");
    println("  aob-decode <#aob-index|address>");println("  aob-save <file.cwaob> | aob-load <file.cwaob> | aob-rerun <file.cwaob>");println("  aob-clear");
    println("  pointer-settings");println("  pointer-settings alignment <natural|byte|2|4|8>");println("  pointer-settings writable <on|off>");println("  pointer-settings private <on|off>");println("  pointer-settings branch <1..65536>");println("  pointer-settings root <any|module-name>");
    println("  pointer-scan <target> [depth] [max_offset] [max_chains] [max_negative_offset]");println("  pointer-results [count]");println("  pointer-resolve <chain-index>");println("  pointer-rescan <#index|address>");println("  pointer-save <file.cwchain> | pointer-load <file.cwchain>");
    println("  pmap-capture <file.cwmap> <#index|address> [max_entries]");println("  pmap-load <file.cwmap> | pmap-list");println("  pmap-compare [depth] [max_offset] [max_chains] [max_negative_offset]");println("  pmap-compare-files <file1> <file2> [file3 ...]");println("  pmap-clear | pointer-clear");
    println("  settings alignment <natural|byte>");println("  version | clear | status | help | quit");
}

static void cmd_status(){
    char b[760];usize n=0;append_str(b,sizeof(b),n,"PID: ");append_u64_dec(b,sizeof(b),n,g_pid);
    append_str(b,sizeof(b),n," | type: ");append_str(b,sizeof(b),n,type_name(g_type));append_str(b,sizeof(b),n," | results: ");append_u64_dec(b,sizeof(b),n,g_resultCount);
    append_str(b,sizeof(b),n," | AOB: ");append_u64_dec(b,sizeof(b),n,g_aobCount);append_str(b,sizeof(b),n," | pointer width: ");append_u64_dec(b,sizeof(b),n,(u64)g_pointerSize*8);
    append_str(b,sizeof(b),n," | pointer chains: ");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n," | pointer maps: ");append_u64_dec(b,sizeof(b),n,g_pointerMapCount);
    append_str(b,sizeof(b),n," | value alignment: ");append_str(b,sizeof(b),n,g_alignmentByte?"byte":"natural");
    append_str(b,sizeof(b),n," | ptr align: ");if(g_pointerAlignment==0)append_str(b,sizeof(b),n,"natural");else append_u64_dec(b,sizeof(b),n,g_pointerAlignment);
    append_str(b,sizeof(b),n," | ptr branch: ");append_u64_dec(b,sizeof(b),n,g_pointerBranchCap);
    append_str(b,sizeof(b),n," | ptr root: ");append_str(b,sizeof(b),n,g_pointerRootModule[0]?g_pointerRootModule:"any");
    append_str(b,sizeof(b),n," | unknown snapshot: ");append_str(b,sizeof(b),n,g_snapshotActive?"active":"none");if(g_snapshotActive){append_str(b,sizeof(b),n," (");append_u64_dec(b,sizeof(b),n,g_snapshotCandidates);append_str(b,sizeof(b),n," candidates, ");append_u64_dec(b,sizeof(b),n,g_snapshotBytes/(1024*1024));append_str(b,sizeof(b),n," MiB temp backing)");}
    append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);
}



// -----------------------------------------------------------------------------
// Cheat Wizard native Win32 GUI v1.7.0 - Scanner + Pointer workspace.
// Custom retained/immediate hybrid UI: no legacy list boxes/combo boxes.
// Zinc design system, responsive layout, live address watch list, verified
// writes and deterministic freeze semantics.
// -----------------------------------------------------------------------------

using UINT = unsigned int;
using ATOM = unsigned short;
using WPARAM = unsigned long long;
using LPARAM = long long;
using LRESULT = long long;
using UINT_PTR = unsigned long long;
using COLORREF = unsigned long;
using HWND = void*;
using HINSTANCE = void*;
using HMENU = void*;
using HICON = void*;
using HCURSOR = void*;
using HBRUSH = void*;
using HFONT = void*;
using HDC = void*;
using HGDIOBJ = void*;
using HPEN = void*;
using HBITMAP = void*;
struct BITMAPINFOHEADER_ { DWORD biSize; LONG biWidth; LONG biHeight; u16 biPlanes; u16 biBitCount; DWORD biCompression; DWORD biSizeImage; LONG biXPelsPerMeter; LONG biYPelsPerMeter; DWORD biClrUsed; DWORD biClrImportant; };
struct RGBQUAD_ { u8 rgbBlue; u8 rgbGreen; u8 rgbRed; u8 rgbReserved; };
struct BITMAPINFO_ { BITMAPINFOHEADER_ bmiHeader; RGBQUAD_ bmiColors[1]; };
struct BLENDFUNCTION_ { u8 BlendOp; u8 BlendFlags; u8 SourceConstantAlpha; u8 AlphaFormat; };
using WNDPROC_ = LRESULT (__stdcall *)(HWND, UINT, WPARAM, LPARAM);

struct POINT_ { LONG x; LONG y; };
struct RECT_ { LONG left; LONG top; LONG right; LONG bottom; };
struct SIZE_ { LONG cx; LONG cy; };
struct MINMAXINFO_ { POINT_ ptReserved; POINT_ ptMaxSize; POINT_ ptMaxPosition; POINT_ ptMinTrackSize; POINT_ ptMaxTrackSize; };
struct MSG_ { HWND hwnd; UINT message; WPARAM wParam; LPARAM lParam; DWORD time; POINT_ pt; };
struct PAINTSTRUCT_ { HDC hdc; BOOL fErase; RECT_ rcPaint; BOOL fRestore; BOOL fIncUpdate; u8 rgbReserved[32]; };
struct WNDCLASSEXA_ {
    UINT cbSize; UINT style; WNDPROC_ lpfnWndProc; int cbClsExtra; int cbWndExtra;
    HINSTANCE hInstance; HICON hIcon; HCURSOR hCursor; HBRUSH hbrBackground;
    const char* lpszMenuName; const char* lpszClassName; HICON hIconSm;
};

struct OPENFILENAMEA_ {
    DWORD lStructSize; HWND hwndOwner; HINSTANCE hInstance; const char* lpstrFilter; char* lpstrCustomFilter;
    DWORD nMaxCustFilter; DWORD nFilterIndex; char* lpstrFile; DWORD nMaxFile; char* lpstrFileTitle; DWORD nMaxFileTitle;
    const char* lpstrInitialDir; const char* lpstrTitle; DWORD Flags; u16 nFileOffset; u16 nFileExtension;
    const char* lpstrDefExt; LPARAM lCustData; void* lpfnHook; const char* lpTemplateName; void* pvReserved; DWORD dwReserved; DWORD FlagsEx;
};
struct CHOOSECOLORA_ {
    DWORD lStructSize; HWND hwndOwner; HWND hInstance; COLORREF rgbResult; COLORREF* lpCustColors;
    DWORD Flags; LPARAM lCustData; void* lpfnHook; const char* lpTemplateName;
};

extern "C" {
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleA(const char*);
__declspec(dllimport) HINSTANCE __stdcall LoadLibraryA(const char*);
__declspec(dllimport) void* __stdcall GetProcAddress(HINSTANCE,const char*);
__declspec(dllimport) ATOM __stdcall RegisterClassExA(const WNDCLASSEXA_*);
__declspec(dllimport) HWND __stdcall CreateWindowExA(DWORD,const char*,const char*,DWORD,int,int,int,int,HWND,HMENU,HINSTANCE,LPVOID);
__declspec(dllimport) LRESULT __stdcall DefWindowProcA(HWND,UINT,WPARAM,LPARAM);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND,int);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND);
__declspec(dllimport) BOOL __stdcall GetMessageA(MSG_*,HWND,UINT,UINT);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG_*);
__declspec(dllimport) LRESULT __stdcall DispatchMessageA(const MSG_*);
__declspec(dllimport) void __stdcall PostQuitMessage(int);
__declspec(dllimport) BOOL __stdcall PostMessageA(HWND,UINT,WPARAM,LPARAM);
__declspec(dllimport) LRESULT __stdcall SendMessageA(HWND,UINT,WPARAM,LPARAM);
__declspec(dllimport) int __stdcall MessageBoxA(HWND,const char*,const char*,UINT);
__declspec(dllimport) BOOL __stdcall SetWindowTextW(HWND,const wchar_t*);
__declspec(dllimport) HCURSOR __stdcall LoadCursorA(HINSTANCE,const char*);
__declspec(dllimport) UINT_PTR __stdcall SetTimer(HWND,UINT_PTR,UINT,void*);
__declspec(dllimport) BOOL __stdcall KillTimer(HWND,UINT_PTR);
__declspec(dllimport) HDC __stdcall BeginPaint(HWND,PAINTSTRUCT_*);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND,const PAINTSTRUCT_*);
__declspec(dllimport) BOOL __stdcall InvalidateRect(HWND,const RECT_*,BOOL);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND,RECT_*);
__declspec(dllimport) HWND __stdcall SetFocus(HWND);
__declspec(dllimport) short __stdcall GetKeyState(int);
__declspec(dllimport) BOOL __stdcall ScreenToClient(HWND,POINT_*);
__declspec(dllimport) BOOL __stdcall SetProcessDPIAware();

__declspec(dllimport) int __stdcall FillRect(HDC,const RECT_*,HBRUSH);
__declspec(dllimport) int __stdcall FrameRect(HDC,const RECT_*,HBRUSH);
__declspec(dllimport) int __stdcall DrawTextA(HDC,const char*,int,RECT_*,UINT);
__declspec(dllimport) int __stdcall DrawTextW(HDC,const wchar_t*,int,RECT_*,UINT);
__declspec(dllimport) BOOL __stdcall GetTextExtentPoint32A(HDC,const char*,int,SIZE_*);
__declspec(dllimport) BOOL __stdcall GetTextExtentPoint32W(HDC,const wchar_t*,int,SIZE_*);
__declspec(dllimport) void* __stdcall GetStockObject(int);
__declspec(dllimport) COLORREF __stdcall SetTextColor(HDC,COLORREF);
__declspec(dllimport) COLORREF __stdcall SetBkColor(HDC,COLORREF);
__declspec(dllimport) int __stdcall SetBkMode(HDC,int);
__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(COLORREF);
__declspec(dllimport) HPEN __stdcall CreatePen(int,int,COLORREF);
__declspec(dllimport) BOOL __stdcall DeleteObject(HGDIOBJ);
__declspec(dllimport) HGDIOBJ __stdcall SelectObject(HDC,HGDIOBJ);
__declspec(dllimport) HFONT __stdcall CreateFontA(int,int,int,int,int,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,const char*);
__declspec(dllimport) BOOL __stdcall Ellipse(HDC,int,int,int,int);
__declspec(dllimport) BOOL __stdcall RoundRect(HDC,int,int,int,int,int,int);
__declspec(dllimport) BOOL __stdcall MoveToEx(HDC,int,int,POINT_*);
__declspec(dllimport) BOOL __stdcall LineTo(HDC,int,int);
__declspec(dllimport) int __stdcall SaveDC(HDC);
__declspec(dllimport) BOOL __stdcall RestoreDC(HDC,int);
__declspec(dllimport) int __stdcall IntersectClipRect(HDC,int,int,int,int);
__declspec(dllimport) HDC __stdcall CreateCompatibleDC(HDC);
__declspec(dllimport) HBITMAP __stdcall CreateCompatibleBitmap(HDC,int,int);
__declspec(dllimport) HBITMAP __stdcall CreateDIBSection(HDC,const BITMAPINFO_*,UINT,void**,HANDLE,DWORD);
__declspec(dllimport) BOOL __stdcall DeleteDC(HDC);
__declspec(dllimport) BOOL __stdcall BitBlt(HDC,int,int,int,int,HDC,int,int,DWORD);
__declspec(dllimport) BOOL __stdcall AlphaBlend(HDC,int,int,int,int,HDC,int,int,int,int,BLENDFUNCTION_);
}

static constexpr DWORD WS_OVERLAPPED_ = 0x00000000UL;
static constexpr DWORD WS_CAPTION_ = 0x00C00000UL;
static constexpr DWORD WS_SYSMENU_ = 0x00080000UL;
static constexpr DWORD WS_MINIMIZEBOX_ = 0x00020000UL;
static constexpr DWORD WS_MAXIMIZEBOX_ = 0x00010000UL;
static constexpr DWORD WS_THICKFRAME_ = 0x00040000UL;
static constexpr DWORD WS_CHILD_ = 0x40000000UL;
static constexpr DWORD WS_VISIBLE_ = 0x10000000UL;
static constexpr DWORD WS_TABSTOP_ = 0x00010000UL;
static constexpr DWORD ES_AUTOHSCROLL_ = 0x0080UL;
static constexpr int SW_HIDE_ = 0;
static constexpr int SW_SHOW_ = 5;
static constexpr int TRANSPARENT_ = 1;
static constexpr int DEFAULT_GUI_FONT_ = 17;
static constexpr int NULL_BRUSH_ = 5;
static constexpr int NULL_PEN_ = 8;
static constexpr int FW_NORMAL_ = 400;
static constexpr int FW_SEMIBOLD_ = 600;
static constexpr DWORD CLEARTYPE_QUALITY_ = 5;
static constexpr int PS_SOLID_ = 0;
static constexpr DWORD SRCCOPY_ = 0x00CC0020UL;
static constexpr DWORD BI_RGB_ = 0;
static constexpr UINT DIB_RGB_COLORS_ = 0;
static constexpr u8 AC_SRC_OVER_ = 0;
static constexpr u8 AC_SRC_ALPHA_ = 1;
static constexpr UINT CS_DBLCLKS_ = 0x0008;
static constexpr UINT WM_CREATE_ = 0x0001;
static constexpr UINT WM_DESTROY_ = 0x0002;
static constexpr UINT WM_SIZE_ = 0x0005;
static constexpr UINT WM_PAINT_ = 0x000F;
static constexpr UINT WM_CLOSE_ = 0x0010;
static constexpr UINT WM_ERASEBKGND_ = 0x0014;
static constexpr UINT WM_GETMINMAXINFO_ = 0x0024;
static constexpr UINT WM_SETFONT_ = 0x0030;
static constexpr UINT WM_COMMAND_ = 0x0111;
static constexpr UINT WM_TIMER_ = 0x0113;
static constexpr UINT WM_CTLCOLOREDIT_ = 0x0133;
static constexpr UINT WM_CTLCOLORSTATIC_ = 0x0138;
static constexpr UINT WM_MOUSEMOVE_ = 0x0200;
static constexpr UINT WM_LBUTTONDOWN_ = 0x0201;
static constexpr UINT WM_LBUTTONDBLCLK_ = 0x0203;
static constexpr UINT WM_MOUSEWHEEL_ = 0x020A;
static constexpr UINT WM_APP_SCAN_DONE_ = 0x8001;
static constexpr UINT WM_APP_POINTER_DONE_ = 0x8002;
static constexpr UINT MB_OK_ = 0x00000000;
static constexpr UINT MB_ICONERROR_ = 0x00000010;
static constexpr UINT DT_LEFT_ = 0x00000000;
static constexpr UINT DT_CENTER_ = 0x00000001;
static constexpr UINT DT_RIGHT_ = 0x00000002;
static constexpr UINT DT_VCENTER_ = 0x00000004;
static constexpr UINT DT_WORDBREAK_ = 0x00000010;
static constexpr UINT DT_SINGLELINE_ = 0x00000020;
static constexpr UINT DT_END_ELLIPSIS_ = 0x00008000;
static constexpr unsigned int CP_UTF8_ = 65001;
static constexpr DWORD MB_ERR_INVALID_CHARS_ = 0x00000008UL;

static constexpr COLORREF rgb_(u8 r,u8 g,u8 b){return (COLORREF)((u32)r|((u32)g<<8)|((u32)b<<16));}
static constexpr COLORREF Z950 = rgb_(9,9,11);
static constexpr COLORREF Z925 = rgb_(14,14,17);
static constexpr COLORREF Z900 = rgb_(24,24,27);
static constexpr COLORREF Z850 = rgb_(31,31,35);
static constexpr COLORREF Z800 = rgb_(39,39,42);
static constexpr COLORREF Z750 = rgb_(51,51,56);
static constexpr COLORREF Z700 = rgb_(63,63,70);
static constexpr COLORREF Z600 = rgb_(82,82,91);
static constexpr COLORREF Z500 = rgb_(113,113,122);
static constexpr COLORREF Z400 = rgb_(161,161,170);
static constexpr COLORREF Z300 = rgb_(212,212,216);
static constexpr COLORREF Z200 = rgb_(228,228,231);
static constexpr COLORREF Z100 = rgb_(244,244,245);
static constexpr COLORREF Z50  = rgb_(250,250,250);
static constexpr COLORREF BLUE500 = rgb_(59,130,246);
static constexpr COLORREF BLUE600 = rgb_(37,99,235);
static constexpr COLORREF BLUE300 = rgb_(147,197,253);
static constexpr COLORREF GREEN400 = rgb_(52,211,153);
static constexpr COLORREF AMBER400 = rgb_(251,191,36);
static constexpr COLORREF RED400 = rgb_(248,113,113);

struct UiRect { int x,y,w,h; };
static bool ui_contains(const UiRect& r,int x,int y){return x>=r.x&&x<r.x+r.w&&y>=r.y&&y<r.y+r.h;}
static RECT_ ui_rect(const UiRect& r){RECT_ q{r.x,r.y,r.x+r.w,r.y+r.h};return q;}
static int ui_maxi(int a,int b){return a>b?a:b;}
static int ui_mini(int a,int b){return a<b?a:b;}
static int ui_clampi(int v,int lo,int hi){return v<lo?lo:(v>hi?hi:v);}

struct UiLayout_ {
    int w,h;
    UiRect header;
    UiRect tabScanner;
    UiRect tabPointers;
    UiRect tabTrainer;
    UiRect target;
    UiRect refresh;
    UiRect attach;
    UiRect scanCard;
    UiRect scanValueBox;
    UiRect scanType;
    UiRect valueType;
    UiRect scanSummary;
    UiRect scanStats;
    UiRect scanHint;
    UiRect alignment;
    UiRect firstScan;
    UiRect nextScan;
    UiRect newScan;
    UiRect guideChanged;
    UiRect guideUnchanged;
    UiRect guideIncreased;
    UiRect guideDecreased;
    UiRect wizardGoal;
    UiRect resultCard;
    UiRect resultTable;
    UiRect rankToggle;
    UiRect addResult;
    UiRect watchCard;
    UiRect watchTable;
    UiRect watchNameBox;
    UiRect renameWatch;
    UiRect watchValueBox;
    UiRect writeValue;
    UiRect freezeValue;
    UiRect removeWatch;
    UiRect pointerFromWatch;
    UiRect clearWatch;
    // Pointer workspace
    UiRect pointerControlCard;
    UiRect pointerTargetBox;
    UiRect pointerUseSelected;
    UiRect pointerPresetFast;
    UiRect pointerPresetBalanced;
    UiRect pointerPresetDeep;
    UiRect pointerRootToggle;
    UiRect pointerStart;
    UiRect pointerRescan;
    UiRect pointerClear;
    UiRect pointerSave;
    UiRect pointerLoad;
    UiRect pointerAddWatch;
    UiRect pointerCancel;
    UiRect pointerResultCard;
    UiRect pointerTable;
    // Trainer project workspace
    UiRect trainerProjectCard;
    UiRect trainerSubConfig;
    UiRect trainerSubVisual;
    UiRect trainerTitleBox;
    UiRect trainerProcessBox;
    UiRect trainerAddTitle;
    UiRect trainerAddSubtitle;
    UiRect trainerAddProfile;
    UiRect trainerAddCurrent;
    UiRect trainerSaveJson;
    UiRect trainerEntryCard;
    UiRect trainerTable;
    UiRect trainerLabelBox;
    UiRect trainerDefaultBox;
    UiRect trainerShowToggle;
    UiRect trainerWriteToggle;
    UiRect trainerFreezeToggle;
    UiRect trainerMoveUp;
    UiRect trainerMoveDown;
    UiRect trainerRemove;
    // Trainer visual editor
    UiRect trainerIconButton;
    UiRect trainerIconConvert;
    UiRect trainerColorBg;
    UiRect trainerColorPanel;
    UiRect trainerColorSurface;
    UiRect trainerColorAccent;
    UiRect trainerColorText;
    UiRect trainerColorMuted;
    UiRect trainerPreview;
    UiRect footer;
    UiRect locale;
};
static UiLayout_ g_ui{};

static HWND g_hwnd = nullptr;
enum UiTextFocus_ { UI_TEXT_NONE=0, UI_TEXT_SCAN=1, UI_TEXT_WATCH=2, UI_TEXT_TRAINER_TITLE=3, UI_TEXT_TRAINER_LABEL=4, UI_TEXT_TRAINER_DEFAULT=5, UI_TEXT_COLOR_BG=6, UI_TEXT_COLOR_PANEL=7, UI_TEXT_COLOR_SURFACE=8, UI_TEXT_COLOR_ACCENT=9, UI_TEXT_COLOR_TEXT=10, UI_TEXT_COLOR_MUTED=11, UI_TEXT_PROCESS_FILTER=12, UI_TEXT_WATCH_NAME=13 };
static UiTextFocus_ g_uiTextFocus = UI_TEXT_NONE;
static char g_uiScanText[128] = "100";
static char g_uiWatchText[128] = "";
static char g_uiWatchNameText[128] = "";
static char g_uiProcessFilter[128] = "";
static HFONT g_font = nullptr;
static HFONT g_fontSmall = nullptr;
static HFONT g_fontBold = nullptr;
static HFONT g_fontTitle = nullptr;
static HFONT g_fontMono = nullptr;
static HBRUSH g_brushBg = nullptr;
static HBRUSH g_brushPanel = nullptr;
static HBRUSH g_brushSurface = nullptr;
static HBRUSH g_brushHover = nullptr;
static HBRUSH g_brushSelected = nullptr;
static HBRUSH g_brushAccent = nullptr;
static HBRUSH g_brushAccentHover = nullptr;
static HBRUSH g_brushDanger = nullptr;
static HPEN g_penBorder = nullptr;
static HPEN g_penStrong = nullptr;
static HPEN g_penAccent = nullptr;
static HPEN g_penGreen = nullptr;

static volatile LONG g_uiBusy = 0;
static constexpr usize UI_RESULT_RENDER_LIMIT = 5000;
static constexpr usize UI_WATCH_LIMIT = 256;
static constexpr int UI_WATCH_ROW_H = 38;
static constexpr usize UI_PROCESS_LIMIT = 1024;

struct UiProcess_ { DWORD pid; char name[260]; };
static UiProcess_ g_uiProcesses[UI_PROCESS_LIMIT]{};
static int g_uiProcessCount = 0;
static int g_uiProcessSelected = -1;
static int g_uiProcessScroll = 0;
static int g_uiProcessFiltered[UI_PROCESS_LIMIT]{};
static int g_uiProcessFilteredCount = 0;
static char g_uiAttachedName[260]{};

struct UiWatch_ {
    bool active;
    uptr address;
    u8 type;
    u8 scanValue[8];
    char name[128];
};
static UiWatch_ g_uiWatches[UI_WATCH_LIMIT]{};
static int g_uiWatchCount = 0;
static int g_uiSelectedWatch = -1;
static int g_uiSelectedResult = -1;
static int g_uiResultScroll = 0;
static int g_uiWatchScroll = 0;
static void ui_refresh_rank_anchors(){g_rankAnchorCount=0;for(int i=0;i<(int)UI_WATCH_LIMIT&&g_rankAnchorCount<MAX_RANK_ANCHORS;++i){if(!g_uiWatches[i].active)continue;g_rankAnchors[g_rankAnchorCount++]={g_uiWatches[i].address,i};}for(usize i=1;i<g_rankAnchorCount;++i){RankAnchor_ a=g_rankAnchors[i];usize j=i;while(j>0&&(g_rankAnchors[j-1].address>a.address||(g_rankAnchors[j-1].address==a.address&&g_rankAnchors[j-1].watchSlot>a.watchSlot))){g_rankAnchors[j]=g_rankAnchors[j-1];--j;}g_rankAnchors[j]=a;}g_rankingDirty=true;}
static void ui_watch_list_changed(bool rebuildNow=true){ui_refresh_rank_anchors();if(rebuildNow&&g_rankingEnabled&&!g_snapshotActive&&g_resultCount&&!g_uiBusy){rebuild_result_ranking();g_uiResultScroll=0;}}

static int g_uiScanType = 0;
static int g_uiValueType = 2;
static bool g_uiUnknownFlow = false;
static int g_uiUnknownInitialMode = 0; // 0=none, 1=Full, 2=Smart
enum UiPopup_ { UI_POP_NONE=0, UI_POP_PROCESS=1, UI_POP_SCAN=2, UI_POP_VALUE=3 };
static UiPopup_ g_uiPopup = UI_POP_NONE;
static int g_uiMouseX = -1;
static int g_uiMouseY = -1;
static char g_uiStatus[420] = "Ready. Select a process to begin.";
static int g_uiStatusKind = 0; // 0 neutral, 1 success, 2 warn, 3 error

enum UiView_ { UI_VIEW_SCANNER=0, UI_VIEW_POINTERS=1, UI_VIEW_TRAINER=2 };
static UiView_ g_uiView = UI_VIEW_SCANNER;
static bool g_uiPointerTargetValid = false;
static uptr g_uiPointerTarget = 0;
static u8 g_uiPointerTargetType = (u8)ValueType::Invalid;
static char g_uiPointerProfilePath[260]{};
static char g_uiPointerProfileProcess[260]{};
static u8 g_uiPointerProfileType = (u8)ValueType::Invalid;
static u8 g_uiPointerTargetScanValue[8]{};
static int g_uiPointerPreset = 1; // 0 fast, 1 balanced, 2 deep
static bool g_uiPointerRootAny = false;
static int g_uiSelectedPointer = -1;
static int g_uiPointerScroll = 0;
static usize g_uiPointerIndexed = 0;
static usize g_uiPointerBefore = 0;
static usize g_uiPointerLevel1Candidates = 0;
static bool g_uiPointerIndexTruncated = false;
static bool g_uiPointerAutoRootFallback = false;
static bool g_uiPointerSearchTruncated = false;
static bool g_uiPointerSearchBudgetHit = false;
static bool g_uiPointerTargetedUsed = false;
static volatile LONG g_uiPointerPhase = 0; // 0 idle, 1 index, 2 search, 3 fallback, 4 rescan
static uptr g_uiPointerResolvedCache[MAX_POINTER_CHAINS]{};
static u8 g_uiPointerResolveState[MAX_POINTER_CHAINS]{}; // 0 unknown, 1 fail, 2 resolved
static u8 g_uiPointerValueCache[MAX_POINTER_CHAINS][8]{};
static u8 g_uiPointerValueState[MAX_POINTER_CHAINS]{}; // 0 unknown, 1 unreadable, 2 readable

static constexpr usize UI_TRAINER_ENTRY_LIMIT = 8;
static constexpr usize UI_TRAINER_ELEMENT_LIMIT = 32;
enum UiTrainerElementType_:u8 { UI_TRAINER_TITLE=0, UI_TRAINER_SUBTITLE=1, UI_TRAINER_FIELD=2 };
struct UiTrainerEntry_ {
    bool active;
    char id[64];
    char label[128];
    char profile[260];
    char defaultValue[64];
    bool showCurrent;
    bool allowWrite;
    bool allowFreeze;
};
struct UiTrainerElement_ {
    bool active;
    u8 type;
    int entryIndex;
    char text[192];
};
static UiTrainerEntry_ g_uiTrainerEntries[UI_TRAINER_ENTRY_LIMIT]{};
static UiTrainerElement_ g_uiTrainerElements[UI_TRAINER_ELEMENT_LIMIT]{};
static int g_uiTrainerCount = 0;
static int g_uiTrainerSelected = -1;
static int g_uiTrainerElementCount = 0;
static int g_uiTrainerElementSelected = -1;
static int g_uiTrainerElementScroll = 0;
static char g_uiTrainerElementText[192]{};
static char g_uiTrainerTitle[128] = "Trainer";
static char g_uiTrainerProcess[260]{};
static char g_uiTrainerLabel[128]{};
static char g_uiTrainerDefault[64]{};
static int g_uiTrainerMode = 0; // 0 configuracao, 1 visual
static char g_uiTrainerIcon[260]{};
static char g_uiTrainerColorBg[16] = "#09090B";
static char g_uiTrainerColorPanel[16] = "#18181B";
static char g_uiTrainerColorSurface[16] = "#27272A";
static char g_uiTrainerColorAccent[16] = "#2563EB";
static char g_uiTrainerColorText[16] = "#FAFAFA";
static char g_uiTrainerColorMuted[16] = "#A1A1AA";

// Locale contract: flat UTF-8 JSON with compiled English fallbacks. External
// files only override known keys, so a missing/incomplete locale can never
// prevent the GUI from starting.
struct UiLocaleDef_ { const char* key; const char* fallback; };
static const UiLocaleDef_ g_uiLocaleDefs[] = {
    {"_meta.code", "en-US"},
    {"_meta.name", "English (United States)"},
    {"_meta.nativeName", "English"},
    {"app.name", "Cheat Wizard"},
    {"app.tagline", "Memory Tools"},
    {"app.windowTitle", "Cheat Wizard v1.7.0 - Memory Scanner, Pointers & Trainer Projects"},
    {"nav.scanner", "Scanner"},
    {"nav.pointers", "Pointers"},
    {"nav.trainer", "Trainer"},
    {"header.selectProcess", "Select process"},
    {"header.refresh", "Refresh"},
    {"header.attach", "Attach"},
    {"header.attached", "Attached"},
    {"status.ready", "Ready. Select a process to begin."},
    {"status.localeChanged", "Language changed."},
    {"status.localeFallback", "Locale file unavailable or invalid. Compiled English fallback is active."},
    {"status.processEnumFailed", "Could not enumerate processes."},
    {"status.processesUpdated", "Processes refreshed: "},
    {"status.selectResult", "Select a result to add to the address list."},
    {"status.addressAlreadyListed", "That address is already in the list."},
    {"status.addressListFull", "The address list is full."},
    {"status.selectAddress", "Select an address from the list."},
    {"status.addressRemoved", "Address removed from the list."},
    {"status.addressRemovedRanking", "Address removed. Ranking V3 recalculated without that anchor."},
    {"status.addressNameUpdated", "Address name updated."},
    {"status.addressNameRemoved", "Address name removed."},
    {"status.invalidAddressValue", "Invalid value for this address type."},
    {"status.writeFailed", "WriteProcessMemory failed. Check permissions and address."},
    {"status.writeConfirmed", "Write confirmed in the process."},
    {"status.writeConfirmedFreeze", "Write confirmed; the freeze target was updated."},
    {"status.writeOverwritten", "The write occurred, but the process immediately overwrote the value."},
    {"status.freezeRemoved", "Freeze removed."},
    {"status.freezeValueRequired", "Enter the value that should remain frozen."},
    {"status.freezeEnableFailed", "Could not enable freeze."},
    {"status.freezeActive", "Freeze active: the value is reinforced every 10 ms."},
    {"status.attachBeforeScan", "Attach to a process before scanning."},
    {"status.selectValueType", "Select a value type."},
    {"status.firstScanModesOnly", "First Scan accepts Exact Value, Unknown Full, or Unknown Smart."},
    {"status.unknownOnlyFirst", "Unknown initial value is only valid on First Scan."},
    {"status.firstBeforeNext", "Run First Scan before Next Scan."},
    {"status.enterScanValue", "Enter a value for this scan type."},
    {"status.firstScanRunning", "First Scan in progress..."},
    {"status.nextScanRunning", "Next Scan in progress..."},
    {"status.scanThreadFailed", "Could not start the scan thread."},
    {"status.guidedUnavailable", "The Wizard is available only for scans started as Unknown."},
    {"status.guidedPrefix", "Guided: "},
    {"status.guidedRefining", ". Refining all active candidates..."},
    {"status.guidedThreadFailed", "Could not start the guided scan thread."},
    {"status.newScan", "New scan. The Address List was preserved."},
    {"status.selectProcess", "Select a process."},
    {"status.openProcessFailed", "OpenProcess failed. Win32 error "},
    {"status.attachedTo", "Attached to "},
    {"status.pointerWidth", " - pointers "},
    {"status.previousChains", " Previous chains preserved: find the new address and use Rescan."},
    {"status.addressAddedRanking", "Address added. Ranking V3 recalculated using proximity to the List."},
    {"status.addressAddedTracking", "Address added. The Current column tracks memory once per second."},
    {"status.typeRemovedPrefix", "Type "},
    {"status.typeRemovedMiddle", " removed: "},
    {"status.typeRemovedCandidates", " candidates."},
    {"status.materializeNext", " Run Next Scan to materialize."},
    {"status.wizardGoalPrefix", "Wizard target: "},
    {"status.alignmentByteOn", "Byte alignment enabled."},
    {"status.alignmentNaturalOn", "Natural alignment enabled."},
    {"scanner.value", "Value"},
    {"scanner.scanType", "Scan type"},
    {"scanner.valueType", "Value type"},
    {"scanner.exact", "Exact value"},
    {"scanner.unknown", "Unknown initial value"},
    {"scanner.firstScan", "First scan"},
    {"scanner.nextScan", "Next scan"},
    {"scanner.changed", "Changed"},
    {"scanner.unchanged", "Unchanged"},
    {"scanner.increased", "Increased"},
    {"scanner.decreased", "Decreased"},
    {"scanner.biggerThan", "Greater than"},
    {"scanner.smallerThan", "Less than"},
    {"scanner.stop", "Cancel"},
    {"scanner.cardReadyHint", "Choose how the scan should begin."},
    {"scanner.cardActiveHint", "Refine candidates step by step."},
    {"scanner.scanning", "Scanning..."},
    {"scanner.scanningHint", "Wait for the scan to finish.\nThe Address List will be preserved."},
    {"scanner.scanningBadge", "SCANNING"},
    {"scanner.alignmentPrefix", "Alignment: "},
    {"scanner.alignmentByte", "byte"},
    {"scanner.alignmentNatural", "natural"},
    {"scanner.smartHint", "Smart examines private writable memory. Recommended when you do not know the value or type yet."},
    {"scanner.fullHint", "Full examines all readable memory. Use it when Smart does not find the target."},
    {"scanner.exactHint", "Enter the known value and the most likely numeric type."},
    {"scanner.unknownSmart", "Unknown Smart"},
    {"scanner.unknownFull", "Unknown Full"},
    {"scanner.active", "Active scan"},
    {"scanner.refineValue", "REFINE VALUE"},
    {"scanner.targetPrefix", "Target: "},
    {"scanner.candidateSingular", " candidate"},
    {"scanner.candidatePlural", " candidates"},
    {"scanner.resultSingular", " result"},
    {"scanner.resultPlural", " results"},
    {"scanner.stepSingular", " step"},
    {"scanner.stepPlural", " steps"},
    {"scanner.lastPrefix", "Last: "},
    {"scanner.manualHint", "Choose below how the value should be compared on the next refinement."},
    {"scanner.manualRefine", "MANUAL REFINE"},
    {"scanner.referenceValue", "REFERENCE VALUE"},
    {"scanner.newScan", "New Scan"},
    {"scanner.allTypes", "All"},
    {"guided.changed", "Changed"},
    {"guided.unchanged", "Unchanged"},
    {"guided.increased", "Increased"},
    {"guided.decreased", "Decreased"},
    {"guided.exact", "Exact"},
    {"guided.bigger", "Greater"},
    {"guided.smaller", "Less"},
    {"guided.goal.generic", "Generic"},
    {"guided.goal.money", "Money"},
    {"guided.goal.health", "Health"},
    {"guided.goal.ammo", "Ammo"},
    {"guided.action.steady", "Keep the value unchanged for a few seconds, then click Unchanged."},
    {"guided.action.moneyDown", "Spend money in the game, then click Decreased."},
    {"guided.action.moneyUp", "Earn money in the game, then click Increased."},
    {"guided.action.healthDown", "Take damage in the game, then click Decreased."},
    {"guided.action.healthUp", "Recover health, then click Increased."},
    {"guided.action.ammoDown", "Fire or consume ammo, then click Decreased."},
    {"guided.action.ammoUp", "Reload or gain ammo, then click Increased."},
    {"guided.action.generic", "Change the target value in the game, then click Changed."},
    {"guided.action.fallback", "Change the target value and refine."},
    {"results.title", "Scan results"},
    {"results.address", "Address"},
    {"results.type", "Type"},
    {"results.scanValue", "Scan value"},
    {"results.current", "Current"},
    {"results.scoreNear", "Score / near"},
    {"results.waitSubtitle", "The results area appears when the scan finishes."},
    {"results.waiting", "Scan in progress..."},
    {"results.unknownTitle", "Unknown refinement"},
    {"results.unknownSubtitle", "Complete snapshot preserved. No candidate is discarded automatically."},
    {"results.exactSuffix", " exact  |  "},
    {"results.tempMiBSuffix", " MiB temporary"},
    {"results.mixedRefineHint", "Use the Wizard to refine. Remove a type below only when you are sure it is not the target."},
    {"results.singleRefineHint", "Use the Wizard to refine. Table and Ranking appear when results are materialized."},
    {"results.materializedOnly", "The table appears only when there are materialized results."},
    {"results.none", "No results to display"},
    {"results.startScan", "Start a scan to populate this area."},
    {"results.rankingHint", "Addresses near the List rise in ranking and are marked."},
    {"results.doubleClickHint", "Double-click adds the address to the Address List."},
    {"results.rankingOn", "Ranking V3 ON"},
    {"results.rankingOff", "Ranking V3 OFF"},
    {"results.add", "+ Add"},
    {"results.listMarker", "LIST"},
    {"results.nearPrefix", "Near "},
    {"results.nearUnnamed", "an address in the List"},
    {"results.alreadyInList", "This result is already in the List"},
    {"results.showingPrefix", "Showing "},
    {"results.showingMiddle", " of "},
    {"results.showingSuffix", ". Keep refining to reduce the list."},
    {"common.unavailable", "unavailable"},
    {"watch.title", "Address list"},
    {"watch.freeze", "Freeze"},
    {"watch.name", "Name"},
    {"watch.address", "Address"},
    {"watch.type", "Type"},
    {"watch.scanValue", "Scan value"},
    {"watch.currentNew", "Current / new"},
    {"watch.actions", "Actions"},
    {"watch.saveValue", "Save value"},
    {"watch.openPointers", "Open Pointers"},
    {"watch.remove", "Remove from list"},
    {"watch.subtitle", "Persists across scans. Name and Current are editable; freeze with the checkbox."},
    {"watch.clear", "Clear"},
    {"watch.empty", "Add a result when you want to track, edit, or freeze an address."},
    {"pointers.title", "Pointers"},
    {"pointers.savedProfile", "Saved pointer profile"},
    {"pointers.saveProfile", "Save .cwptr"},
    {"pointers.loadProfile", "Load .cwptr"},
    {"pointers.search", "Search pointers"},
    {"pointers.rescan", "Rescan chains"},
    {"pointers.cardHint", "Find a stable chain for the selected address."},
    {"pointers.target", "TARGET"},
    {"pointers.noTarget", "No address selected"},
    {"pointers.useSelected", "Use selected address"},
    {"pointers.searchIntensity", "SEARCH INTENSITY"},
    {"pointers.fast", "Fast"},
    {"pointers.balanced", "Balanced"},
    {"pointers.deep", "Deep"},
    {"pointers.rootTitle", "CHAIN ROOT"},
    {"pointers.rootPrefix", "Root: "},
    {"pointers.anyModule", "any module"},
    {"pointers.mainProcess", "main process"},
    {"pointers.clearChains", "Clear chains"},
    {"pointers.addResolved", "Add resolved to List"},
    {"pointers.profileLabel", "POINTER PROFILE"},
    {"pointers.profileHelpLoaded", "1 .cwptr profile represents ONE value and may contain multiple redundant chains.\n\nDouble-click any chain to open its resolved address in the Scanner List for editing or freezing.\n\nIn Trainer you can add multiple profiles (.cwptr), one for each value."},
    {"pointers.profileHelpEmpty", "Load a .cwptr profile (or legacy .mcptr) to restore a value's chains. Then resolve it, check Current Value, and double-click a chain to open it in Scanner."},
    {"pointers.resultsTitle", "Pointer chains"},
    {"pointers.empty", "No pointer chains yet"},
    {"pointers.currentPrefix", "current: "},
    {"pointers.stateTarget", "CURRENT TARGET"},
    {"pointers.stateUnavailable", "unavailable"},
    {"pointers.stateChecking", "checking"},
    {"pointers.attachBeforeSearch", "Attach to a process before searching for pointers."},
    {"pointers.chooseTarget", "Choose an address from the Address List as the target."},
    {"pointers.noChainsRescan", "There are no chains to rescan. Run a search first."},
    {"pointers.rescanning", "Rescanning chains at the current address..."},
    {"pointers.buildingIndex", "Building a valid pointer index and searching for chains..."},
    {"pointers.threadFailed", "Could not start the pointer scan thread."},
    {"pointers.cleared", "Pointer chains cleared."},
    {"pointers.cancelRequested", "Cancellation requested; finishing the current stage..."},
    {"pointers.fastStatus", "Fast Search: depth 3 and smaller offsets."},
    {"pointers.balancedStatus", "Balanced Search selected."},
    {"pointers.deepStatus", "Deep Search: uses layer-directed search without a huge index."},
    {"pointers.rootAnyStatus", "Root allowed in any module."},
    {"pointers.rootMainStatus", "Preferred root: main module. If it returns 0, the search automatically tries all modules."},
    {"pointers.fastDesc", "Depth 3 | offset 0x400 | 3M index"},
    {"pointers.balancedDesc", "Depth 4 | offset 0x1000 | 5M index"},
    {"pointers.deepDesc", "Depth 6 | offset 0x4000 | directed search"},
    {"pointers.colBase", "Base"},
    {"pointers.colOffsets", "Offsets"},
    {"pointers.colResolved", "Resolved"},
    {"pointers.colCurrent", "Current value"},
    {"pointers.colStatus", "Status"},
    {"pointers.phaseIndexingPrefix", "Indexing/sorting memory: "},
    {"pointers.phaseCandidatesSuffix", " candidate pointers"},
    {"pointers.phaseFallbackPrefix", "Fallback in all modules: "},
    {"pointers.phaseSearchingPrefix", "Searching chains: "},
    {"pointers.phaseStepsSuffix", " steps"},
    {"pointers.phaseRescanning", "Rescanning chains..."},
    {"pointers.summaryChainsSuffix", " chain(s)"},
    {"pointers.summaryLimitReached", " [limit reached]"},
    {"pointers.summaryRestartRescan", ". Restart the process, find the new address, and use Rescan."},
    {"pointers.summaryTargetedPrefix", "0 chains | directed search up to level "},
    {"pointers.summaryMatches", " | matches "},
    {"pointers.summaryFrontierLimited", " [frontier limited]"},
    {"pointers.summaryTriedAllModules", " | tried all modules"},
    {"pointers.summaryIndexPrefix", "0 chains | index "},
    {"pointers.summaryPartial", " [PARTIAL]"},
    {"pointers.summaryDirectParents", " | direct parents "},
    {"pointers.summaryEmpty", "Found chains appear here and are resolved against the current process."},
    {"pointers.busyIndexingPrefix", "Indexing memory. Candidates: "},
    {"pointers.busyIndexingSuffix", "\nThen Cheat Wizard searches for chains."},
    {"pointers.busyFallbackStepsPrefix", "Trying any module. Steps: "},
    {"pointers.busySearchingStepsPrefix", "Searching chains. Steps: "},
    {"pointers.busyBoundedHint", "\nThe search is bounded and always terminates; you can cancel."},
    {"pointers.busyDirectedAnyPrefix", "Directed search in any module. Level "},
    {"pointers.busyDirectedLayersPrefix", "Layered directed search. Level "},
    {"pointers.busyFrontier", " | frontier "},
    {"pointers.busySlotsRead", "\nSlots read: "},
    {"pointers.busyMatches", " | matches: "},
    {"pointers.busyCancelHint", ". You can cancel at any time."},
    {"pointers.busyRescanning", "Rescanning existing chains..."},
    {"pointers.emptyTargetedTruncated", "Directed search hit the frontier limit. There are many paths; reduce offsets or use AOB to locate the structure."},
    {"pointers.emptyTargetedNoRoot", "The search found references between layers, but none reached a static module root. The target may use handles/runtime or a chain outside the current limits."},
    {"pointers.emptyTargetedNoRefs", "Directed search found no references to the target within the selected offsets. Consider AOB/structure instead of increasing limits indefinitely."},
    {"pointers.emptyPartialIndex", "No chain found with the partial index. The GUI automatically switches to directed search when this index is insufficient."},
    {"pointers.emptyNoStaticRoot", "There are pointers near the target, but no chain reached a module. The search already tried all modules automatically."},
    {"pointers.emptyNoNearbyPointer", "No indexed pointer points near the target. This value may not have a classic pointer chain, or it may require wider offsets/alignment."},
    {"pointers.selectAddressFirst", "Select an address in the Address List first."},
    {"pointers.targetChangedRescan", "New address selected. Use Rescan to eliminate unstable chains."},
    {"pointers.targetSetSearch", "Address selected as target. Click Search pointers."},
    {"pointers.saveNeedChains", "Find and validate chains before saving."},
    {"pointers.profileSavedPrefix", "Profile saved with "},
    {"pointers.profileSavedSuffix", " chain(s). Use this .cwptr to open the value without a new scan."},
    {"pointers.saveFailed", "Failed to save the pointer profile."},
    {"pointers.loadInvalid", "Invalid, corrupted, or incompatible .cwptr/.mcptr file for the attached process."},
    {"pointers.profileLoadedPrefix", "Profile loaded: "},
    {"pointers.profileLoadedConsensus", " chain(s); consensus "},
    {"pointers.profileLoadedSame", " at the same address."},
    {"pointers.profileLoadedAmbiguous", " - AMBIGUOUS, do not use Write/Freeze."},
    {"pointers.profileLoadedAttach", "Profile loaded. Attach to the correct process to resolve the chains."},
    {"pointers.needProfile", "Load or find a pointer set first."},
    {"pointers.invalidProfileType", "The profile does not contain a usable numeric type."},
    {"pointers.noResolvedChain", "No chain from the profile resolved in the current process."},
    {"pointers.ambiguousProfile", "Ambiguous profile: no majority of chains agree on the same address."},
    {"pointers.resolvedAlreadyListed", "The resolved address is already in the Address List."},
    {"pointers.addedPrefix", "Pointer added: "},
    {"pointers.addedSuffix", " chain(s) agree on the current address."},
    {"pointers.chainUnavailable", "This chain is not available."},
    {"pointers.chainResolveFailed", "This chain did not resolve in the current process."},
    {"pointers.chainAlreadySelected", "This address was already in the List; it was selected."},
    {"pointers.chainPrefix", "Chain #"},
    {"pointers.chainAddedSuffix", " added to the Address List for editing/freezing."},
    {"pointers.cancelled", "Pointer search cancelled. Partial results were discarded when necessary."},
    {"pointers.rescanFailed", "Rescan failed. Check target and process width."},
    {"pointers.scanFailed", "Pointer scan failed or did not find a usable index."},
    {"pointers.rescanDonePrefix", "Rescan complete: "},
    {"pointers.stableChainsSuffix", " stable chain(s)."},
    {"pointers.scanDonePrefix", "Pointer scan: "},
    {"pointers.chainsSuffix", " chain(s)"},
    {"pointers.targetedLevel", " | directed search level "},
    {"pointers.matches", " | matches "},
    {"pointers.frontierLimited", " | frontier limited"},
    {"pointers.indexPrefix", ", index "},
    {"pointers.partial", " [PARTIAL]"},
    {"pointers.targetParents", ", target parents "},
    {"pointers.budgetHit", " | work limit reached"},
    {"pointers.searchLimited", " | branching/result limited"},
    {"pointers.fallbackModules", " | fallback: all modules"},
    {"dialog.filePickerFailed", "Could not open the file picker."},
    {"dialog.fileDialogUnavailable", "File dialog is unavailable on this Windows version."},
    {"dialog.pointerSaveTitle", "Save stable pointer profile"},
    {"dialog.pointerLoadTitle", "Load saved pointer profile"},
    {"dialog.pointerProfiles", "Cheat Wizard Pointer Profiles (*.cwptr;*.mcptr)"},
    {"dialog.legacyPointerProfile", "Legacy MiniCE Pointer Profile (*.mcptr)"},
    {"dialog.windowsIcon", "Windows icon (*.ico)"},
    {"dialog.images", "Images (*.png;*.jpg;*.jpeg;*.bmp;*.gif)"},
    {"dialog.allFiles", "All files (*.*)"},
    {"results.rankingEnabledNear", "Ranking V3 enabled. Proximity to addresses in the List now contributes to the score and appears in the table; no result was discarded."},
    {"results.rankingEnabledBase", "Ranking V3 enabled. Region, type, value, target, and isolation order the display; add an address to the List to enable proximity."},
    {"results.rankingDisabled", "Ranking disabled. Original address/type order restored."},
    {"watch.cleared", "Address List cleared."},
    {"status.unknownReadyPrefix", "Unknown ready to refine: "},
    {"status.unknownReadyMiddle", " candidates  |  "},
    {"status.unknownReadySuffix", " MiB temporary. Use the Wizard."},
    {"status.scanDonePrefix", "Scan complete: "},
    {"status.scanDoneSuffix", " results."},
    {"status.scanFailed", "The scan failed. Check process, type, value, and temporary disk space."},
    {"status.closePointerBusy", "Cancel or wait for the pointer scan to finish before closing."},
    {"status.closeScanBusy", "Wait for the scan to finish before closing Cheat Wizard."},
    {"trainer.configuration", "Configuration"},
    {"trainer.visual", "Visual"},
    {"trainer.name", "Trainer name"},
    {"trainer.process", "Target process"},
    {"trainer.addProfile", "Add .cwptr"},
    {"trainer.build", "Build Trainer"},
    {"trainer.saveProject", "Save project"},
    {"trainer.icon", "Icon"},
    {"trainer.convertIcon", "Convert image to .ico"},
    {"trainer.cardHint", "Build the final screen using ordered blocks."},
    {"trainer.changeIcon", "Change .ico file"},
    {"trainer.chooseIcon", "Choose .ico file"},
    {"trainer.iconPrefix", "Icon: "},
    {"trainer.colorHint", "Click a color square to open the picker."},
    {"trainer.colorBackground", "BACKGROUND"},
    {"trainer.colorPanel", "PANEL"},
    {"trainer.colorSurface", "INPUT / SURFACE"},
    {"trainer.colorAccent", "ACCENT"},
    {"trainer.colorText", "TEXT"},
    {"trainer.colorMuted", "SECONDARY TEXT"},
    {"trainer.previewTitle", "Trainer preview"},
    {"trainer.previewVisualHint", "Same order and structure as the generated executable."},
    {"trainer.previewEditHint", "Click a block to edit it. Use the mouse wheel to scroll."},
    {"trainer.processFromFirst", "Defined by the first .cwptr field"},
    {"trainer.addElement", "ADD ELEMENT"},
    {"trainer.addTitle", "+ Title"},
    {"trainer.addSubtitle", "+ Subtitle"},
    {"trainer.addCurrent", "+ Current profile field"},
    {"trainer.elementSingular", " element  |  "},
    {"trainer.elementPlural", " elements  |  "},
    {"trainer.fieldSingular", " field"},
    {"trainer.fieldPlural", " fields"},
    {"trainer.selectionHint", "Select a block in the preview to edit properties or change its order."},
    {"trainer.displayName", "DISPLAY NAME"},
    {"trainer.defaultValue", "DEFAULT VALUE"},
    {"trainer.showValueYes", "Show value: YES"},
    {"trainer.showValueNo", "Show value: NO"},
    {"trainer.allowEditYes", "Allow edit: YES"},
    {"trainer.allowEditNo", "Allow edit: NO"},
    {"trainer.freezeYes", "Freeze: YES"},
    {"trainer.freezeNo", "Freeze: NO"},
    {"trainer.titleText", "TITLE TEXT"},
    {"trainer.subtitleText", "SUBTITLE TEXT"},
    {"trainer.textHint", "This text appears directly in the final form."},
    {"trainer.moveUp", "Move up"},
    {"trainer.moveDown", "Move down"},
    {"trainer.remove", "Remove"},
    {"trainer.selectElement", "Select an element in the preview to see its properties."},
    {"trainer.previewEmpty", "Add a title, subtitle, or .cwptr field to build the form."},
    {"trainer.connectedPrefix", "Connected to "},
    {"trainer.elementPrefix", "Element "},
    {"trainer.currentValuePrefix", "Current value: "},
    {"trainer.currentHidden", "Current value: hidden"},
    {"trainer.consensusPrefix", "   |   consensus "},
    {"trainer.apply", "Apply"},
    {"trainer.selectProfileFile", "Select a .cwptr or legacy .mcptr file."},
    {"trainer.entryLimit", "The Trainer project reached the entry limit."},
    {"trainer.invalidProfile", "This is not a valid .cwptr/.mcptr file."},
    {"trainer.profileNoProcess", "The profile has no target process."},
    {"trainer.profileOtherProcess", "This profile belongs to another process. A trainer uses a single target process."},
    {"trainer.profileAlreadyAdded", "This profile is already in the Trainer form."},
    {"trainer.elementLimit", "The Trainer form reached the element limit."},
    {"trainer.fieldAddedPrefix", "Field added to form: "},
    {"trainer.chainCountSuffix", " chain(s)."},
    {"trainer.saveOrLoadProfile", "Save or load a .cwptr in the Pointers tab first."},
    {"trainer.newTitle", "New title"},
    {"trainer.newSubtitle", "New subtitle"},
    {"trainer.titleAdded", "Title added to the form."},
    {"trainer.subtitleAdded", "Subtitle added to the form."},
    {"trainer.movedUp", "Element moved up."},
    {"trainer.movedDown", "Element moved down."},
    {"trainer.elementRemoved", "Element removed from the form."},
    {"trainer.colorUnavailable", "Color picker is unavailable on this Windows version."},
    {"trainer.colorUpdated", "Color updated in the Trainer preview."},
    {"trainer.iconSelected", "Icon selected. trainer-builder applies the .ico to the final EXE."},
    {"trainer.imagePickerFailed", "Could not open the image picker."},
    {"trainer.iconSaveDialogFailed", "Could not open the dialog to save the icon."},
    {"trainer.convertingImage", "Converting image to a multi-size icon..."},
    {"trainer.convertFailed", "Failed to convert the image. Try a valid PNG, JPEG, BMP, or GIF."},
    {"trainer.converted", "Image converted to a multi-size .ico and applied to the Trainer."},
    {"trainer.saveNeedsProfile", "Add at least one .cwptr to the Trainer project."},
    {"trainer.projectSavedPrefix", "Project saved. Run: cw-trainer-builder.exe build \""},
    {"trainer.projectSavedSuffix", "\" -o MyTrainer.exe"},
    {"trainer.projectSaveFailed", "Failed to save the .cwtrainer project."},
    {"dialog.iconPickTitle", "Choose Trainer icon"},
    {"dialog.imagePickTitle", "Choose image to convert to an icon"},
    {"dialog.iconSaveTitle", "Save converted icon"},
    {"dialog.trainerSaveTitle", "Save Trainer project"},
    {"process.searchPlaceholder", "Search process or PID..."},
    {"process.none", "No process found."},
    {"process.of", " of "},
    {"process.singular", " process"},
    {"process.plural", " processes"},
    {"dialog.pointerProfile", "Cheat Wizard Pointer Profile (*.cwptr)"},
    {"dialog.trainerProject", "Cheat Wizard Trainer Project (*.cwtrainer)"},
    {"locale.label", "Language"},
    {"locale.enUS", "English"},
    {"locale.ptBR", "Portuguese (Brazil)"}
};
static constexpr usize UI_LOCALE_DEF_COUNT = sizeof(g_uiLocaleDefs)/sizeof(g_uiLocaleDefs[0]);
static constexpr usize UI_LOCALE_VALUE_CAP = 384;
static char g_uiLocaleValues[UI_LOCALE_DEF_COUNT][UI_LOCALE_VALUE_CAP]{};
static constexpr int UI_LOCALE_CHOICE_LIMIT = 32;
struct UiLocaleChoice_ { char code[32]; };
static UiLocaleChoice_ g_uiLocaleChoices[UI_LOCALE_CHOICE_LIMIT]{};
static int g_uiLocaleChoiceCount = 0;
static int g_uiLocaleIndex = 0;
static char g_uiExeDir[520]{};
static wchar_t g_uiWideScratch[2048]{};
static wchar_t g_uiWideTitle[512]{};

static int ui_locale_def_index(const char* key){for(usize i=0;i<UI_LOCALE_DEF_COUNT;++i)if(streq(g_uiLocaleDefs[i].key,key))return (int)i;return -1;}
static const char* ui_tr(const char* key){int i=ui_locale_def_index(key);if(i<0)return key?key:"";return g_uiLocaleValues[i][0]?g_uiLocaleValues[i]:g_uiLocaleDefs[i].fallback;}
static int ui_locale_choice_index(const char* code){for(int i=0;i<g_uiLocaleChoiceCount;++i)if(strieq(g_uiLocaleChoices[i].code,code))return i;return -1;}
static bool ui_locale_code_valid(const char* code){if(!code||!*code)return false;usize n=0;for(;code[n];++n){char c=code[n];if(n>=31||!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return false;}return n>0;}
static void ui_locale_add_choice(const char* code){if(!ui_locale_code_valid(code)||g_uiLocaleChoiceCount>=UI_LOCALE_CHOICE_LIMIT||ui_locale_choice_index(code)>=0)return;strcopy(g_uiLocaleChoices[g_uiLocaleChoiceCount].code,sizeof(g_uiLocaleChoices[g_uiLocaleChoiceCount].code),code);++g_uiLocaleChoiceCount;}
static bool ui_utf8_to_wide(const char* text,wchar_t* out,int cap){if(!out||cap<=0)return false;out[0]=0;if(!text)return true;int n=MultiByteToWideChar(CP_UTF8_,MB_ERR_INVALID_CHARS_,text,-1,out,cap);if(n>0)return true;out[0]=0;return false;}
static void ui_set_localized_window_title(){if(!g_hwnd)return;if(ui_utf8_to_wide(ui_tr("app.windowTitle"),g_uiWideTitle,(int)(sizeof(g_uiWideTitle)/sizeof(g_uiWideTitle[0]))))SetWindowTextW(g_hwnd,g_uiWideTitle);}
static void ui_locale_reset_overrides(){memzero(g_uiLocaleValues,sizeof(g_uiLocaleValues));}
static bool ui_path_join(char* out,usize cap,const char* a,const char* b){if(!out||!cap||!a||!b)return false;usize n=0;while(*a&&n+1<cap)out[n++]=*a++;if(n&&out[n-1]!='\\'&&out[n-1]!='/'){if(n+1>=cap)return false;out[n++]='\\';}while(*b&&n+1<cap)out[n++]=*b++;if(*b)return false;out[n]=0;return true;}
static bool ui_locale_init_exe_dir(){char path[520]{};DWORD n=GetModuleFileNameA(nullptr,path,(DWORD)sizeof(path));if(!n||n>=sizeof(path))return false;usize cut=n;while(cut&&path[cut-1]!='\\'&&path[cut-1]!='/')--cut;if(!cut){strcopy(g_uiExeDir,sizeof(g_uiExeDir),".");return true;}path[cut-1]=0;strcopy(g_uiExeDir,sizeof(g_uiExeDir),path);return g_uiExeDir[0]!=0;}
static void ui_locale_discover_choices(){g_uiLocaleChoiceCount=0;ui_locale_add_choice("en-US");ui_locale_add_choice("pt-BR");if(!g_uiExeDir[0]&&!ui_locale_init_exe_dir())return;char pattern[640]{};if(!ui_path_join(pattern,sizeof(pattern),g_uiExeDir,"locales\\*.json"))return;WIN32_FIND_DATAA_ fd{};HANDLE find=FindFirstFileA(pattern,&fd);if((uptr)find==INVALID_HANDLE_BITS)return;do{if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY_)continue;usize len=cstrlen(fd.cFileName);if(len<=5||len>=36)continue;const char* ext=fd.cFileName+len-5;if(ext[0]!='.'||ascii_lower(ext[1])!='j'||ascii_lower(ext[2])!='s'||ascii_lower(ext[3])!='o'||ascii_lower(ext[4])!='n')continue;usize codeLen=len-5;if(codeLen>=32)continue;char code[32]{};for(usize i=0;i<codeLen;++i)code[i]=fd.cFileName[i];code[codeLen]=0;ui_locale_add_choice(code);}while(FindNextFileA(find,&fd));FindClose(find);}
static bool ui_read_text_file(const char* path,char*& data,usize& size){data=nullptr;size=0;HANDLE h=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ_,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS)return false;DWORD sz=GetFileSize(h,nullptr);if(sz==0xFFFFFFFFUL||sz>256u*1024u){CloseHandle(h);return false;}char* p=(char*)HeapAlloc(g_heap,0,(SIZE_T)sz+1);if(!p){CloseHandle(h);return false;}DWORD done=0;while(done<sz){DWORD got=0;if(!ReadFile(h,p+done,sz-done,&got,nullptr)||!got){HeapFree(g_heap,0,p);CloseHandle(h);return false;}done+=got;}CloseHandle(h);p[sz]=0;data=p;size=sz;return true;}
static void ui_json_skip_ws(const char*& p,const char* e){while(p<e&&(*p==' '||*p=='\t'||*p=='\r'||*p=='\n'))++p;}
static bool ui_json_emit_utf8(char* out,usize cap,usize& n,u32 cp){if(cp>0x10FFFFu||(cp>=0xD800u&&cp<=0xDFFFu))return false;u8 bytes[4]{};int count=0;if(cp<=0x7Fu){bytes[0]=(u8)cp;count=1;}else if(cp<=0x7FFu){bytes[0]=(u8)(0xC0u|(cp>>6));bytes[1]=(u8)(0x80u|(cp&0x3Fu));count=2;}else if(cp<=0xFFFFu){bytes[0]=(u8)(0xE0u|(cp>>12));bytes[1]=(u8)(0x80u|((cp>>6)&0x3Fu));bytes[2]=(u8)(0x80u|(cp&0x3Fu));count=3;}else{bytes[0]=(u8)(0xF0u|(cp>>18));bytes[1]=(u8)(0x80u|((cp>>12)&0x3Fu));bytes[2]=(u8)(0x80u|((cp>>6)&0x3Fu));bytes[3]=(u8)(0x80u|(cp&0x3Fu));count=4;}if(n+(usize)count>=cap)return false;for(int i=0;i<count;++i)out[n++]=(char)bytes[i];return true;}
static bool ui_json_hex4(const char*& p,const char* e,u32& value){if(e-p<4)return false;value=0;for(int i=0;i<4;++i){int h=hex_nibble(*p++);if(h<0)return false;value=(value<<4)|(u32)h;}return true;}
static bool ui_json_string(const char*& p,const char* e,char* out,usize cap){if(p>=e||*p!='\"'||!out||cap==0)return false;++p;usize n=0;while(p<e){u8 c=(u8)*p++;if(c=='\"'){out[n]=0;return true;}if(c<0x20)return false;if(c!='\\'){if(n+1>=cap)return false;out[n++]=(char)c;continue;}if(p>=e)return false;char esc=*p++;if(esc=='\"'||esc=='\\'||esc=='/'){if(n+1>=cap)return false;out[n++]=esc;}else if(esc=='b'||esc=='f'||esc=='n'||esc=='r'||esc=='t'){char mapped=esc=='b'?8:(esc=='f'?12:(esc=='n'?'\n':(esc=='r'?'\r':'\t')));if(n+1>=cap)return false;out[n++]=mapped;}else if(esc=='u'){u32 cp=0;if(!ui_json_hex4(p,e,cp))return false;if(cp>=0xD800u&&cp<=0xDBFFu){if(e-p<6||p[0]!='\\'||p[1]!='u')return false;p+=2;u32 low=0;if(!ui_json_hex4(p,e,low)||low<0xDC00u||low>0xDFFFu)return false;cp=0x10000u+((cp-0xD800u)<<10)+(low-0xDC00u);}else if(cp>=0xDC00u&&cp<=0xDFFFu)return false;if(!ui_json_emit_utf8(out,cap,n,cp))return false;}else return false;}return false;}
using UiJsonPairFn_ = bool (*)(const char*,const char*,void*);
static bool ui_json_flat_object(const char* data,usize size,UiJsonPairFn_ pair,void* ctx){if(!data)return false;const char* p=data;const char* e=data+size;if(size>=3&&(u8)p[0]==0xEFu&&(u8)p[1]==0xBBu&&(u8)p[2]==0xBFu)p+=3;ui_json_skip_ws(p,e);if(p>=e||*p!='{')return false;++p;ui_json_skip_ws(p,e);if(p<e&&*p=='}'){++p;ui_json_skip_ws(p,e);return p==e;}for(;;){char key[128]{};char value[UI_LOCALE_VALUE_CAP]{};if(!ui_json_string(p,e,key,sizeof(key)))return false;ui_json_skip_ws(p,e);if(p>=e||*p!=':')return false;++p;ui_json_skip_ws(p,e);if(!ui_json_string(p,e,value,sizeof(value)))return false;if(pair&&!pair(key,value,ctx))return false;ui_json_skip_ws(p,e);if(p>=e)return false;if(*p=='}'){++p;ui_json_skip_ws(p,e);return p==e;}if(*p!=',')return false;++p;ui_json_skip_ws(p,e);}}
struct UiLocaleParseCtx_ { char* values; char metaCode[32]; };
static bool ui_locale_json_pair(const char* key,const char* value,void* raw){UiLocaleParseCtx_* ctx=(UiLocaleParseCtx_*)raw;if(streq(key,"_meta.code"))strcopy(ctx->metaCode,sizeof(ctx->metaCode),value);int idx=ui_locale_def_index(key);if(idx>=0)strcopy(ctx->values+(usize)idx*UI_LOCALE_VALUE_CAP,UI_LOCALE_VALUE_CAP,value);return true;}
static bool ui_locale_load_external(const char* code){ui_locale_reset_overrides();if(!g_uiExeDir[0]&&!ui_locale_init_exe_dir())return false;char rel[96]{};usize rn=0;append_str(rel,sizeof(rel),rn,"locales\\");append_str(rel,sizeof(rel),rn,code);append_str(rel,sizeof(rel),rn,".json");rel[rn]=0;char path[640]{};if(!ui_path_join(path,sizeof(path),g_uiExeDir,rel))return false;char* data=nullptr;usize size=0;if(!ui_read_text_file(path,data,size))return false;char* temp=(char*)HeapAlloc(g_heap,0,UI_LOCALE_DEF_COUNT*UI_LOCALE_VALUE_CAP);if(!temp){HeapFree(g_heap,0,data);return false;}memzero(temp,UI_LOCALE_DEF_COUNT*UI_LOCALE_VALUE_CAP);UiLocaleParseCtx_ ctx{temp,{}};bool ok=ui_json_flat_object(data,size,ui_locale_json_pair,&ctx)&&ctx.metaCode[0]&&strieq(ctx.metaCode,code);if(ok)memcopy(g_uiLocaleValues,temp,UI_LOCALE_DEF_COUNT*UI_LOCALE_VALUE_CAP);HeapFree(g_heap,0,temp);HeapFree(g_heap,0,data);return ok;}
struct UiSettingsParseCtx_ { char locale[32]; };
static bool ui_settings_json_pair(const char* key,const char* value,void* raw){UiSettingsParseCtx_* ctx=(UiSettingsParseCtx_*)raw;if(streq(key,"locale"))strcopy(ctx->locale,sizeof(ctx->locale),value);return true;}
static int ui_locale_default_index(){u16 lang=GetUserDefaultUILanguage();return ((lang&0x03FFu)==0x16u)?ui_locale_choice_index("pt-BR"):ui_locale_choice_index("en-US");}
static bool ui_locale_load_settings_index(int& index){index=-1;if(!g_uiExeDir[0]&&!ui_locale_init_exe_dir())return false;char path[640]{};if(!ui_path_join(path,sizeof(path),g_uiExeDir,"cw-settings.json"))return false;char* data=nullptr;usize size=0;if(!ui_read_text_file(path,data,size))return false;UiSettingsParseCtx_ ctx{};bool ok=ui_json_flat_object(data,size,ui_settings_json_pair,&ctx);HeapFree(g_heap,0,data);if(!ok||!ctx.locale[0])return false;index=ui_locale_choice_index(ctx.locale);return index>=0;}
static bool ui_locale_save_settings(){if(!g_uiExeDir[0]&&!ui_locale_init_exe_dir())return false;char path[640]{};if(!ui_path_join(path,sizeof(path),g_uiExeDir,"cw-settings.json"))return false;HANDLE h=CreateFileA(path,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS)return false;char b[96]{};usize n=0;append_str(b,sizeof(b),n,"{ \"locale\": \"");append_str(b,sizeof(b),n,g_uiLocaleChoices[g_uiLocaleIndex].code);append_str(b,sizeof(b),n,"\" }\r\n");bool ok=file_write_all(h,b,n);CloseHandle(h);return ok;}
static void ui_locale_initialize(){ui_locale_init_exe_dir();ui_locale_discover_choices();int index=-1;if(!ui_locale_load_settings_index(index))index=ui_locale_default_index();if(index<0||index>=g_uiLocaleChoiceCount)index=0;g_uiLocaleIndex=index;ui_locale_load_external(g_uiLocaleChoices[g_uiLocaleIndex].code);}

struct UiTask_ {
    int kind; int scanType; ValueType type; char value[128];
    uptr pointerTarget; u64 pointerDepth; u64 pointerMaxOffset; u64 pointerMaxNegative; u64 pointerMaxChains; u64 pointerBranch; u64 pointerIndexLimit; u64 pointerAlignment; u64 pointerSearchBudget; bool pointerWritableOnly; bool pointerRootAny;
};
static UiTask_ g_uiTask{};

static void ui_set_status(const char* s,int kind=0){strcopy(g_uiStatus,sizeof(g_uiStatus),s?s:"");g_uiStatusKind=kind;if(g_hwnd)InvalidateRect(g_hwnd,nullptr,0);}
static void ui_select_locale(int index,bool persist,bool announce){if(index<0||index>=g_uiLocaleChoiceCount)return;g_uiLocaleIndex=index;bool loaded=ui_locale_load_external(g_uiLocaleChoices[index].code);if(persist)ui_locale_save_settings();ui_set_localized_window_title();if(announce)ui_set_status(loaded?ui_tr("status.localeChanged"):ui_tr("status.localeFallback"),loaded?1:2);if(g_hwnd)InvalidateRect(g_hwnd,nullptr,0);}
static void ui_fatal(const char* s){MessageBoxA(g_hwnd,s,ui_tr("app.name"),MB_OK_|MB_ICONERROR_);}

static const char* ui_scan_type_name(int i){
    switch(i){case 0:return ui_tr("scanner.exact");case 1:return ui_tr("scanner.unknown");case 2:return ui_tr("scanner.changed");case 3:return ui_tr("scanner.unchanged");case 4:return ui_tr("scanner.increased");case 5:return ui_tr("scanner.decreased");case 6:return ui_tr("scanner.biggerThan");case 7:return ui_tr("scanner.smallerThan");case 8:return ui_tr("scanner.unknown");default:return "?";}
}
static const char* ui_value_type_name(int i){
    static const char* names[]={"Byte","2 Bytes","4 Bytes","8 Bytes","Float","Double"};
    if(i==6)return ui_tr("scanner.allTypes");
    return (i>=0&&i<6)?names[i]:"?";
}
static ValueType ui_selected_type(){
    switch(g_uiValueType){case 0:return ValueType::Byte;case 1:return ValueType::Int16;case 2:return ValueType::Int32;case 3:return ValueType::Int64;case 4:return ValueType::Float;case 5:return ValueType::Double;case 6:return ValueType::Mixed;default:return ValueType::Invalid;}
}
static bool ui_scan_active(){return g_type!=ValueType::Invalid;}
static bool ui_unknown_flow_active(){return ui_scan_active()&&g_uiUnknownFlow;}
static bool ui_scan_mode_needs_value(int scanType){return scanType==0||scanType==6||scanType==7;}
static bool ui_scan_value_visible(){return ui_scan_mode_needs_value(g_uiScanType);}
static int ui_scan_popup_count(){return ui_scan_active()?7:3;}
static int ui_scan_popup_value(int row){
    static const int initialModes[3]={0,8,1};
    static const int refineModes[7]={0,2,3,4,5,6,7};
    int count=ui_scan_popup_count();if(row<0||row>=count)return -1;return ui_scan_active()?refineModes[row]:initialModes[row];
}
static const char* ui_active_type_label(){if(g_type==ValueType::Mixed)return ui_tr("scanner.allTypes");switch(g_type){case ValueType::Byte:return "Byte";case ValueType::Int16:return "2 Bytes";case ValueType::Int32:return "4 Bytes";case ValueType::Int64:return "8 Bytes";case ValueType::Float:return "Float";case ValueType::Double:return "Double";default:return "-";}}
static int ui_scan_type_from_next_mode(NextMode mode){switch(mode){case NextMode::Exact:return 0;case NextMode::Changed:return 2;case NextMode::Unchanged:return 3;case NextMode::Increased:return 4;case NextMode::Decreased:return 5;case NextMode::Bigger:return 6;case NextMode::Smaller:return 7;}return 2;}

static void ui_compute_layout(){
    RECT_ c{};GetClientRect(g_hwnd,&c);int w=(int)(c.right-c.left),h=(int)(c.bottom-c.top);g_ui.w=w;g_ui.h=h;
    const int m=18,gap=14,headerH=72,footerH=32;int bodyY=m+headerH+gap;int bodyBottom=h-m-footerH-gap;int bodyH=ui_maxi(500,bodyBottom-bodyY);
    int leftW=ui_clampi(w/4,300,340);int rightX=m+leftW+gap;int rightW=ui_maxi(620,w-m-rightX);
    g_ui.header={m,m,w-2*m,headerH};
    int tabW=92;g_ui.tabScanner={m+146,m+18,tabW,36};g_ui.tabPointers={m+146+tabW+8,m+18,tabW,36};g_ui.tabTrainer={m+146+(tabW+8)*2,m+18,tabW,36};
    int attachW=116,refreshW=120;g_ui.attach={w-m-attachW-14,m+18,attachW,36};g_ui.refresh={g_ui.attach.x-gap-refreshW,m+18,refreshW,36};
    int targetX=g_ui.tabTrainer.x+g_ui.tabTrainer.w+14;g_ui.target={targetX,m+16,ui_maxi(240,g_ui.refresh.x-gap-targetX),40};
    g_ui.scanCard={m,bodyY,leftW,bodyH};
    int sx=m+18,sw=leftW-36;int sy=bodyY+82;bool activeScan=ui_scan_active();bool unknownFlow=ui_unknown_flow_active();bool needsValue=ui_scan_value_visible();
    g_ui.scanValueBox={};g_ui.scanType={};g_ui.valueType={};g_ui.scanSummary={};g_ui.scanStats={};g_ui.scanHint={};g_ui.alignment={};g_ui.firstScan={};g_ui.nextScan={};g_ui.newScan={};g_ui.guideChanged={};g_ui.guideUnchanged={};g_ui.guideIncreased={};g_ui.guideDecreased={};g_ui.wizardGoal={};
    if(!activeScan){
        g_ui.scanType={sx,sy,sw,40};sy+=62;
        if(needsValue){g_ui.scanValueBox={sx,sy,sw,40};sy+=62;}
        g_ui.valueType={sx,sy,sw,40};sy+=56;g_ui.alignment={sx,sy,sw,34};sy+=52;g_ui.firstScan={sx,sy,sw,40};sy+=54;
        g_ui.scanHint={sx,sy,sw,72};
    }else{
        g_ui.scanSummary={sx,sy,sw,44};sy+=56;
        if(unknownFlow){
            int guideW=(sw-gap)/2;g_ui.wizardGoal={sx+sw-118,sy-2,118,24};sy+=26;g_ui.guideChanged={sx,sy,guideW,34};g_ui.guideUnchanged={sx+guideW+gap,sy,guideW,34};sy+=38;g_ui.guideIncreased={sx,sy,guideW,34};g_ui.guideDecreased={sx+guideW+gap,sy,guideW,34};sy+=44;g_ui.scanStats={sx,sy,sw,28};sy+=30;g_ui.scanHint={sx,sy,sw,72};sy+=96;
        }else{g_ui.scanStats={sx,sy,sw,28};sy+=36;g_ui.scanHint={sx,sy,sw,48};sy+=78;}
        g_ui.scanType={sx,sy,sw,40};if(needsValue){sy+=68;g_ui.scanValueBox={sx,sy,sw,40};sy+=52;}else sy+=52;int actionW=(sw-gap)/2;g_ui.nextScan={sx,sy,actionW,38};g_ui.newScan={sx+actionW+gap,sy,actionW,38};
    }
    int resultsH=ui_clampi((bodyH*52)/100,270,430);g_ui.resultCard={rightX,bodyY,rightW,resultsH};g_ui.watchCard={rightX,bodyY+resultsH+gap,rightW,bodyH-resultsH-gap};
    g_ui.addResult={rightX+rightW-168,bodyY+14,150,32};g_ui.rankToggle={g_ui.addResult.x-136,bodyY+14,124,32};g_ui.resultTable={rightX+16,bodyY+58,rightW-32,resultsH-74};
    g_ui.clearWatch={};if(g_uiWatchCount)g_ui.clearWatch={rightX+rightW-118,g_ui.watchCard.y+14,100,32};
    g_ui.watchTable={rightX+16,g_ui.watchCard.y+58,rightW-32,ui_maxi(66,g_ui.watchCard.h-70)};g_ui.watchNameBox={};g_ui.renameWatch={};g_ui.watchValueBox={};g_ui.writeValue={};g_ui.freezeValue={};g_ui.removeWatch={};g_ui.pointerFromWatch={};

    // Pointer workspace uses the same left/right grid, but the results card takes
    // the entire right column so the chain table stays readable.
    g_ui.pointerControlCard={m,bodyY,leftW,bodyH};
    int px=m+18,pw=leftW-36;g_ui.pointerTargetBox={px,bodyY+82,pw,54};g_ui.pointerUseSelected={px,bodyY+144,pw,32};
    int presetGap=8,presetW=(pw-presetGap*2)/3;g_ui.pointerPresetFast={px,bodyY+210,presetW,32};g_ui.pointerPresetBalanced={px+presetW+presetGap,bodyY+210,presetW,32};g_ui.pointerPresetDeep={px+(presetW+presetGap)*2,bodyY+210,presetW,32};
    g_ui.pointerRootToggle={px,bodyY+286,pw,34};g_ui.pointerStart={px,bodyY+334,pw,36};g_ui.pointerRescan={px,bodyY+380,(pw-gap)/2,34};g_ui.pointerClear={px+(pw-gap)/2+gap,bodyY+380,(pw-gap)/2,34};
    int profGap=8,profW=(pw-profGap)/2;g_ui.pointerSave={px,bodyY+424,profW,34};g_ui.pointerLoad={px+profW+profGap,bodyY+424,profW,34};g_ui.pointerAddWatch={px,bodyY+466,pw,34};g_ui.pointerCancel=g_ui.pointerStart;
    g_ui.pointerResultCard={rightX,bodyY,rightW,bodyH};g_ui.pointerTable={rightX+16,bodyY+92,rightW-32,bodyH-110};

    g_ui.trainerProjectCard={m,bodyY,leftW,bodyH};
    int tx=m+18,tw=leftW-36;int subW=(tw-gap)/2;g_ui.trainerSubConfig={tx,bodyY+62,subW,34};g_ui.trainerSubVisual={tx+subW+gap,bodyY+62,subW,34};
    g_ui.trainerTitleBox={tx,bodyY+126,tw,38};g_ui.trainerProcessBox={tx,bodyY+190,tw,38};
    int trainerBtnW=(tw-gap)/2;g_ui.trainerAddTitle={tx,bodyY+258,trainerBtnW,36};g_ui.trainerAddSubtitle={tx+trainerBtnW+gap,bodyY+258,trainerBtnW,36};g_ui.trainerAddProfile={tx,bodyY+304,tw,36};g_ui.trainerAddCurrent={tx,bodyY+350,tw,34};g_ui.trainerSaveJson={tx,bodyY+400,tw,38};
    g_ui.trainerEntryCard={rightX,bodyY,rightW,bodyH};g_ui.trainerTable={rightX+16,bodyY+68,rightW-32,ui_maxi(180,bodyH-245)};
    int ey=g_ui.trainerTable.y+g_ui.trainerTable.h+18;int half=(rightW-48)/2;g_ui.trainerLabelBox={rightX+16,ey,half,36};g_ui.trainerDefaultBox={rightX+32+half,ey,half,36};
    int ty=ey+46;int actionGap=8;int trainerActionW=(rightW-32-actionGap*2)/3;g_ui.trainerShowToggle={rightX+16,ty,trainerActionW,34};g_ui.trainerWriteToggle={rightX+16+trainerActionW+actionGap,ty,trainerActionW,34};g_ui.trainerFreezeToggle={rightX+16+(trainerActionW+actionGap)*2,ty,trainerActionW,34};
    int my=ty+42;int moveW=(rightW-32-actionGap*2)/3;g_ui.trainerMoveUp={rightX+16,my,moveW,34};g_ui.trainerMoveDown={rightX+16+moveW+actionGap,my,moveW,34};g_ui.trainerRemove={rightX+16+(moveW+actionGap)*2,my,moveW,34};
    g_ui.trainerIconButton={tx,bodyY+126,tw,38};g_ui.trainerIconConvert={tx,bodyY+172,tw,38};int colorGap=10,colorW=(tw-colorGap)/2;g_ui.trainerColorBg={tx,bodyY+234,colorW,36};g_ui.trainerColorPanel={tx+colorW+colorGap,bodyY+234,colorW,36};g_ui.trainerColorSurface={tx,bodyY+302,colorW,36};g_ui.trainerColorAccent={tx+colorW+colorGap,bodyY+302,colorW,36};g_ui.trainerColorText={tx,bodyY+370,colorW,36};g_ui.trainerColorMuted={tx+colorW+colorGap,bodyY+370,colorW,36};g_ui.trainerPreview={rightX+16,bodyY+68,rightW-32,bodyH-86};
    g_ui.footer={m,h-m-footerH,w-2*m,footerH};g_ui.locale={g_ui.footer.x+g_ui.footer.w-94,g_ui.footer.y+3,84,g_ui.footer.h-6};
}
static void ui_sync_edits(){
    // v1.7.0 uses fully custom drawn text fields. There are no child EDIT
    // windows to move/repaint, eliminating the one-second flash caused by the
    // parent refresh timer repainting underneath native controls.
    ui_compute_layout();
}

static void ui_text(HDC dc,const char* s,UiRect r,COLORREF c,HFONT f,UINT flags){RECT_ q=ui_rect(r);SetBkMode(dc,TRANSPARENT_);SetTextColor(dc,c);HGDIOBJ old=f?SelectObject(dc,(HGDIOBJ)f):nullptr;const char* text=s?s:"";if(ui_utf8_to_wide(text,g_uiWideScratch,(int)(sizeof(g_uiWideScratch)/sizeof(g_uiWideScratch[0]))))DrawTextW(dc,g_uiWideScratch,-1,&q,flags);else DrawTextA(dc,text,-1,&q,flags);if(old)SelectObject(dc,old);}
static void ui_round(HDC dc,UiRect r,HBRUSH br,HPEN pen,int radius=10){HGDIOBJ ob=SelectObject(dc,(HGDIOBJ)br);HGDIOBJ op=SelectObject(dc,(HGDIOBJ)(pen?pen:GetStockObject(NULL_PEN_)));RoundRect(dc,r.x,r.y,r.x+r.w,r.y+r.h,radius,radius);SelectObject(dc,ob);SelectObject(dc,op);}
static void ui_line(HDC dc,int x1,int y1,int x2,int y2,HPEN pen){HGDIOBJ op=SelectObject(dc,(HGDIOBJ)pen);MoveToEx(dc,x1,y1,nullptr);LineTo(dc,x2,y2);SelectObject(dc,op);}
static bool ui_hover(const UiRect& r){return ui_contains(r,g_uiMouseX,g_uiMouseY);}
static usize ui_text_len(const char* s){usize n=0;while(s&&s[n])++n;return n;}
static usize g_uiTextCursor=0;
static usize g_uiTextAnchor=0;
static bool ui_input_enabled(UiTextFocus_ which){
    if(g_uiBusy)return false;
    if(which==UI_TEXT_SCAN||which==UI_TEXT_TRAINER_TITLE||which==UI_TEXT_COLOR_BG||which==UI_TEXT_COLOR_PANEL||which==UI_TEXT_COLOR_SURFACE||which==UI_TEXT_COLOR_ACCENT||which==UI_TEXT_COLOR_TEXT||which==UI_TEXT_COLOR_MUTED)return true;
    if(which==UI_TEXT_PROCESS_FILTER)return !g_uiBusy&&g_uiPopup==UI_POP_PROCESS;
    if(which==UI_TEXT_TRAINER_LABEL)return g_uiTrainerElementSelected>=0&&g_uiTrainerElementSelected<g_uiTrainerElementCount;
    if(which==UI_TEXT_TRAINER_DEFAULT)return g_uiTrainerSelected>=0&&g_uiTrainerSelected<g_uiTrainerCount&&g_uiTrainerElementSelected>=0&&g_uiTrainerElementSelected<g_uiTrainerElementCount&&g_uiTrainerElements[g_uiTrainerElementSelected].type==UI_TRAINER_FIELD;
    if(which==UI_TEXT_WATCH_NAME)return g_uiSelectedWatch>=0&&g_uiSelectedWatch<(int)UI_WATCH_LIMIT&&g_uiWatches[g_uiSelectedWatch].active;
    return g_uiSelectedWatch>=0&&g_uiSelectedWatch<(int)UI_WATCH_LIMIT&&g_uiWatches[g_uiSelectedWatch].active;
}
static bool ui_text_buffer(UiTextFocus_ which,char*& buf,usize& cap,bool& freeText){
    buf=nullptr;cap=0;freeText=false;
    if(which==UI_TEXT_SCAN){buf=g_uiScanText;cap=sizeof(g_uiScanText);}
    else if(which==UI_TEXT_PROCESS_FILTER&&ui_input_enabled(UI_TEXT_PROCESS_FILTER)){buf=g_uiProcessFilter;cap=sizeof(g_uiProcessFilter);freeText=true;}
    else if(which==UI_TEXT_WATCH&&ui_input_enabled(UI_TEXT_WATCH)){buf=g_uiWatchText;cap=sizeof(g_uiWatchText);}
    else if(which==UI_TEXT_WATCH_NAME&&ui_input_enabled(UI_TEXT_WATCH_NAME)){buf=g_uiWatchNameText;cap=sizeof(g_uiWatchNameText);freeText=true;}
    else if(which==UI_TEXT_TRAINER_TITLE){buf=g_uiTrainerTitle;cap=sizeof(g_uiTrainerTitle);freeText=true;}
    else if(which==UI_TEXT_TRAINER_LABEL&&ui_input_enabled(UI_TEXT_TRAINER_LABEL)){if(g_uiTrainerElementSelected>=0&&g_uiTrainerElementSelected<g_uiTrainerElementCount&&g_uiTrainerElements[g_uiTrainerElementSelected].type!=UI_TRAINER_FIELD){buf=g_uiTrainerElementText;cap=sizeof(g_uiTrainerElementText);}else{buf=g_uiTrainerLabel;cap=sizeof(g_uiTrainerLabel);}freeText=true;}
    else if(which==UI_TEXT_TRAINER_DEFAULT&&ui_input_enabled(UI_TEXT_TRAINER_DEFAULT)){buf=g_uiTrainerDefault;cap=sizeof(g_uiTrainerDefault);}
    else if(which==UI_TEXT_COLOR_BG){buf=g_uiTrainerColorBg;cap=sizeof(g_uiTrainerColorBg);freeText=true;}
    else if(which==UI_TEXT_COLOR_PANEL){buf=g_uiTrainerColorPanel;cap=sizeof(g_uiTrainerColorPanel);freeText=true;}
    else if(which==UI_TEXT_COLOR_SURFACE){buf=g_uiTrainerColorSurface;cap=sizeof(g_uiTrainerColorSurface);freeText=true;}
    else if(which==UI_TEXT_COLOR_ACCENT){buf=g_uiTrainerColorAccent;cap=sizeof(g_uiTrainerColorAccent);freeText=true;}
    else if(which==UI_TEXT_COLOR_TEXT){buf=g_uiTrainerColorText;cap=sizeof(g_uiTrainerColorText);freeText=true;}
    else if(which==UI_TEXT_COLOR_MUTED){buf=g_uiTrainerColorMuted;cap=sizeof(g_uiTrainerColorMuted);freeText=true;}
    return buf&&cap;
}
static int ui_text_width(HDC dc,HFONT font,const char* text,usize count){
    if(!text||!count)return 0;SIZE_ sz{};HGDIOBJ old=font?SelectObject(dc,(HGDIOBJ)font):nullptr;BOOL ok=0;int wn=0;if(count<sizeof(g_uiWideScratch)/sizeof(g_uiWideScratch[0]))wn=MultiByteToWideChar(CP_UTF8_,MB_ERR_INVALID_CHARS_,text,(int)count,g_uiWideScratch,(int)(sizeof(g_uiWideScratch)/sizeof(g_uiWideScratch[0])));if(wn>0)ok=GetTextExtentPoint32W(dc,g_uiWideScratch,wn,&sz);else ok=GetTextExtentPoint32A(dc,text,(int)count,&sz);if(old)SelectObject(dc,old);return ok?(int)sz.cx:(int)count*8;
}
static usize ui_text_pos_from_x(HDC dc,HFONT font,const char* text,int localX){
    usize len=ui_text_len(text);if(localX<=0)return 0;for(usize i=1;i<=len;++i){int w=ui_text_width(dc,font,text,i);if(localX<w){int prev=ui_text_width(dc,font,text,i-1);return (localX-prev)<(w-localX)?i-1:i;}}return len;
}
static void ui_input(HDC dc,const UiRect& r,const char* text,UiTextFocus_ which,bool enabled,HFONT font=nullptr,int leftInset=12){
    bool focused=(g_uiTextFocus==which)&&enabled;HFONT f=font?font:g_font;leftInset=ui_clampi(leftInset,10,ui_maxi(10,r.w-20));
    ui_round(dc,r,enabled?g_brushSurface:g_brushPanel,focused?g_penAccent:g_penBorder,8);
    UiRect tx{r.x+leftInset,r.y,r.w-leftInset-12,r.h};usize len=ui_text_len(text);
    if(focused){
        if(g_uiTextCursor>len)g_uiTextCursor=len;if(g_uiTextAnchor>len)g_uiTextAnchor=len;
        usize a=g_uiTextCursor<g_uiTextAnchor?g_uiTextCursor:g_uiTextAnchor,b=g_uiTextCursor>g_uiTextAnchor?g_uiTextCursor:g_uiTextAnchor;
        if(a!=b){int x1=r.x+leftInset+ui_text_width(dc,f,text,a);int x2=r.x+leftInset+ui_text_width(dc,f,text,b);if(x2>x1){RECT_ sr{x1,r.y+6,ui_mini(x2,r.x+r.w-10),r.y+r.h-6};if(sr.right>sr.left)FillRect(dc,&sr,g_brushSelected);}}
    }
    ui_text(dc,text&&text[0]?text:"",tx,enabled?Z50:Z600,f,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
    if(focused){int caretX=r.x+leftInset+ui_text_width(dc,f,text,g_uiTextCursor);caretX=ui_clampi(caretX,r.x+leftInset,r.x+r.w-10);ui_line(dc,caretX,r.y+8,caretX,r.y+r.h-8,g_penAccent);}
}
static void ui_set_text_focus(UiTextFocus_ f){
    g_uiTextFocus=f;char* b=nullptr;usize cap=0;bool freeText=false;if(ui_text_buffer(f,b,cap,freeText)){g_uiTextCursor=ui_text_len(b);g_uiTextAnchor=g_uiTextCursor;}else g_uiTextCursor=g_uiTextAnchor=0;SetFocus(g_hwnd);InvalidateRect(g_hwnd,nullptr,0);
}
static void ui_set_text_focus_at(UiTextFocus_ f,const UiRect& r,int x,HFONT font,int leftInset=12){
    g_uiTextFocus=f;char* b=nullptr;usize cap=0;bool freeText=false;if(ui_text_buffer(f,b,cap,freeText)){HDC dc=CreateCompatibleDC(nullptr);g_uiTextCursor=ui_text_pos_from_x(dc,font?font:g_font,b,x-(r.x+leftInset));g_uiTextAnchor=g_uiTextCursor;DeleteDC(dc);}SetFocus(g_hwnd);InvalidateRect(g_hwnd,nullptr,0);
}
static void ui_select_all_text(UiTextFocus_ f){char* b=nullptr;usize cap=0;bool freeText=false;if(!ui_text_buffer(f,b,cap,freeText))return;g_uiTextAnchor=0;g_uiTextCursor=ui_text_len(b);InvalidateRect(g_hwnd,nullptr,0);}
static void ui_write_selected_watch();
static void ui_rename_selected_watch();
static void ui_attach_selected();
static bool ui_selected_is_attached();
static void ui_rebuild_process_filter();
static void ui_process_select_delta(int delta);
static void ui_start_scan(bool first);
static void ui_start_pointer_scan(bool rescan);
static void ui_pointer_reset_cache();
static void ui_pointer_refresh_visible_cache();
static bool ui_text_char_allowed(char c){
    return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')||c=='x'||c=='X'||c=='-'||c=='+'||c=='.'||c=='e'||c=='E';
}
static void ui_text_sync_model(){
    if(g_uiTextFocus==UI_TEXT_TRAINER_LABEL&&g_uiTrainerElementSelected>=0&&g_uiTrainerElementSelected<g_uiTrainerElementCount){UiTrainerElement_& el=g_uiTrainerElements[g_uiTrainerElementSelected];if(el.type==UI_TRAINER_FIELD){if(el.entryIndex>=0&&el.entryIndex<g_uiTrainerCount)strcopy(g_uiTrainerEntries[el.entryIndex].label,sizeof(g_uiTrainerEntries[el.entryIndex].label),g_uiTrainerLabel);}else strcopy(el.text,sizeof(el.text),g_uiTrainerElementText);}
    else if(g_uiTextFocus==UI_TEXT_TRAINER_DEFAULT&&g_uiTrainerSelected>=0&&g_uiTrainerSelected<g_uiTrainerCount)strcopy(g_uiTrainerEntries[g_uiTrainerSelected].defaultValue,sizeof(g_uiTrainerEntries[g_uiTrainerSelected].defaultValue),g_uiTrainerDefault);
}
static void ui_delete_text_selection(char* buf){
    usize len=ui_text_len(buf),a=g_uiTextCursor<g_uiTextAnchor?g_uiTextCursor:g_uiTextAnchor,b=g_uiTextCursor>g_uiTextAnchor?g_uiTextCursor:g_uiTextAnchor;if(a>len)a=len;if(b>len)b=len;if(a==b)return;usize tail=len-b;for(usize i=0;i<=tail;++i)buf[a+i]=buf[b+i];g_uiTextCursor=g_uiTextAnchor=a;
}
static void ui_text_insert(char* buf,usize cap,char c){
    ui_delete_text_selection(buf);usize len=ui_text_len(buf);if(len+1>=cap)return;if(g_uiTextCursor>len)g_uiTextCursor=len;for(usize i=len+1;i>g_uiTextCursor;--i)buf[i]=buf[i-1];buf[g_uiTextCursor]=c;++g_uiTextCursor;g_uiTextAnchor=g_uiTextCursor;
}
static void ui_text_input_char(char c){
    char* buf=nullptr;usize cap=0;bool freeText=false;if(!ui_text_buffer(g_uiTextFocus,buf,cap,freeText))return;usize n=ui_text_len(buf);bool processFilter=g_uiTextFocus==UI_TEXT_PROCESS_FILTER;
    if(c==8){if(g_uiTextCursor!=g_uiTextAnchor)ui_delete_text_selection(buf);else if(g_uiTextCursor){usize p=g_uiTextCursor-1;for(usize i=p;i<n;++i)buf[i]=buf[i+1];g_uiTextCursor=g_uiTextAnchor=p;}}
    else if(c==13){if(processFilter){if(g_uiProcessSelected>=0&&g_uiProcessSelected<g_uiProcessCount&&!ui_selected_is_attached())ui_attach_selected();g_uiPopup=UI_POP_NONE;g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;ui_sync_edits();InvalidateRect(g_hwnd,nullptr,0);return;}if(g_uiTextFocus==UI_TEXT_WATCH)ui_write_selected_watch();else if(g_uiTextFocus==UI_TEXT_WATCH_NAME)ui_rename_selected_watch();else if(g_uiTextFocus==UI_TEXT_SCAN&&g_process)ui_start_scan(g_type==ValueType::Invalid);}
    else if(((freeText&&(unsigned char)c>=32&&(unsigned char)c<127)||(!freeText&&ui_text_char_allowed(c))))ui_text_insert(buf,cap,c);
    if(processFilter)ui_rebuild_process_filter();else ui_text_sync_model();InvalidateRect(g_hwnd,nullptr,0);
}
static void ui_text_keydown(UINT key){
    bool processFilter=g_uiTextFocus==UI_TEXT_PROCESS_FILTER&&g_uiPopup==UI_POP_PROCESS;
    if(processFilter&&key==0x1B /* escape */){g_uiPopup=UI_POP_NONE;g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;ui_sync_edits();InvalidateRect(g_hwnd,nullptr,0);return;}
    if(processFilter&&key==0x26 /* up */){ui_process_select_delta(-1);return;}
    if(processFilter&&key==0x28 /* down */){ui_process_select_delta(1);return;}
    char* buf=nullptr;usize cap=0;bool freeText=false;if(!ui_text_buffer(g_uiTextFocus,buf,cap,freeText))return;usize len=ui_text_len(buf);bool ctrl=(GetKeyState(0x11)&0x8000)!=0;bool shift=(GetKeyState(0x10)&0x8000)!=0;
    if(ctrl&&(key=='A'||key=='a')){g_uiTextAnchor=0;g_uiTextCursor=len;InvalidateRect(g_hwnd,nullptr,0);return;}
    usize old=g_uiTextCursor;
    if(key==0x25 /* left */){if(!shift&&g_uiTextCursor!=g_uiTextAnchor){g_uiTextCursor=g_uiTextCursor<g_uiTextAnchor?g_uiTextCursor:g_uiTextAnchor;}else if(g_uiTextCursor) --g_uiTextCursor;}
    else if(key==0x27 /* right */){if(!shift&&g_uiTextCursor!=g_uiTextAnchor){g_uiTextCursor=g_uiTextCursor>g_uiTextAnchor?g_uiTextCursor:g_uiTextAnchor;}else if(g_uiTextCursor<len) ++g_uiTextCursor;}
    else if(key==0x24 /* home */)g_uiTextCursor=0;
    else if(key==0x23 /* end */)g_uiTextCursor=len;
    else if(key==0x2E /* delete */){if(g_uiTextCursor!=g_uiTextAnchor)ui_delete_text_selection(buf);else if(g_uiTextCursor<len){for(usize i=g_uiTextCursor;i<len;++i)buf[i]=buf[i+1];}if(processFilter)ui_rebuild_process_filter();else ui_text_sync_model();InvalidateRect(g_hwnd,nullptr,0);return;}
    else return;
    if(!shift)g_uiTextAnchor=g_uiTextCursor;else if(old==g_uiTextAnchor&&old==g_uiTextCursor)g_uiTextAnchor=old;InvalidateRect(g_hwnd,nullptr,0);
}

// Exact Pictogrammers Material Design Icons (MDI) v7.4.47 glyphs, Apache-2.0.
// The official @mdi/font is used only at development time to generate the alpha masks
// in MdiIconMasks.hpp. Cheat Wizard ships no icon font, SVG parser or external icon file.
enum UiIcon_ { UI_ICON_SEARCH=0, UI_ICON_REFRESH=1, UI_ICON_ATTACH=2, UI_ICON_CHECK=3, UI_ICON_FILE=4, UI_ICON_CONVERT=5, UI_ICON_DELETE=6, UI_ICON_POINTER=7, UI_ICON_SAVE=8 };
static const u8* ui_icon_mask(UiIcon_ icon){if(icon==UI_ICON_SEARCH)return MDI_MAGNIFY;if(icon==UI_ICON_REFRESH)return MDI_REFRESH;if(icon==UI_ICON_ATTACH)return MDI_CONNECTION;if(icon==UI_ICON_CHECK)return MDI_CHECK_CIRCLE_OUTLINE;if(icon==UI_ICON_FILE)return MDI_FILE_IMAGE_OUTLINE;if(icon==UI_ICON_DELETE)return MDI_TRASH_CAN_OUTLINE;if(icon==UI_ICON_POINTER)return MDI_SOURCE_BRANCH;if(icon==UI_ICON_SAVE)return MDI_CONTENT_SAVE_OUTLINE;return MDI_IMAGE_SYNC;}
static void ui_draw_mdi_mask(HDC dc,const u8* mask,int cx,int cy,int drawSize,COLORREF color,u8 opacity=255){
    if(!dc||!mask||drawSize<=0)return;BITMAPINFO_ bi{};bi.bmiHeader.biSize=(DWORD)sizeof(BITMAPINFOHEADER_);bi.bmiHeader.biWidth=MDI_ICON_MASK_SIZE;bi.bmiHeader.biHeight=-MDI_ICON_MASK_SIZE;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;bi.bmiHeader.biCompression=BI_RGB_;
    void* bits=nullptr;HBITMAP bmp=CreateDIBSection(dc,&bi,DIB_RGB_COLORS_,&bits,nullptr,0);if(!bmp||!bits){if(bmp)DeleteObject((HGDIOBJ)bmp);return;}u32* px=(u32*)bits;u32 cr=(u32)color;u32 r=cr&0xFFu,g=(cr>>8)&0xFFu,b=(cr>>16)&0xFFu;
    for(int i=0;i<MDI_ICON_MASK_SIZE*MDI_ICON_MASK_SIZE;++i){u32 a=mask[i];u32 rr=(r*a+127)/255,gg=(g*a+127)/255,bb=(b*a+127)/255;px[i]=bb|(gg<<8)|(rr<<16)|(a<<24);}HDC mem=CreateCompatibleDC(dc);if(mem){HGDIOBJ old=SelectObject(mem,(HGDIOBJ)bmp);BLENDFUNCTION_ bf{AC_SRC_OVER_,0,opacity,AC_SRC_ALPHA_};AlphaBlend(dc,cx-drawSize/2,cy-drawSize/2,drawSize,drawSize,mem,0,0,MDI_ICON_MASK_SIZE,MDI_ICON_MASK_SIZE,bf);SelectObject(mem,old);DeleteDC(mem);}DeleteObject((HGDIOBJ)bmp);
}
static void ui_draw_icon(HDC dc,UiIcon_ icon,int cx,int cy,COLORREF color,u8 opacity=255,int size=20){ui_draw_mdi_mask(dc,ui_icon_mask(icon),cx,cy,size,color,opacity);}
static void ui_draw_chevron(HDC dc,const UiRect& r,bool open,bool enabled){const u8* mask=open?MDI_CHEVRON_UP:MDI_CHEVRON_DOWN;ui_draw_mdi_mask(dc,mask,r.x+r.w/2,r.y+r.h/2,14,enabled?(open?BLUE300:Z300):Z600,255);}
static void ui_button(HDC dc,const UiRect& r,const char* label,bool primary=false,bool enabled=true){
    bool hov=enabled&&ui_hover(r);HBRUSH br=enabled?(primary?(hov?g_brushAccentHover:g_brushAccent):(hov?g_brushHover:g_brushSurface)):g_brushPanel;
    ui_round(dc,r,br,enabled?(primary?g_penAccent:g_penBorder):g_penBorder,8);
    ui_text(dc,label,r,enabled?Z50:Z600,g_fontBold,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);
}
static void ui_button_icon(HDC dc,const UiRect& r,const char* label,UiIcon_ icon,bool primary=false,bool enabled=true,bool success=false){
    bool hov=enabled&&ui_hover(r);HBRUSH br=enabled?(primary?(hov?g_brushAccentHover:g_brushAccent):(hov?g_brushHover:g_brushSurface)):g_brushPanel;ui_round(dc,r,br,enabled?(primary?g_penAccent:g_penBorder):g_penBorder,8);
    int textW=ui_text_width(dc,g_fontBold,label,ui_text_len(label));int iconSize=20;int gap=8;int innerPad=6;int total=iconSize+gap+textW;int start=r.x+(r.w-total)/2;if(start<r.x+innerPad)start=r.x+innerPad;COLORREF iconColor=!enabled?Z600:(success?GREEN400:(primary?Z50:(hov?Z100:Z300)));int saved=SaveDC(dc);IntersectClipRect(dc,r.x+1,r.y+1,r.x+r.w-1,r.y+r.h-1);ui_draw_icon(dc,icon,start+iconSize/2,r.y+r.h/2,iconColor,255,iconSize);int textX=start+iconSize+gap;UiRect tr{textX,r.y,ui_maxi(1,r.x+r.w-innerPad-textX),r.h};ui_text(dc,label,tr,enabled?Z50:Z600,g_fontBold,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);RestoreDC(dc,saved);
}
static void ui_icon_action_button(HDC dc,const UiRect& r,UiIcon_ icon,COLORREF hoverColor,bool enabled=true){bool hov=enabled&&ui_hover(r);ui_round(dc,r,enabled?(hov?g_brushHover:g_brushSurface):g_brushPanel,enabled?g_penBorder:nullptr,6);COLORREF c=!enabled?Z600:(hov?hoverColor:Z400);ui_draw_icon(dc,icon,r.x+r.w/2,r.y+r.h/2,c,255,18);}
static void ui_tooltip(HDC dc,const UiRect& anchor,const char* text){if(!ui_hover(anchor)||!text||!*text)return;int tw=ui_text_width(dc,g_fontSmall,text,ui_text_len(text));int w=ui_clampi(tw+20,72,190),h=28;int x=ui_clampi(anchor.x+anchor.w/2-w/2,8,ui_maxi(8,g_ui.w-w-8));int y=anchor.y-h-6;if(y<8)y=anchor.y+anchor.h+6;UiRect tip{x,y,w,h};ui_round(dc,tip,g_brushSurface,g_penStrong,6);ui_text(dc,text,{tip.x+8,tip.y,tip.w-16,tip.h},Z100,g_fontSmall,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);}
static void ui_field(HDC dc,const UiRect& r,const char* text,bool open=false,bool enabled=true){
    ui_round(dc,r,g_brushSurface,open?g_penAccent:g_penBorder,8);
    UiRect t{r.x+12,r.y,r.w-42,r.h};ui_text(dc,text,t,enabled?Z100:Z600,g_font,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
    UiRect chev{r.x+r.w-34,r.y,24,r.h};ui_draw_chevron(dc,chev,open,enabled);
}
static void ui_badge(HDC dc,int x,int y,const char* text,COLORREF color,HBRUSH br,int width){UiRect r{x,y,width,24};ui_round(dc,r,br,nullptr,12);ui_text(dc,text,r,color,g_fontSmall,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);}
static void ui_card_title(HDC dc,const UiRect& card,const char* title,const char* subtitle=nullptr){UiRect t{card.x+18,card.y+15,card.w-36,24};ui_text(dc,title,t,Z50,g_fontBold,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);if(subtitle){UiRect s{card.x+18,card.y+37,card.w-36,18};ui_text(dc,subtitle,s,Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);}}
static void ui_append_grouped_u64(char* b,usize cap,usize& n,u64 v){char t[32];int k=0;if(!v){append_char(b,cap,n,'0');return;}while(v&&k<31){t[k++]=(char)('0'+(v%10));v/=10;}for(int i=k-1;i>=0;--i){append_char(b,cap,n,t[i]);if(i>0&&(i%3)==0)append_char(b,cap,n,'.');}}
static void ui_append_compact_count(char* b,usize cap,usize& n,u64 v){u64 unit=0;const char* suffix=nullptr;if(v>=1000000000ULL){unit=1000000000ULL;suffix=" bi";}else if(v>=1000000ULL){unit=1000000ULL;suffix=" mi";}else if(v>=1000ULL){unit=1000ULL;suffix=" mil";}if(!unit){append_u64_dec(b,cap,n,v);return;}u64 whole=v/unit;u64 tenth=(v%unit)/(unit/10);append_u64_dec(b,cap,n,whole);if(tenth){append_char(b,cap,n,',');append_char(b,cap,n,(char)('0'+tenth));}append_str(b,cap,n,suffix);}
static const char* ui_type_display_name(int ti){static const char* names[6]={"Byte","2 Bytes","4 Bytes","8 Bytes","Float","Double"};return ti>=0&&ti<6?names[ti]:"?";}
static void ui_type_chip(HDC dc,const UiRect& r,int ti,usize count){bool active=count>0;bool hov=active&&ui_hover(r);HBRUSH br=active?(hov?g_brushHover:g_brushSurface):g_brushPanel;ui_round(dc,r,br,active?g_penAccent:g_penBorder,8);char label[96]{};usize n=0;append_str(label,sizeof(label),n,ui_type_display_name(ti));append_str(label,sizeof(label),n,"  ");ui_append_compact_count(label,sizeof(label),n,count);label[n]=0;ui_text(dc,label,r,active?Z200:Z600,g_fontSmall,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);}

static int ui_ci_compare(const char* a,const char* b){usize i=0;while(a[i]&&b[i]){char aa=ascii_lower(a[i]),bb=ascii_lower(b[i]);if(aa<bb)return -1;if(aa>bb)return 1;++i;}return a[i]?1:(b[i]?-1:0);}
static bool ui_ci_contains(const char* text,const char* needle){if(!needle||!*needle)return true;if(!text)return false;usize nl=cstrlen(needle);for(usize i=0;text[i];++i){usize j=0;while(j<nl&&text[i+j]&&ascii_lower(text[i+j])==ascii_lower(needle[j]))++j;if(j==nl)return true;}return false;}
static bool ui_process_matches_filter(const UiProcess_& p){if(!g_uiProcessFilter[0])return true;if(ui_ci_contains(p.name,g_uiProcessFilter))return true;char pid[32]{};usize n=0;append_u64_dec(pid,sizeof(pid),n,p.pid);pid[n]=0;return ui_ci_contains(pid,g_uiProcessFilter);}
static constexpr int UI_PROCESS_POPUP_ROWS=10;
static int ui_process_selected_filtered_pos(){for(int i=0;i<g_uiProcessFilteredCount;++i)if(g_uiProcessFiltered[i]==g_uiProcessSelected)return i;return -1;}
static void ui_rebuild_process_filter(){g_uiProcessFilteredCount=0;for(int i=0;i<g_uiProcessCount;++i)if(ui_process_matches_filter(g_uiProcesses[i]))g_uiProcessFiltered[g_uiProcessFilteredCount++]=i;int pos=ui_process_selected_filtered_pos();if(g_uiProcessFilteredCount==0){g_uiProcessSelected=-1;g_uiProcessScroll=0;return;}if(pos<0){g_uiProcessSelected=g_uiProcessFiltered[0];pos=0;}int maxScroll=ui_maxi(0,g_uiProcessFilteredCount-UI_PROCESS_POPUP_ROWS);if(pos<g_uiProcessScroll)g_uiProcessScroll=pos;else if(pos>=g_uiProcessScroll+UI_PROCESS_POPUP_ROWS)g_uiProcessScroll=pos-UI_PROCESS_POPUP_ROWS+1;g_uiProcessScroll=ui_clampi(g_uiProcessScroll,0,maxScroll);}
static void ui_process_select_delta(int delta){if(!g_uiProcessFilteredCount)return;int pos=ui_process_selected_filtered_pos();if(pos<0)pos=0;else pos=ui_clampi(pos+delta,0,g_uiProcessFilteredCount-1);g_uiProcessSelected=g_uiProcessFiltered[pos];int maxScroll=ui_maxi(0,g_uiProcessFilteredCount-UI_PROCESS_POPUP_ROWS);if(pos<g_uiProcessScroll)g_uiProcessScroll=pos;else if(pos>=g_uiProcessScroll+UI_PROCESS_POPUP_ROWS)g_uiProcessScroll=pos-UI_PROCESS_POPUP_ROWS+1;g_uiProcessScroll=ui_clampi(g_uiProcessScroll,0,maxScroll);InvalidateRect(g_hwnd,nullptr,0);}
static void ui_process_popup_geometry(UiRect& base,UiRect& search,UiRect& list,UiRect& footerText,UiRect& refresh,UiRect& attach){int width=ui_clampi(g_ui.target.w+170,420,560);int right=g_ui.target.x+g_ui.target.w;int x=ui_clampi(right-width,18,ui_maxi(18,g_ui.w-18-width));int y=g_ui.target.y+g_ui.target.h+8;int rows=ui_clampi(g_uiProcessFilteredCount,1,UI_PROCESS_POPUP_ROWS);int listH=rows*30;search={x+12,y+12,width-24,40};list={x+12,search.y+search.h+8,width-24,listH};int fy=list.y+list.h+8;int buttonW=120;int buttonGap=10;attach={x+width-12-buttonW,fy,buttonW,34};refresh={attach.x-buttonGap-buttonW,fy,buttonW,34};footerText={x+14,fy,ui_maxi(72,refresh.x-x-26),34};base={x,y,width,fy+46-y};}
static void ui_refresh_processes(){
    DWORD keepPid=(g_uiProcessSelected>=0&&g_uiProcessSelected<g_uiProcessCount)?g_uiProcesses[g_uiProcessSelected].pid:0;
    g_uiProcessCount=0;g_uiProcessSelected=-1;HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==(HANDLE)(uptr)-1){ui_set_status(ui_tr("status.processEnumFailed"),3);return;}
    PROCESSENTRY32A_ e{};e.dwSize=(DWORD)sizeof(e);
    if(Process32First(snap,&e)){do{if(!e.th32ProcessID||g_uiProcessCount>=(int)UI_PROCESS_LIMIT)continue;UiProcess_& p=g_uiProcesses[g_uiProcessCount++];p.pid=e.th32ProcessID;strcopy(p.name,sizeof(p.name),e.szExeFile);}while(Process32Next(snap,&e));}
    CloseHandle(snap);
    for(int i=1;i<g_uiProcessCount;++i){UiProcess_ key=g_uiProcesses[i];int j=i-1;while(j>=0&&ui_ci_compare(g_uiProcesses[j].name,key.name)>0){g_uiProcesses[j+1]=g_uiProcesses[j];--j;}g_uiProcesses[j+1]=key;}
    for(int i=0;i<g_uiProcessCount;++i)if(g_uiProcesses[i].pid==keepPid){g_uiProcessSelected=i;break;}
    if(g_uiProcessSelected<0&&g_uiProcessCount)g_uiProcessSelected=0;g_uiProcessScroll=0;ui_rebuild_process_filter();
    char b[120];usize n=0;append_str(b,sizeof(b),n,ui_tr("status.processesUpdated"));append_u64_dec(b,sizeof(b),n,g_uiProcessCount);b[n]=0;ui_set_status(b,0);InvalidateRect(g_hwnd,nullptr,0);
}

static int ui_find_freeze(uptr address){for(int i=0;i<MAX_FREEZES;++i)if(g_freezes[i].active&&g_freezes[i].address==address)return i;return -1;}
static void ui_remove_freeze(uptr address){for(int i=0;i<MAX_FREEZES;++i)if(g_freezes[i].active&&g_freezes[i].address==address){g_freezes[i].active=0;g_freezes[i].lastWriteOk=0;}}
static bool ui_read_value(uptr address,ValueType t,u8 out[8]){memzero(out,8);u8 sz=type_size(t);SIZE_T got=0;return g_process&&sz&&ReadProcessMemory((HANDLE)g_process,(LPCVOID)address,out,sz,&got)&&got==sz;}
static bool ui_freeze_value(uptr address,ValueType t,const char* text){
    u8 raw[8]{};if(!encode_value(t,text,raw))return false;int slot=ui_find_freeze(address);if(slot<0){for(int i=0;i<MAX_FREEZES;++i)if(!g_freezes[i].active){slot=i;break;}}
    if(slot<0)return false;FreezeEntry& f=g_freezes[slot];f.active=0;f.lastWriteOk=0;f.address=address;f.size=type_size(t);f.type=(u8)t;memzero(f.bytes,8);memcopy(f.bytes,raw,f.size);
    if(!write_address(address,t,text))return false;f.lastWriteOk=1;f.active=1;return true;
}
static int ui_find_watch(uptr address,ValueType t){for(int i=0;i<(int)UI_WATCH_LIMIT;++i)if(g_uiWatches[i].active&&g_uiWatches[i].address==address&&g_uiWatches[i].type==(u8)t)return i;return -1;}
static int ui_watch_slot_for_row(int logicalRow){int row=0;for(int i=0;i<(int)UI_WATCH_LIMIT;++i)if(g_uiWatches[i].active){if(row==logicalRow)return i;++row;}return -1;}
static int ui_watch_row_for_slot(int slot){int row=0;for(int i=0;i<(int)UI_WATCH_LIMIT;++i)if(g_uiWatches[i].active){if(i==slot)return row;++row;}return -1;}

static void ui_fill_watch_edit(bool currentOnly=true){
    if(g_uiSelectedWatch<0||g_uiSelectedWatch>=(int)UI_WATCH_LIMIT||!g_uiWatches[g_uiSelectedWatch].active){g_uiWatchText[0]=0;g_uiWatchNameText[0]=0;return;}
    UiWatch_& w=g_uiWatches[g_uiSelectedWatch];strcopy(g_uiWatchNameText,sizeof(g_uiWatchNameText),w.name);if(!currentOnly)return;ValueType t=(ValueType)w.type;g_uiWatchText[0]=0;u8 raw[8]{};
    if(ui_read_value(w.address,t,raw)){usize n=0;append_value(g_uiWatchText,sizeof(g_uiWatchText),n,t,raw);g_uiWatchText[n]=0;}
}
static void ui_clear_watches(bool removeFreeze,bool updateRanking=true){if(removeFreeze){for(int i=0;i<(int)UI_WATCH_LIMIT;++i)if(g_uiWatches[i].active)ui_remove_freeze(g_uiWatches[i].address);}memzero(g_uiWatches,sizeof(g_uiWatches));g_uiWatchCount=0;g_uiSelectedWatch=-1;g_uiWatchScroll=0;g_uiWatchText[0]=0;g_uiWatchNameText[0]=0;g_uiTextFocus=UI_TEXT_NONE;ui_watch_list_changed(updateRanking);}

static void ui_add_selected_result(){
    if(g_uiSelectedResult<0||(usize)g_uiSelectedResult>=g_resultCount){ui_set_status(ui_tr("status.selectResult"),2);return;}
    usize idx=(usize)g_uiSelectedResult;ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[idx].type:g_type;uptr address=g_results[idx].address;
    int ex=ui_find_watch(address,t);if(ex>=0){g_uiSelectedWatch=ex;ui_fill_watch_edit(true);ui_set_status(ui_tr("status.addressAlreadyListed"),0);InvalidateRect(g_hwnd,nullptr,0);return;}
    int slot=-1;for(int i=0;i<(int)UI_WATCH_LIMIT;++i)if(!g_uiWatches[i].active){slot=i;break;}if(slot<0){ui_set_status(ui_tr("status.addressListFull"),3);return;}
    UiWatch_& w=g_uiWatches[slot];w.active=true;w.address=address;w.type=(u8)t;w.name[0]=0;memzero(w.scanValue,8);memcopy(w.scanValue,g_results[idx].previous,type_size(t));++g_uiWatchCount;g_uiSelectedWatch=slot;
    int row=ui_watch_row_for_slot(slot);int visible=ui_maxi(1,(g_ui.watchTable.h-34)/UI_WATCH_ROW_H);if(row>=g_uiWatchScroll+visible)g_uiWatchScroll=row-visible+1;ui_fill_watch_edit(true);ui_watch_list_changed(true);ui_set_status(g_rankingEnabled?ui_tr("status.addressAddedRanking"):ui_tr("status.addressAddedTracking"),1);InvalidateRect(g_hwnd,nullptr,0);
}
static void ui_remove_selected_watch(){if(g_uiSelectedWatch<0||!g_uiWatches[g_uiSelectedWatch].active){ui_set_status(ui_tr("status.selectAddress"),2);return;}ui_remove_freeze(g_uiWatches[g_uiSelectedWatch].address);g_uiWatches[g_uiSelectedWatch].active=false;if(g_uiWatchCount)--g_uiWatchCount;g_uiSelectedWatch=-1;g_uiWatchText[0]=0;g_uiWatchNameText[0]=0;g_uiTextFocus=UI_TEXT_NONE;ui_watch_list_changed(true);ui_set_status(g_rankingEnabled?ui_tr("status.addressRemovedRanking"):ui_tr("status.addressRemoved"),0);InvalidateRect(g_hwnd,nullptr,0);}
static void ui_rename_selected_watch(){if(g_uiSelectedWatch<0||g_uiSelectedWatch>=(int)UI_WATCH_LIMIT||!g_uiWatches[g_uiSelectedWatch].active){ui_set_status(ui_tr("status.selectAddress"),2);return;}UiWatch_& w=g_uiWatches[g_uiSelectedWatch];strcopy(w.name,sizeof(w.name),g_uiWatchNameText);ui_set_status(w.name[0]?ui_tr("status.addressNameUpdated"):ui_tr("status.addressNameRemoved"),0);g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;InvalidateRect(g_hwnd,nullptr,0);}
static void ui_finish_watch_inline_edit(bool commitName=true){if(g_uiTextFocus==UI_TEXT_WATCH_NAME&&commitName){ui_rename_selected_watch();return;}if(g_uiTextFocus==UI_TEXT_WATCH_NAME||g_uiTextFocus==UI_TEXT_WATCH){g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;}}
static void ui_write_selected_watch(){
    if(g_uiSelectedWatch<0||!g_uiWatches[g_uiSelectedWatch].active){ui_set_status(ui_tr("status.selectAddress"),2);return;}UiWatch_& w=g_uiWatches[g_uiSelectedWatch];ValueType t=(ValueType)w.type;char text[128]{};strcopy(text,sizeof(text),g_uiWatchText);u8 desired[8]{};
    if(!encode_value(t,text,desired)){ui_set_status(ui_tr("status.invalidAddressValue"),3);return;}int fi=ui_find_freeze(w.address);u8 sz=type_size(t);
    if(fi>=0){FreezeEntry& f=g_freezes[fi];f.active=0;f.address=w.address;f.size=sz;f.type=(u8)t;memzero(f.bytes,8);memcopy(f.bytes,desired,sz);f.lastWriteOk=0;}
    if(!write_address(w.address,t,text)){if(fi>=0)g_freezes[fi].active=1;ui_set_status(ui_tr("status.writeFailed"),3);return;}
    if(fi>=0){g_freezes[fi].lastWriteOk=1;g_freezes[fi].active=1;}
    u8 after[8]{};bool reread=ui_read_value(w.address,t,after);bool verified=reread&&memequal(after,desired,sz);if(reread){usize n=0;append_value(g_uiWatchText,sizeof(g_uiWatchText),n,t,after);g_uiWatchText[n]=0;}g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;ui_set_status(verified?(fi>=0?ui_tr("status.writeConfirmedFreeze"):ui_tr("status.writeConfirmed")):ui_tr("status.writeOverwritten"),verified?1:2);InvalidateRect(g_hwnd,nullptr,0);
}
static void ui_toggle_selected_freeze(bool preferCurrentIfEmpty=false){
    if(g_uiSelectedWatch<0||!g_uiWatches[g_uiSelectedWatch].active){ui_set_status(ui_tr("status.selectAddress"),2);return;}UiWatch_& w=g_uiWatches[g_uiSelectedWatch];ValueType t=(ValueType)w.type;int fi=ui_find_freeze(w.address);
    if(fi>=0){ui_remove_freeze(w.address);ui_set_status(ui_tr("status.freezeRemoved"),0);InvalidateRect(g_hwnd,nullptr,0);return;}
    char text[128]{};strcopy(text,sizeof(text),g_uiWatchText);if(!text[0]&&preferCurrentIfEmpty){u8 raw[8]{};if(ui_read_value(w.address,t,raw)){usize n=0;append_value(text,sizeof(text),n,t,raw);text[n]=0;strcopy(g_uiWatchText,sizeof(g_uiWatchText),text);}}
    if(!text[0]){ui_set_status(ui_tr("status.freezeValueRequired"),2);return;}if(!ui_freeze_value(w.address,t,text)){ui_set_status(ui_tr("status.freezeEnableFailed"),3);return;}ui_set_status(ui_tr("status.freezeActive"),1);InvalidateRect(g_hwnd,nullptr,0);
}

static DWORD __stdcall ui_scan_worker(LPVOID){
    bool ok=true;
    if(g_uiTask.kind==1){
        guided_reset();
        if(g_uiTask.scanType==0){if(g_uiTask.type==ValueType::Mixed)ok=scan_all_exact(g_uiTask.value);else{u8 raw[8]{};ok=encode_value(g_uiTask.type,g_uiTask.value,raw)&&scan_exact(g_uiTask.type,raw);}}
        else if(g_uiTask.scanType==1||g_uiTask.scanType==8){bool smart=g_uiTask.scanType==8;ok=g_uiTask.type==ValueType::Mixed?scan_all_unknown(smart):scan_unknown(g_uiTask.type,smart);}else ok=false;
    }else if(g_uiTask.kind==2){
        NextMode mode=NextMode::Exact;bool has=false;switch(g_uiTask.scanType){case 0:mode=NextMode::Exact;has=true;break;case 2:mode=NextMode::Changed;break;case 3:mode=NextMode::Unchanged;break;case 4:mode=NextMode::Increased;break;case 5:mode=NextMode::Decreased;break;case 6:mode=NextMode::Bigger;has=true;break;case 7:mode=NextMode::Smaller;has=true;break;default:ok=false;break;}
        if(ok){usize before=guided_current_count();usize beforeTypes[6]{};guided_current_types(beforeTypes);next_scan_text(mode,has?g_uiTask.value:nullptr,has);guided_record(mode,before,beforeTypes);}
    }
    if(ok&&g_rankingEnabled&&!g_snapshotActive&&g_rankingDirty)rebuild_result_ranking();
    PostMessageA(g_hwnd,WM_APP_SCAN_DONE_,ok?1:0,0);return 0;
}
static void ui_start_scan(bool first){
    if(g_uiBusy)return;if(!g_process){ui_set_status(ui_tr("status.attachBeforeScan"),2);return;}ValueType t=ui_selected_type();if(t==ValueType::Invalid){ui_set_status(ui_tr("status.selectValueType"),2);return;}if(first&&g_uiScanType>1&&g_uiScanType!=8){ui_set_status(ui_tr("status.firstScanModesOnly"),2);return;}if(!first&&(g_uiScanType==1||g_uiScanType==8)){ui_set_status(ui_tr("status.unknownOnlyFirst"),2);return;}if(!first&&g_type==ValueType::Invalid){ui_set_status(ui_tr("status.firstBeforeNext"),2);return;}
    char value[128]{};strcopy(value,sizeof(value),g_uiScanText);bool needs=(g_uiScanType==0||g_uiScanType==6||g_uiScanType==7);if(needs&&!value[0]){ui_set_status(ui_tr("status.enterScanValue"),2);return;}
    if(first){g_uiUnknownFlow=(g_uiScanType==1||g_uiScanType==8);g_uiUnknownInitialMode=g_uiScanType==8?2:(g_uiScanType==1?1:0);}
    g_uiTask.kind=first?1:2;g_uiTask.scanType=g_uiScanType;g_uiTask.type=t;strcopy(g_uiTask.value,sizeof(g_uiTask.value),value);g_uiBusy=1;g_uiPopup=UI_POP_NONE;ui_sync_edits();ui_set_status(first?ui_tr("status.firstScanRunning"):ui_tr("status.nextScanRunning"),0);InvalidateRect(g_hwnd,nullptr,0);
    DWORD tid=0;HANDLE th=CreateThread(nullptr,0,ui_scan_worker,nullptr,0,&tid);if(!th){g_uiBusy=0;if(first){g_uiUnknownFlow=false;g_uiUnknownInitialMode=0;g_uiScanType=0;}ui_sync_edits();ui_set_status(ui_tr("status.scanThreadFailed"),3);}else CloseHandle(th);
}
static void ui_start_guided(int scanType){if(g_uiBusy)return;if(!g_process||g_type==ValueType::Invalid||!g_uiUnknownFlow){ui_set_status(ui_tr("status.guidedUnavailable"),2);return;}if(scanType<2||scanType>5)return;g_uiTask.kind=2;g_uiTask.scanType=scanType;g_uiTask.type=g_type;g_uiTask.value[0]=0;g_uiBusy=1;g_uiPopup=UI_POP_NONE;ui_sync_edits();const char* label=scanType==2?ui_tr("guided.changed"):(scanType==3?ui_tr("guided.unchanged"):(scanType==4?ui_tr("guided.increased"):ui_tr("guided.decreased")));char b[180]{};usize n=0;append_str(b,sizeof(b),n,ui_tr("status.guidedPrefix"));append_str(b,sizeof(b),n,label);append_str(b,sizeof(b),n,ui_tr("status.guidedRefining"));b[n]=0;ui_set_status(b,0);InvalidateRect(g_hwnd,nullptr,0);DWORD tid=0;HANDLE th=CreateThread(nullptr,0,ui_scan_worker,nullptr,0,&tid);if(!th){g_uiBusy=0;ui_sync_edits();ui_set_status(ui_tr("status.guidedThreadFailed"),3);}else CloseHandle(th);}
static void ui_new_scan(){if(g_uiBusy)return;clear_results();clear_snapshot();guided_reset();g_type=ValueType::Invalid;g_uiUnknownFlow=false;g_uiUnknownInitialMode=0;g_uiScanType=0;g_uiSelectedResult=-1;g_uiResultScroll=0;ui_set_status(ui_tr("status.newScan"),0);InvalidateRect(g_hwnd,nullptr,0);}
static void ui_attach_selected(){
    if(g_uiBusy)return;if(g_uiProcessSelected<0||g_uiProcessSelected>=g_uiProcessCount){ui_set_status(ui_tr("status.selectProcess"),2);return;}UiProcess_ p=g_uiProcesses[g_uiProcessSelected];ui_clear_watches(true,false);
    if(!attach_pid(p.pid)){char b[180];usize n=0;append_str(b,sizeof(b),n,ui_tr("status.openProcessFailed"));append_u64_dec(b,sizeof(b),n,GetLastError());b[n]=0;ui_set_status(b,3);return;}g_uiUnknownFlow=false;g_uiUnknownInitialMode=0;g_uiScanType=0;strcopy(g_uiAttachedName,sizeof(g_uiAttachedName),p.name);if(!g_uiTrainerCount&&!g_uiTrainerProcess[0])strcopy(g_uiTrainerProcess,sizeof(g_uiTrainerProcess),p.name);refresh_modules();g_uiSelectedResult=-1;g_uiResultScroll=0;g_uiPointerTargetValid=false;g_uiSelectedPointer=-1;g_uiPointerScroll=0;ui_pointer_reset_cache();
    char b[360];usize n=0;append_str(b,sizeof(b),n,ui_tr("status.attachedTo"));append_str(b,sizeof(b),n,p.name);append_str(b,sizeof(b),n," (PID ");append_u64_dec(b,sizeof(b),n,p.pid);append_str(b,sizeof(b),n,")");append_str(b,sizeof(b),n,ui_tr("status.pointerWidth"));append_u64_dec(b,sizeof(b),n,(u64)g_pointerSize*8);append_str(b,sizeof(b),n,"-bit.");if(g_pointerChainCount)append_str(b,sizeof(b),n,ui_tr("status.previousChains"));b[n]=0;ui_set_status(b,1);InvalidateRect(g_hwnd,nullptr,0);
}

// Draw a dot without allocating a brush per frame.
static HBRUSH g_brushSuccess = nullptr;
static HBRUSH g_brushWarn = nullptr;
static HBRUSH g_brushError = nullptr;
static HBRUSH g_brushAccentSoft = nullptr;

static bool ui_selected_is_attached(){return g_process&&g_uiProcessSelected>=0&&g_uiProcessSelected<g_uiProcessCount&&g_uiProcesses[g_uiProcessSelected].pid==g_pid;}
static void ui_tab(HDC dc,const UiRect& r,const char* label,bool active,bool enabled){
    HBRUSH br=active?g_brushSelected:(ui_hover(r)&&enabled?g_brushHover:g_brushPanel);ui_round(dc,r,br,active?g_penAccent:g_penBorder,8);ui_text(dc,label,r,enabled?(active?Z50:Z300):Z600,g_fontBold,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);
}
static void ui_draw_header2(HDC dc){
    ui_round(dc,g_ui.header,g_brushPanel,g_penBorder,12);UiRect brand{g_ui.header.x+18,g_ui.header.y+10,120,28};ui_text(dc,ui_tr("app.name"),brand,Z50,g_fontTitle,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);UiRect sub{g_ui.header.x+18,g_ui.header.y+39,120,20};ui_text(dc,ui_tr("app.tagline"),sub,Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);
    ui_tab(dc,g_ui.tabScanner,ui_tr("nav.scanner"),g_uiView==UI_VIEW_SCANNER,!g_uiBusy);ui_tab(dc,g_ui.tabPointers,ui_tr("nav.pointers"),g_uiView==UI_VIEW_POINTERS,!g_uiBusy);ui_tab(dc,g_ui.tabTrainer,ui_tr("nav.trainer"),g_uiView==UI_VIEW_TRAINER,!g_uiBusy);
    char target[420]{};if(g_uiProcessSelected>=0&&g_uiProcessSelected<g_uiProcessCount){usize n=0;append_str(target,sizeof(target),n,g_uiProcesses[g_uiProcessSelected].name);append_str(target,sizeof(target),n,"   PID ");append_u64_dec(target,sizeof(target),n,g_uiProcesses[g_uiProcessSelected].pid);target[n]=0;}else strcopy(target,sizeof(target),ui_tr("header.selectProcess"));ui_field(dc,g_ui.target,target,g_uiPopup==UI_POP_PROCESS,!g_uiBusy);
    if(g_process){UiRect dot{g_ui.target.x+g_ui.target.w-48,g_ui.target.y+16,8,8};ui_round(dc,dot,ui_selected_is_attached()?g_brushSuccess:g_brushWarn,nullptr,8);}
    ui_button_icon(dc,g_ui.refresh,ui_tr("header.refresh"),UI_ICON_REFRESH,false,!g_uiBusy);bool same=ui_selected_is_attached();ui_button_icon(dc,g_ui.attach,same?ui_tr("header.attached"):ui_tr("header.attach"),same?UI_ICON_CHECK:UI_ICON_ATTACH,!same,!g_uiBusy,same);
}
static void ui_draw_scan_panel(HDC dc){
    ui_round(dc,g_ui.scanCard,g_brushPanel,g_penBorder,12);ui_card_title(dc,g_ui.scanCard,ui_tr("nav.scanner"),ui_scan_active()?ui_tr("scanner.cardActiveHint"):ui_tr("scanner.cardReadyHint"));int x=g_ui.scanCard.x+18;
    if(g_uiBusy==1){UiRect busy{g_ui.scanCard.x+24,g_ui.scanCard.y+92,g_ui.scanCard.w-48,128};ui_text(dc,ui_tr("scanner.scanning"),busy,Z200,g_fontTitle,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);UiRect sub{g_ui.scanCard.x+30,g_ui.scanCard.y+230,g_ui.scanCard.w-60,72};ui_text(dc,ui_tr("scanner.scanningHint"),sub,Z500,g_fontSmall,DT_CENTER_|DT_WORDBREAK_);ui_badge(dc,x,g_ui.scanCard.y+g_ui.scanCard.h-42,ui_tr("scanner.scanningBadge"),AMBER400,g_brushSurface,104);return;}
    if(!ui_scan_active()){
        ui_text(dc,ui_tr("scanner.scanType"),{x,g_ui.scanType.y-20,g_ui.scanCard.w-36,16},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_field(dc,g_ui.scanType,ui_scan_type_name(g_uiScanType),g_uiPopup==UI_POP_SCAN,true);
        if(ui_scan_value_visible()){ui_text(dc,ui_tr("scanner.value"),{x,g_ui.scanValueBox.y-20,g_ui.scanCard.w-36,16},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_input(dc,g_ui.scanValueBox,g_uiScanText,UI_TEXT_SCAN,true,g_font);}
        ui_text(dc,ui_tr("scanner.valueType"),{x,g_ui.valueType.y-20,g_ui.scanCard.w-36,16},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_field(dc,g_ui.valueType,ui_value_type_name(g_uiValueType),g_uiPopup==UI_POP_VALUE,true);
        char align[80]{};usize an=0;append_str(align,sizeof(align),an,ui_tr("scanner.alignmentPrefix"));append_str(align,sizeof(align),an,g_alignmentByte?ui_tr("scanner.alignmentByte"):ui_tr("scanner.alignmentNatural"));align[an]=0;ui_button(dc,g_ui.alignment,align,false,true);ui_button(dc,g_ui.firstScan,ui_tr("scanner.firstScan"),true,g_process!=nullptr);
        const char* hint=g_uiScanType==8?ui_tr("scanner.smartHint"):(g_uiScanType==1?ui_tr("scanner.fullHint"):ui_tr("scanner.exactHint"));ui_text(dc,hint,g_ui.scanHint,Z500,g_fontSmall,DT_LEFT_|DT_WORDBREAK_);return;
    }
    ui_round(dc,g_ui.scanSummary,g_brushSurface,g_penBorder,8);char summary[220]{};usize n=0;if(ui_unknown_flow_active()){append_str(summary,sizeof(summary),n,g_uiUnknownInitialMode==2?ui_tr("scanner.unknownSmart"):ui_tr("scanner.unknownFull"));append_str(summary,sizeof(summary),n,"  |  ");append_str(summary,sizeof(summary),n,ui_active_type_label());}else{append_str(summary,sizeof(summary),n,ui_tr("scanner.active"));append_str(summary,sizeof(summary),n,"  |  ");append_str(summary,sizeof(summary),n,ui_active_type_label());}append_str(summary,sizeof(summary),n,"  |  ");append_str(summary,sizeof(summary),n,g_alignmentByte?ui_tr("scanner.alignmentByte"):ui_tr("scanner.alignmentNatural"));summary[n]=0;ui_text(dc,summary,{g_ui.scanSummary.x+12,g_ui.scanSummary.y,g_ui.scanSummary.w-24,g_ui.scanSummary.h},Z300,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
    if(ui_unknown_flow_active()){
        ui_text(dc,ui_tr("scanner.refineValue"),{x,g_ui.wizardGoal.y,g_ui.scanCard.w-168,24},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);char goalLabel[64]{};usize gn=0;append_str(goalLabel,sizeof(goalLabel),gn,ui_tr("scanner.targetPrefix"));append_str(goalLabel,sizeof(goalLabel),gn,guided_goal_name(g_guidedGoal));goalLabel[gn]=0;ui_button(dc,g_ui.wizardGoal,goalLabel,false,true);NextMode suggested=guided_recommended_mode();ui_button(dc,g_ui.guideChanged,ui_tr("guided.changed"),suggested==NextMode::Changed,true);ui_button(dc,g_ui.guideUnchanged,ui_tr("guided.unchanged"),suggested==NextMode::Unchanged,true);ui_button(dc,g_ui.guideIncreased,ui_tr("guided.increased"),suggested==NextMode::Increased,true);ui_button(dc,g_ui.guideDecreased,ui_tr("guided.decreased"),suggested==NextMode::Decreased,true);
        char count[180]{};n=0;ui_append_compact_count(count,sizeof(count),n,g_snapshotActive?g_snapshotCandidates:g_resultCount);append_str(count,sizeof(count),n,g_snapshotActive?ui_tr("scanner.candidatePlural"):ui_tr("scanner.resultPlural"));if(g_guidedCount){append_str(count,sizeof(count),n,"  |  ");append_u64_dec(count,sizeof(count),n,g_guidedCount);append_str(count,sizeof(count),n,g_guidedCount==1?ui_tr("scanner.stepSingular"):ui_tr("scanner.stepPlural"));}count[n]=0;ui_text(dc,count,g_ui.scanStats,Z50,g_fontBold,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
        char hint[420]{};n=0;if(g_guidedCount){GuidedStep_& s=g_guidedSteps[g_guidedCount-1];append_str(hint,sizeof(hint),n,ui_tr("scanner.lastPrefix"));append_str(hint,sizeof(hint),n,guided_mode_name((NextMode)s.mode));append_str(hint,sizeof(hint),n,"  ");ui_append_compact_count(hint,sizeof(hint),n,s.beforeCount);append_str(hint,sizeof(hint),n," -> ");ui_append_compact_count(hint,sizeof(hint),n,s.afterCount);append_str(hint,sizeof(hint),n,". ");}append_str(hint,sizeof(hint),n,guided_action_text());hint[n]=0;ui_text(dc,hint,g_ui.scanHint,Z500,g_fontSmall,DT_LEFT_|DT_WORDBREAK_);
    }else{
        char count[120]{};n=0;ui_append_compact_count(count,sizeof(count),n,g_resultCount);append_str(count,sizeof(count),n,ui_tr("scanner.resultPlural"));count[n]=0;ui_text(dc,count,g_ui.scanStats,Z50,g_fontBold,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_text(dc,ui_tr("scanner.manualHint"),g_ui.scanHint,Z500,g_fontSmall,DT_LEFT_|DT_WORDBREAK_);
    }
    ui_text(dc,ui_tr("scanner.manualRefine"),{x,g_ui.scanType.y-20,g_ui.scanCard.w-36,16},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_field(dc,g_ui.scanType,ui_scan_type_name(g_uiScanType),g_uiPopup==UI_POP_SCAN,true);if(ui_scan_value_visible()){ui_text(dc,ui_tr("scanner.referenceValue"),{x,g_ui.scanValueBox.y-18,g_ui.scanCard.w-36,16},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_input(dc,g_ui.scanValueBox,g_uiScanText,UI_TEXT_SCAN,true,g_font);}ui_button(dc,g_ui.nextScan,ui_tr("scanner.nextScan"),true,g_process!=nullptr);ui_button(dc,g_ui.newScan,ui_tr("scanner.newScan"),false,true);
}

static void ui_result_column_widths(const UiRect& table,int widths[6]){int avail=ui_maxi(420,table.w-20);widths[0]=48;widths[2]=78;widths[5]=118;int flex=ui_maxi(220,avail-widths[0]-widths[2]-widths[5]);widths[1]=ui_clampi((flex*35)/100,105,190);int rem=ui_maxi(120,flex-widths[1]);widths[3]=rem/2;widths[4]=rem-widths[3];}
static void ui_watch_column_widths(const UiRect& table,int widths[7]){int avail=ui_maxi(500,table.w-20);widths[0]=48;widths[3]=60;widths[6]=76;int flex=ui_maxi(316,avail-widths[0]-widths[3]-widths[6]);widths[1]=ui_clampi((flex*22)/100,96,160);widths[2]=ui_clampi((flex*30)/100,118,190);int rem=ui_maxi(102,flex-widths[1]-widths[2]);widths[4]=(rem*45)/100;widths[5]=rem-widths[4];}
static void ui_watch_column_rects(const UiRect& row,UiRect cols[7]){int widths[7]{};ui_watch_column_widths(g_ui.watchTable,widths);int x=row.x+10;for(int i=0;i<7;++i){cols[i]={x,row.y,widths[i],row.h};x+=widths[i];}}
static void ui_watch_action_rects(const UiRect& row,UiRect& pointerRect,UiRect& removeRect){UiRect cols[7]{};ui_watch_column_rects(row,cols);int size=30,gap=4,total=size*2+gap;int x=cols[6].x+(cols[6].w-total)/2;int y=row.y+(row.h-size)/2;pointerRect={x,y,size,size};removeRect={x+size+gap,y,size,size};}
static void ui_watch_value_edit_rects(const UiRect& row,UiRect& inputRect,UiRect& saveRect){UiRect cols[7]{};ui_watch_column_rects(row,cols);int size=28,gap=4;saveRect={cols[5].x+cols[5].w-size-3,row.y+(row.h-size)/2,size,size};int right=saveRect.x-gap;inputRect={cols[5].x,row.y+4,ui_maxi(36,right-cols[5].x),row.h-8};}
static void ui_draw_table_header(HDC dc,const UiRect& table,bool watch){
    UiRect head{table.x,table.y,table.w,30};ui_round(dc,head,g_brushSurface,nullptr,6);int x=table.x+10;
    if(!watch){int widths[6]{};ui_result_column_widths(table,widths);const char* names[6]={"#",ui_tr("results.address"),ui_tr("results.type"),ui_tr("results.scanValue"),ui_tr("results.current"),ui_tr("results.scoreNear")};for(int i=0;i<6;++i){UiRect r{x,head.y,widths[i],head.h};ui_text(dc,names[i],r,Z400,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);x+=widths[i];}}
    else {int widths[7]{};ui_watch_column_widths(table,widths);const char* names[7]={ui_tr("watch.freeze"),ui_tr("watch.name"),ui_tr("watch.address"),ui_tr("watch.type"),ui_tr("watch.scanValue"),ui_tr("watch.currentNew"),ui_tr("watch.actions")};for(int i=0;i<7;++i){UiRect r{x,head.y,widths[i],head.h};ui_text(dc,names[i],r,Z400,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);x+=widths[i];}}
}
static void ui_draw_scrollbar(HDC dc,const UiRect& table,int total,int scroll,int visible){if(total<=visible||visible<=0)return;int trackY=table.y+34,trackH=table.h-38;UiRect tr{table.x+table.w-5,trackY,3,trackH};ui_round(dc,tr,g_brushSurface,nullptr,3);int thumbH=ui_maxi(24,(trackH*visible)/total);int maxScroll=total-visible;int thumbY=trackY+(maxScroll?((trackH-thumbH)*scroll)/maxScroll:0);UiRect th{tr.x,thumbY,3,thumbH};ui_round(dc,th,g_brushSelected,nullptr,3);}

static void ui_format_result(usize idx,char a[48],char ty[32],char sv[96],char cv[96],bool& readable){
    ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[idx].type:g_type;usize n=0;append_hex(a,48,n,g_results[idx].address);a[n]=0;strcopy(ty,32,type_name(t));n=0;append_value(sv,96,n,t,g_results[idx].previous);sv[n]=0;u8 raw[8]{};readable=ui_read_value(g_results[idx].address,t,raw);n=0;if(readable)append_value(cv,96,n,t,raw);else append_str(cv,96,n,ui_tr("common.unavailable"));cv[n]=0;
}
static UiRect ui_type_filter_rect(int ti){int gap=10,pad=40;int w=(g_ui.resultCard.w-pad*2-gap*2)/3;int col=ti%3,row=ti/3;return {g_ui.resultCard.x+pad+col*(w+gap),g_ui.resultCard.y+210+row*42,w,32};}
static usize ui_type_filter_count(int ti){if(ti<0||ti>=6)return 0;return g_snapshotActive?g_snapshotTypeCounts[ti]:g_resultTypeCounts[ti];}
static int ui_result_display_total(){if(g_rankingEnabled&&!g_snapshotActive&&!g_rankingDirty)return (int)g_rankedCount;return (int)(g_resultCount<UI_RESULT_RENDER_LIMIT?g_resultCount:UI_RESULT_RENDER_LIMIT);}
static usize ui_result_display_index(int logical){if(logical<0)return (usize)-1;if(g_rankingEnabled&&!g_snapshotActive&&!g_rankingDirty&&(usize)logical<g_rankedCount)return g_rankedIndices[logical];return (usize)logical;}
static u16 ui_result_display_score(int logical){if(g_rankingEnabled&&!g_snapshotActive&&!g_rankingDirty&&(usize)logical<g_rankedCount)return g_rankedScores[logical];return 0;}
static void ui_append_rank_distance(char* b,usize cap,usize& n,uptr distance){if(distance<1024u){append_u64_dec(b,cap,n,(u64)distance);append_str(b,cap,n," B");return;}if(distance<(uptr)(1024u*1024u)){append_u64_dec(b,cap,n,(u64)((distance+1023u)/1024u));append_str(b,cap,n," KB");return;}append_u64_dec(b,cap,n,(u64)((distance+(1024u*1024u-1u))/(1024u*1024u)));append_str(b,cap,n," MB");}
static bool ui_result_rank_proximity(usize idx,uptr& distance,int& watchSlot){if(idx>=g_resultCount||!g_rankAnchorCount)return false;if(!rank_nearest_anchor(g_results[idx].address,distance,watchSlot,nullptr))return false;return distance==0||distance<=0x1000000u;}
static void ui_draw_results(HDC dc){
    ui_round(dc,g_ui.resultCard,g_brushPanel,g_penBorder,12);
    if(g_uiBusy==1){ui_card_title(dc,g_ui.resultCard,ui_tr("results.title"),ui_tr("results.waitSubtitle"));UiRect wait{g_ui.resultCard.x+30,g_ui.resultCard.y+92,g_ui.resultCard.w-60,g_ui.resultCard.h-130};ui_text(dc,ui_tr("results.waiting"),wait,Z500,g_font,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);return;}
    if(g_snapshotActive){ui_card_title(dc,g_ui.resultCard,ui_tr("results.unknownTitle"),ui_tr("results.unknownSubtitle"));char totalText[128]{};usize n=0;ui_append_compact_count(totalText,sizeof(totalText),n,g_snapshotCandidates);append_str(totalText,sizeof(totalText),n,ui_tr("scanner.candidatePlural"));totalText[n]=0;ui_text(dc,totalText,{g_ui.resultCard.x+32,g_ui.resultCard.y+82,g_ui.resultCard.w-64,46},Z50,g_fontTitle,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);char detail[220]{};n=0;ui_append_grouped_u64(detail,sizeof(detail),n,g_snapshotCandidates);append_str(detail,sizeof(detail),n,ui_tr("results.exactSuffix"));append_u64_dec(detail,sizeof(detail),n,g_snapshotBytes/(1024*1024));append_str(detail,sizeof(detail),n,ui_tr("results.tempMiBSuffix"));detail[n]=0;ui_text(dc,detail,{g_ui.resultCard.x+32,g_ui.resultCard.y+128,g_ui.resultCard.w-64,24},Z500,g_fontSmall,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);UiRect note{g_ui.resultCard.x+54,g_ui.resultCard.y+160,g_ui.resultCard.w-108,50};ui_text(dc,g_type==ValueType::Mixed?ui_tr("results.mixedRefineHint"):ui_tr("results.singleRefineHint"),note,Z400,g_fontSmall,DT_CENTER_|DT_VCENTER_|DT_WORDBREAK_);if(g_type==ValueType::Mixed){for(int ti=0;ti<6;++ti)ui_type_chip(dc,ui_type_filter_rect(ti),ti,ui_type_filter_count(ti));}return;}
    if(!g_resultCount){ui_card_title(dc,g_ui.resultCard,ui_tr("results.title"),ui_tr("results.materializedOnly"));UiRect empty{g_ui.resultCard.x+40,g_ui.resultCard.y+100,g_ui.resultCard.w-80,g_ui.resultCard.h-140};ui_text(dc,ui_scan_active()?ui_tr("results.none"):ui_tr("results.startScan"),empty,Z600,g_font,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);return;}
    ui_card_title(dc,g_ui.resultCard,ui_tr("results.title"),g_rankingEnabled?ui_tr("results.rankingHint"):ui_tr("results.doubleClickHint"));ui_button(dc,g_ui.rankToggle,g_rankingEnabled?ui_tr("results.rankingOn"):ui_tr("results.rankingOff"),g_rankingEnabled,true);if(g_uiSelectedResult>=0)ui_button(dc,g_ui.addResult,ui_tr("results.add"),false,true);ui_draw_table_header(dc,g_ui.resultTable,false);
    int bodyY=g_ui.resultTable.y+34,rowH=30;int visible=ui_maxi(1,(g_ui.resultTable.h-34)/rowH);int total=ui_result_display_total();int maxScroll=ui_maxi(0,total-visible);g_uiResultScroll=ui_clampi(g_uiResultScroll,0,maxScroll);
    int widths[6]{};ui_result_column_widths(g_ui.resultTable,widths);char proximityTip[220]{};UiRect proximityTipAnchor{};bool proximityTipReady=false;for(int r=0;r<visible;++r){int logical=g_uiResultScroll+r;if(logical>=total)break;usize idx=ui_result_display_index(logical);if(idx>=g_resultCount)continue;UiRect row{g_ui.resultTable.x,bodyY+r*rowH,g_ui.resultTable.w-8,rowH-1};bool sel=(g_uiSelectedResult==(int)idx);bool hov=ui_contains(row,g_uiMouseX,g_uiMouseY);if(sel)ui_round(dc,row,g_brushSelected,nullptr,5);else if(hov)ui_round(dc,row,g_brushHover,nullptr,5);
        char ix[32]{},a[48]{},ty[32]{},sv[96]{},cv[96]{},score[48]{};usize n=0;append_char(ix,sizeof(ix),n,'#');append_u64_dec(ix,sizeof(ix),n,idx);ix[n]=0;bool readable=false;ui_format_result(idx,a,ty,sv,cv,readable);uptr proximityDistance=0;int proximitySlot=-1;bool proximity=g_rankingEnabled&&ui_result_rank_proximity(idx,proximityDistance,proximitySlot);n=0;if(g_rankingEnabled){append_u64_dec(score,sizeof(score),n,ui_result_display_score(logical));if(proximity){append_str(score,sizeof(score),n," | ");if(proximityDistance==0)append_str(score,sizeof(score),n,ui_tr("results.listMarker"));else ui_append_rank_distance(score,sizeof(score),n,proximityDistance);}}else append_char(score,sizeof(score),n,'-');score[n]=0;const char* vals[6]={ix,a,ty,sv,cv,score};int x=row.x+10;for(int c=0;c<6;++c){UiRect cell{x,row.y,widths[c]-6,row.h};COLORREF scoreColor=!g_rankingEnabled?Z600:(proximity?(proximityDistance==0||proximityDistance<=0x10000u?GREEN400:(proximityDistance<=0x100000u?BLUE300:Z300)):BLUE300);COLORREF color=c==0?Z500:(c==5?scoreColor:(c==4?(readable?Z100:AMBER400):(c==2?Z400:Z200)));HFONT f=(c==1||c==3||c==4)?g_fontMono:g_fontSmall;ui_text(dc,vals[c],cell,color,f,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);if(c==5&&proximity&&ui_hover(cell)){usize tn=0;if(proximityDistance==0){append_str(proximityTip,sizeof(proximityTip),tn,ui_tr("results.alreadyInList"));}else{append_str(proximityTip,sizeof(proximityTip),tn,ui_tr("results.nearPrefix"));if(proximitySlot>=0&&proximitySlot<(int)UI_WATCH_LIMIT&&g_uiWatches[proximitySlot].active&&g_uiWatches[proximitySlot].name[0])append_str(proximityTip,sizeof(proximityTip),tn,g_uiWatches[proximitySlot].name);else append_str(proximityTip,sizeof(proximityTip),tn,ui_tr("results.nearUnnamed"));append_str(proximityTip,sizeof(proximityTip),tn,": ");ui_append_rank_distance(proximityTip,sizeof(proximityTip),tn,proximityDistance);}proximityTip[tn]=0;proximityTipAnchor=cell;proximityTipReady=true;}x+=widths[c];}}
    ui_draw_scrollbar(dc,g_ui.resultTable,total,g_uiResultScroll,visible);if(proximityTipReady)ui_tooltip(dc,proximityTipAnchor,proximityTip);
    if(!g_rankingEnabled&&((usize)total<g_resultCount)){char b[220];usize n=0;append_str(b,sizeof(b),n,ui_tr("results.showingPrefix"));append_u64_dec(b,sizeof(b),n,total);append_str(b,sizeof(b),n,ui_tr("results.showingMiddle"));append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n,ui_tr("results.showingSuffix"));b[n]=0;UiRect note{g_ui.resultTable.x+10,g_ui.resultTable.y+g_ui.resultTable.h-22,g_ui.resultTable.w-20,18};ui_text(dc,b,note,Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);}
}

static void ui_draw_checkbox(HDC dc,int x,int y,bool checked,bool error){UiRect b{x,y,18,18};ui_round(dc,b,checked?(error?g_brushWarn:g_brushAccent):g_brushSurface,checked?(error?g_penStrong:g_penAccent):g_penStrong,5);if(checked&&!error){HGDIOBJ op=SelectObject(dc,(HGDIOBJ)g_penGreen);MoveToEx(dc,x+4,y+9,nullptr);LineTo(dc,x+8,y+13);LineTo(dc,x+15,y+5);SelectObject(dc,op);}if(checked&&error)ui_text(dc,"!",b,Z950,g_fontBold,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);}
static void ui_draw_watch(HDC dc){
    ui_round(dc,g_ui.watchCard,g_brushPanel,g_penBorder,12);ui_card_title(dc,g_ui.watchCard,ui_tr("watch.title"),ui_tr("watch.subtitle"));if(g_uiWatchCount){ui_button(dc,g_ui.clearWatch,ui_tr("watch.clear"),false,!g_uiBusy);}else{UiRect empty{g_ui.watchCard.x+36,g_ui.watchCard.y+72,g_ui.watchCard.w-72,g_ui.watchCard.h-100};ui_text(dc,ui_tr("watch.empty"),empty,Z600,g_font,DT_CENTER_|DT_VCENTER_|DT_WORDBREAK_);return;}ui_draw_table_header(dc,g_ui.watchTable,true);
    int bodyY=g_ui.watchTable.y+34,rowH=UI_WATCH_ROW_H;int visible=ui_maxi(1,(g_ui.watchTable.h-34)/rowH);int maxScroll=ui_maxi(0,g_uiWatchCount-visible);g_uiWatchScroll=ui_clampi(g_uiWatchScroll,0,maxScroll);const char* tooltipText=nullptr;UiRect tooltipAnchor{};
    for(int r=0;r<visible;++r){int logical=g_uiWatchScroll+r;if(logical>=g_uiWatchCount)break;int slot=ui_watch_slot_for_row(logical);if(slot<0)continue;UiWatch_& w=g_uiWatches[slot];UiRect row{g_ui.watchTable.x,bodyY+r*rowH,g_ui.watchTable.w-8,rowH-1};bool sel=(g_uiSelectedWatch==slot);bool hov=ui_contains(row,g_uiMouseX,g_uiMouseY);if(sel)ui_round(dc,row,g_brushSelected,nullptr,5);else if(hov)ui_round(dc,row,g_brushHover,nullptr,5);UiRect cols[7]{};ui_watch_column_rects(row,cols);
        ValueType t=(ValueType)w.type;int fi=ui_find_freeze(w.address);bool frozen=fi>=0;bool ferr=frozen&&!g_freezes[fi].lastWriteOk;int cbx=cols[0].x+(cols[0].w-18)/2;ui_draw_checkbox(dc,cbx,row.y+(row.h-18)/2,frozen,ferr);
        char a[48]{},ty[32]{},sv[96]{},cv[96]{};usize n=0;append_hex(a,sizeof(a),n,w.address);a[n]=0;strcopy(ty,sizeof(ty),type_name(t));n=0;append_value(sv,sizeof(sv),n,t,w.scanValue);sv[n]=0;u8 raw[8]{};bool readable=ui_read_value(w.address,t,raw);n=0;if(readable)append_value(cv,sizeof(cv),n,t,raw);else append_str(cv,sizeof(cv),n,ui_tr("common.unavailable"));cv[n]=0;
        UiRect nameEdit{cols[1].x,row.y+4,ui_maxi(24,cols[1].w-6),row.h-8};bool editName=sel&&g_uiTextFocus==UI_TEXT_WATCH_NAME;if(editName)ui_input(dc,nameEdit,g_uiWatchNameText,UI_TEXT_WATCH_NAME,true,g_fontSmall);else{if(ui_hover(cols[1]))ui_round(dc,nameEdit,g_brushSurface,g_penBorder,5);const char* name=w.name[0]?w.name:(sel?"Clique para nomear":"-");ui_text(dc,name,{cols[1].x+5,row.y,cols[1].w-10,row.h},w.name[0]?Z100:Z600,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);}
        ui_text(dc,a,{cols[2].x+4,row.y,cols[2].w-8,row.h},Z200,g_fontMono,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);ui_text(dc,ty,{cols[3].x+4,row.y,cols[3].w-8,row.h},Z400,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);ui_text(dc,sv,{cols[4].x+4,row.y,cols[4].w-8,row.h},Z200,g_fontMono,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
        UiRect valueEdit{},saveRect{};ui_watch_value_edit_rects(row,valueEdit,saveRect);bool editValue=sel&&g_uiTextFocus==UI_TEXT_WATCH;if(editValue){ui_input(dc,valueEdit,g_uiWatchText,UI_TEXT_WATCH,true,g_fontMono);ui_icon_action_button(dc,saveRect,UI_ICON_SAVE,GREEN400,!g_uiBusy);}else{UiRect hoverRect{cols[5].x,row.y+4,ui_maxi(24,cols[5].w-6),row.h-8};if(ui_hover(cols[5]))ui_round(dc,hoverRect,g_brushSurface,g_penBorder,5);ui_text(dc,cv,{cols[5].x+5,row.y,cols[5].w-10,row.h},readable?Z100:AMBER400,g_fontMono,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);}
        UiRect pointerRect{},removeRect{};ui_watch_action_rects(row,pointerRect,removeRect);ui_icon_action_button(dc,pointerRect,UI_ICON_POINTER,BLUE300,!g_uiBusy);ui_icon_action_button(dc,removeRect,UI_ICON_DELETE,RED400,!g_uiBusy);if(editValue&&ui_hover(saveRect)){tooltipText=ui_tr("watch.saveValue");tooltipAnchor=saveRect;}else if(ui_hover(pointerRect)){tooltipText=ui_tr("watch.openPointers");tooltipAnchor=pointerRect;}else if(ui_hover(removeRect)){tooltipText=ui_tr("watch.remove");tooltipAnchor=removeRect;}
    }
    ui_draw_scrollbar(dc,g_ui.watchTable,g_uiWatchCount,g_uiWatchScroll,visible);if(tooltipText)ui_tooltip(dc,tooltipAnchor,tooltipText);
}


static void ui_pointer_take_selected_watch(){
    if(g_uiSelectedWatch<0||g_uiSelectedWatch>=(int)UI_WATCH_LIMIT||!g_uiWatches[g_uiSelectedWatch].active){ui_set_status(ui_tr("pointers.selectAddressFirst"),2);return;}
    UiWatch_& w=g_uiWatches[g_uiSelectedWatch];g_uiPointerTargetValid=true;g_uiPointerTarget=w.address;g_uiPointerTargetType=w.type;memzero(g_uiPointerTargetScanValue,8);memcopy(g_uiPointerTargetScanValue,w.scanValue,type_size((ValueType)w.type));g_uiSelectedPointer=-1;g_uiPointerScroll=0;ui_pointer_reset_cache();g_uiView=UI_VIEW_POINTERS;g_uiPopup=UI_POP_NONE;
    if(g_pointerChainCount){ui_set_status(ui_tr("pointers.targetChangedRescan"),1);}else ui_set_status(ui_tr("pointers.targetSetSearch"),1);InvalidateRect(g_hwnd,nullptr,0);
}
static void ui_pointer_apply_preset(u64& depth,u64& maxOffset,u64& maxNegative,u64& maxChains,u64& branch,u64& indexLimit,u64& alignment,u64& searchBudget,bool& writableOnly){
    // Bounded presets: maxCandidatesPerNode + a global search budget prevent
    // exponential searches from looking frozen forever.
    if(g_uiPointerPreset==0){depth=3;maxOffset=0x400;maxNegative=0;maxChains=5000;branch=256;indexLimit=3000000;alignment=0;searchBudget=250000;writableOnly=true;}
    else if(g_uiPointerPreset==2){depth=6;maxOffset=0x4000;maxNegative=0x400;maxChains=10000;branch=2048;indexLimit=MAX_POINTER_ENTRIES;alignment=4;searchBudget=4000000;writableOnly=false;}
    else{depth=4;maxOffset=0x1000;maxNegative=0;maxChains=10000;branch=768;indexLimit=5000000;alignment=0;searchBudget=1250000;writableOnly=true;}
}
static void ui_pointer_reset_cache(){memzero(g_uiPointerResolvedCache,sizeof(g_uiPointerResolvedCache));memzero(g_uiPointerResolveState,sizeof(g_uiPointerResolveState));memzero(g_uiPointerValueCache,sizeof(g_uiPointerValueCache));memzero(g_uiPointerValueState,sizeof(g_uiPointerValueState));}
static void ui_pointer_refresh_visible_cache(){
    if(g_uiBusy||!g_process||!g_pointerChainCount||g_chainPointerSize!=g_pointerSize)return;if(!g_moduleCount&&!refresh_modules())return;int visible=ui_maxi(1,(g_ui.pointerTable.h-34)/32);int start=g_uiPointerScroll;int end=ui_mini((int)g_pointerChainCount,start+visible);ValueType t=(ValueType)g_uiPointerTargetType;for(int i=start;i<end;++i){uptr addr=0;if(resolve_pointer_chain(g_pointerChains[i],addr)){g_uiPointerResolvedCache[i]=addr;g_uiPointerResolveState[i]=2;u8 raw[8]{};if(t!=ValueType::Invalid&&t!=ValueType::Mixed&&ui_read_value(addr,t,raw)){memcopy(g_uiPointerValueCache[i],raw,type_size(t));g_uiPointerValueState[i]=2;}else g_uiPointerValueState[i]=1;}else{g_uiPointerResolvedCache[i]=0;g_uiPointerResolveState[i]=1;g_uiPointerValueState[i]=1;}}
}
static DWORD __stdcall ui_pointer_worker(LPVOID){
    bool ok=true;bool cancelled=false;g_pointerCancelRequested=0;g_uiPointerIndexed=0;g_uiPointerBefore=g_pointerChainCount;g_uiPointerLevel1Candidates=0;g_uiPointerIndexTruncated=false;g_uiPointerAutoRootFallback=false;g_uiPointerSearchTruncated=false;g_uiPointerSearchBudgetHit=false;g_uiPointerTargetedUsed=false;g_pointerSearchSteps=0;g_pointerSearchBudgetHit=0;g_pointerLayerSlots=0;g_pointerLayerMatches=0;g_pointerLayerFrontier=0;g_pointerLayerDepth=0;g_pointerLayerMaxDepth=0;g_pointerLayerTruncated=0;g_uiPointerPhase=(g_uiTask.kind==4)?4:1;
    if(!g_process)ok=false;if(ok&&!refresh_modules())ok=false;
    if(ok){BOOL wow=0;if(IsWow64Process((HANDLE)g_process,&wow))g_pointerSize=wow?4:8;g_pointerAlignment=(usize)g_uiTask.pointerAlignment;g_pointerWritableOnly=g_uiTask.pointerWritableOnly;g_pointerPrivateOnly=false;g_pointerBranchCap=(usize)g_uiTask.pointerBranch;g_pointerIndexLimit=(usize)g_uiTask.pointerIndexLimit;g_pointerSearchBudget=g_uiTask.pointerSearchBudget;if(g_uiTask.pointerRootAny)g_pointerRootModule[0]=0;else strcopy(g_pointerRootModule,sizeof(g_pointerRootModule),g_uiAttachedName);}
    if(ok&&g_uiTask.kind==3){
        clear_pointer_chains();g_chainPointerSize=g_pointerSize;
        if(g_uiPointerPreset==2){
            // Deep mode is index-free: breadth-first targeted reverse scans avoid
            // losing useful pointers simply because a huge managed heap exceeded
            // an arbitrary global index cap.
            g_uiPointerTargetedUsed=true;g_uiPointerIndexed=0;g_uiPointerIndexTruncated=false;g_uiPointerLevel1Candidates=0;
            usize parentCap=(usize)g_uiTask.pointerBranch;g_uiPointerPhase=5;ok=pointer_layered_search(g_uiTask.pointerTarget,(u8)g_uiTask.pointerDepth,(uptr)g_uiTask.pointerMaxOffset,(uptr)g_uiTask.pointerMaxNegative,(usize)g_uiTask.pointerMaxChains,(usize)g_uiTask.pointerAlignment,parentCap);
            if(ok&&!g_pointerCancelRequested&&!g_pointerChainCount&&!g_uiTask.pointerRootAny&&g_pointerRootModule[0]){g_pointerRootModule[0]=0;g_uiPointerAutoRootFallback=true;g_uiPointerPhase=6;ok=pointer_layered_search(g_uiTask.pointerTarget,(u8)g_uiTask.pointerDepth,(uptr)g_uiTask.pointerMaxOffset,(uptr)g_uiTask.pointerMaxNegative,(usize)g_uiTask.pointerMaxChains,(usize)g_uiTask.pointerAlignment,parentCap);}
            g_uiPointerSearchTruncated=(g_pointerLayerTruncated!=0)||g_pointerChainsTruncated;if(g_pointerCancelRequested)cancelled=true;
        }else{
            g_pointerIndexLimit=(usize)g_uiTask.pointerIndexLimit;bool indexed=build_pointer_index();if(g_pointerCancelRequested){cancelled=true;}else if(!indexed)ok=false;
            if(ok&&!cancelled){
                g_uiPointerIndexed=g_pointerCount;g_uiPointerIndexTruncated=g_pointerIndexTruncated;g_uiPointerLevel1Candidates=pointer_near_target_count(g_uiTask.pointerTarget,(uptr)g_uiTask.pointerMaxOffset,(uptr)g_uiTask.pointerMaxNegative);
                g_uiPointerPhase=2;g_pointerSearchSteps=0;g_pointerSearchBudgetHit=0;
                i64 rev[MAX_POINTER_DEPTH]={};uptr path[MAX_POINTER_DEPTH+1]={};path[0]=g_uiTask.pointerTarget;pointer_dfs(g_uiTask.pointerTarget,(u8)g_uiTask.pointerDepth,(uptr)g_uiTask.pointerMaxOffset,(uptr)g_uiTask.pointerMaxNegative,(usize)g_uiTask.pointerMaxChains,rev,0,path,1);
                g_uiPointerSearchBudgetHit=g_pointerSearchBudgetHit!=0;g_uiPointerSearchTruncated=g_pointerChainsTruncated||g_uiPointerSearchBudgetHit;
                if(!g_pointerCancelRequested&&!g_pointerSearchBudgetHit&&g_pointerChainCount==0&&!g_uiTask.pointerRootAny){
                    g_pointerRootModule[0]=0;g_uiPointerAutoRootFallback=true;g_pointerChainsTruncated=false;g_pointerSearchSteps=0;g_pointerSearchBudgetHit=0;g_uiPointerPhase=3;
                    pointer_dfs(g_uiTask.pointerTarget,(u8)g_uiTask.pointerDepth,(uptr)g_uiTask.pointerMaxOffset,(uptr)g_uiTask.pointerMaxNegative,(usize)g_uiTask.pointerMaxChains,rev,0,path,1);
                    g_uiPointerSearchBudgetHit=g_uiPointerSearchBudgetHit||(g_pointerSearchBudgetHit!=0);g_uiPointerSearchTruncated=g_uiPointerSearchTruncated||g_pointerChainsTruncated||(g_pointerSearchBudgetHit!=0);
                }
                // Incomplete monolithic indexes are not treated as a final answer.
                // Fall back to a targeted layered scan that never needs an 8M index.
                if(!g_pointerCancelRequested&&g_pointerChainCount==0&&(g_pointerIndexTruncated||g_uiPointerSearchBudgetHit)){
                    g_uiPointerTargetedUsed=true;g_pointerRootModule[0]=0;g_uiPointerAutoRootFallback=true;clear_pointer_index();g_uiPointerPhase=5;g_pointerChainsTruncated=false;g_pointerSearchBudgetHit=0;
                    usize targetedAlign=(usize)g_pointerSize;usize parentCap=(usize)g_uiTask.pointerBranch;ok=pointer_layered_search(g_uiTask.pointerTarget,(u8)g_uiTask.pointerDepth,(uptr)g_uiTask.pointerMaxOffset,(uptr)g_uiTask.pointerMaxNegative,(usize)g_uiTask.pointerMaxChains,targetedAlign,parentCap);
                    g_uiPointerSearchTruncated=g_uiPointerSearchTruncated||(g_pointerLayerTruncated!=0)||g_pointerChainsTruncated;
                }
                if(g_pointerCancelRequested)cancelled=true;
            }
        }
        clear_pointer_index();if(cancelled)clear_pointer_chains();
    }else if(ok&&g_uiTask.kind==4){
        if(!g_pointerChainCount||!g_uiPointerTargetValid)ok=false;else if(g_chainPointerSize&&g_chainPointerSize!=g_pointerSize)ok=false;else{usize before=g_pointerChainCount,out=0;PointerChain_* tmp=(PointerChain_*)HeapAlloc(g_heap,0,before*sizeof(PointerChain_));if(!tmp)ok=false;else{for(usize i=0;i<before&&!g_pointerCancelRequested;++i){uptr resolved=0;if(resolve_pointer_chain(g_pointerChains[i],resolved)&&resolved==g_uiTask.pointerTarget)tmp[out++]=g_pointerChains[i];}if(g_pointerCancelRequested)cancelled=true;else{for(usize i=0;i<out;++i)g_pointerChains[i]=tmp[i];g_pointerChainCount=out;}HeapFree(g_heap,0,tmp);}}
    }
    PostMessageA(g_hwnd,WM_APP_POINTER_DONE_,cancelled?2:(ok?1:0),(LPARAM)g_uiTask.kind);return 0;
}
static bool ui_filter_pair(char* filter,usize cap,usize& n,const char* label,const char* pattern){
    if(!filter||!label||!pattern)return false;usize ll=cstrlen(label),pl=cstrlen(pattern);if(n+ll+1+pl+2>cap)return false;memcopy(filter+n,label,ll);n+=ll;filter[n++]=0;memcopy(filter+n,pattern,pl);n+=pl;filter[n++]=0;filter[n]=0;return true;
}
static bool ui_pointer_file_dialog(bool save,char out[260]){
    HINSTANCE lib=LoadLibraryA("comdlg32.dll");if(!lib){ui_set_status(ui_tr("dialog.filePickerFailed"),3);return false;}
    using Fn=BOOL (__stdcall *)(OPENFILENAMEA_*);auto fn=(Fn)GetProcAddress(lib,save?"GetSaveFileNameA":"GetOpenFileNameA");if(!fn){ui_set_status(ui_tr("dialog.fileDialogUnavailable"),3);return false;}
    char filter[512]{};usize filterN=0;bool filterOk=false;if(save){filterOk=ui_filter_pair(filter,sizeof(filter),filterN,ui_tr("dialog.pointerProfile"),"*.cwptr")&&ui_filter_pair(filter,sizeof(filter),filterN,ui_tr("dialog.allFiles"),"*.*");}else{filterOk=ui_filter_pair(filter,sizeof(filter),filterN,ui_tr("dialog.pointerProfiles"),"*.cwptr;*.mcptr")&&ui_filter_pair(filter,sizeof(filter),filterN,ui_tr("dialog.pointerProfile"),"*.cwptr")&&ui_filter_pair(filter,sizeof(filter),filterN,ui_tr("dialog.legacyPointerProfile"),"*.mcptr")&&ui_filter_pair(filter,sizeof(filter),filterN,ui_tr("dialog.allFiles"),"*.*");}if(!filterOk)return false;
    out[0]=0;OPENFILENAMEA_ ofn{};ofn.lStructSize=(DWORD)sizeof(ofn);ofn.hwndOwner=g_hwnd;ofn.lpstrFilter=filter;ofn.nFilterIndex=1;ofn.lpstrFile=out;ofn.nMaxFile=260;ofn.lpstrTitle=save?ui_tr("dialog.pointerSaveTitle"):ui_tr("dialog.pointerLoadTitle");ofn.lpstrDefExt="cwptr";ofn.Flags=0x00080000u|0x00000800u|0x00000004u|(save?0x00000002u:0x00001000u);
    return fn(&ofn)!=0;
}
static bool ui_pointer_profile_meta_file(const char* path,char proc[260],u8& type,u64& count){
    if(proc)proc[0]=0;type=(u8)ValueType::Invalid;count=0;if(!path||!*path)return false;HANDLE h=CreateFileA(path,GENERIC_READ,1,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS)return false;
    const char expect[8]={'C','W','P','R','O','F','0','1'};const char legacy[8]={'M','C','E','P','R','O','F','1'};char magic[8]{};u32 ver=0,ps=0,ty=0;u16 plen=0;bool ok=file_read_exact(h,magic,8)&&file_read_exact(h,&ver,4)&&file_read_exact(h,&ps,4)&&file_read_exact(h,&ty,4)&&file_read_exact(h,&plen,2)&&file_read_exact(h,&count,8);
    if(!ok||(!memequal(magic,expect,8)&&!memequal(magic,legacy,8))||ver!=1||(ps!=4&&ps!=8)||ty>(u32)ValueType::Double||plen>=260||count==0||count>MAX_POINTER_CHAINS){CloseHandle(h);return false;}if(plen&&!file_read_exact(h,proc,plen)){CloseHandle(h);return false;}proc[plen]=0;type=(u8)ty;CloseHandle(h);return true;
}
static bool ui_save_pointer_profile_file(const char* path){
    if(!path||!*path||!g_pointerChainCount||g_chainPointerSize==0)return false;ValueType t=(ValueType)g_uiPointerTargetType;if(t==ValueType::Invalid||t==ValueType::Mixed)return false;
    HANDLE h=CreateFileA(path,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS)return false;
    const char magic[8]={'C','W','P','R','O','F','0','1'};u32 ver=1,ps=g_chainPointerSize,ty=(u32)t;usize pl=cstrlen(g_uiAttachedName);if(pl>255)pl=255;u16 plen=(u16)pl;u64 count=(u64)g_pointerChainCount;
    bool ok=file_write_all(h,magic,8)&&file_write_all(h,&ver,4)&&file_write_all(h,&ps,4)&&file_write_all(h,&ty,4)&&file_write_all(h,&plen,2)&&file_write_all(h,&count,8);if(ok&&plen)ok=file_write_all(h,g_uiAttachedName,plen);
    for(usize i=0;ok&&i<g_pointerChainCount;++i){PointerChain_& c=g_pointerChains[i];usize ml=cstrlen(c.module);if(!ml||ml>255||!c.depth||c.depth>MAX_POINTER_DEPTH){ok=false;break;}u16 mlen=(u16)ml;u64 root=(u64)c.rootOffset;u32 depth=(u32)c.depth;ok=file_write_all(h,&mlen,2)&&file_write_all(h,c.module,ml)&&file_write_all(h,&root,8)&&file_write_all(h,&depth,4);for(u32 j=0;ok&&j<depth;++j){u64 raw=0;memcopy(&raw,&c.offsets[j],8);ok=file_write_all(h,&raw,8);}}
    CloseHandle(h);if(ok){strcopy(g_uiPointerProfilePath,sizeof(g_uiPointerProfilePath),path);strcopy(g_uiPointerProfileProcess,sizeof(g_uiPointerProfileProcess),g_uiAttachedName);g_uiPointerProfileType=(u8)t;}return ok;
}
static bool ui_load_pointer_profile_file(const char* path){
    HANDLE h=CreateFileA(path,GENERIC_READ,1,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS)return false;const char expect[8]={'C','W','P','R','O','F','0','1'};const char legacy[8]={'M','C','E','P','R','O','F','1'};char magic[8]{};u32 ver=0,ps=0,ty=0;u16 plen=0;u64 count=0;bool ok=file_read_exact(h,magic,8)&&file_read_exact(h,&ver,4)&&file_read_exact(h,&ps,4)&&file_read_exact(h,&ty,4)&&file_read_exact(h,&plen,2)&&file_read_exact(h,&count,8);
    if(!ok||(!memequal(magic,expect,8)&&!memequal(magic,legacy,8))||ver!=1||(ps!=4&&ps!=8)||ty>(u32)ValueType::Double||plen>=260||count==0||count>MAX_POINTER_CHAINS){CloseHandle(h);return false;}char proc[260]{};if(plen&&!file_read_exact(h,proc,plen)){CloseHandle(h);return false;}proc[plen]=0;if(g_process&&ps!=g_pointerSize){CloseHandle(h);return false;}
    clear_pointer_index();clear_pointer_chains();if(!reserve_pointer_chains((usize)count)){CloseHandle(h);return false;}for(u64 i=0;i<count&&ok;++i){PointerChain_ c{};u16 ml=0;u64 root=0;u32 depth=0;if(!file_read_exact(h,&ml,2)||ml==0||ml>=256||!file_read_exact(h,c.module,ml)||!file_read_exact(h,&root,8)||!file_read_exact(h,&depth,4)||depth==0||depth>MAX_POINTER_DEPTH){ok=false;break;}c.module[ml]=0;c.rootOffset=(uptr)root;c.depth=(u8)depth;for(u32 j=0;j<depth;++j){u64 raw=0;if(!file_read_exact(h,&raw,8)){ok=false;break;}memcopy(&c.offsets[j],&raw,8);}if(ok)g_pointerChains[g_pointerChainCount++]=c;}
    CloseHandle(h);if(!ok){clear_pointer_chains();return false;}g_chainPointerSize=(u8)ps;g_pointerChainsTruncated=false;g_uiPointerTargetType=(u8)ty;g_uiPointerProfileType=(u8)ty;strcopy(g_uiPointerProfilePath,sizeof(g_uiPointerProfilePath),path);strcopy(g_uiPointerProfileProcess,sizeof(g_uiPointerProfileProcess),proc);g_uiSelectedPointer=0;g_uiPointerScroll=0;ui_pointer_reset_cache();return true;
}
static void sort_uptr_values(uptr* a,usize count){if(!a||count<2)return;auto sift=[&](usize start,usize n){usize root=start;for(;;){usize child=root*2+1;if(child>=n)return;usize best=root;if(a[best]<a[child])best=child;if(child+1<n&&a[best]<a[child+1])best=child+1;if(best==root)return;uptr v=a[root];a[root]=a[best];a[best]=v;root=best;}};for(usize i=count/2;i>0;--i)sift(i-1,count);for(usize end=count;end>1;--end){uptr v=a[0];a[0]=a[end-1];a[end-1]=v;sift(0,end-1);}}
static bool ui_resolve_pointer_profile(uptr& address,usize& agreeing,usize& resolvedCount){
    address=0;agreeing=0;resolvedCount=0;if(!g_process||!g_pointerChainCount)return false;if(!refresh_modules())return false;uptr* values=(uptr*)HeapAlloc(g_heap,0,g_pointerChainCount*sizeof(uptr));if(!values)return false;for(usize i=0;i<g_pointerChainCount;++i){uptr r=0;if(resolve_pointer_chain(g_pointerChains[i],r))values[resolvedCount++]=r;}if(!resolvedCount){HeapFree(g_heap,0,values);return false;}sort_uptr_values(values,resolvedCount);uptr best=values[0];usize bestCount=1,run=1;for(usize i=1;i<resolvedCount;++i){if(values[i]==values[i-1]){++run;}else{if(run>bestCount){bestCount=run;best=values[i-1];}run=1;}}if(run>bestCount){bestCount=run;best=values[resolvedCount-1];}HeapFree(g_heap,0,values);address=best;agreeing=bestCount;return true;
}
static void ui_save_pointer_profile(){char path[260]{};if(!g_pointerChainCount){ui_set_status(ui_tr("pointers.saveNeedChains"),2);return;}if(!ui_pointer_file_dialog(true,path))return;if(ui_save_pointer_profile_file(path)){char b[300]{};usize n=0;append_str(b,sizeof(b),n,ui_tr("pointers.profileSavedPrefix"));append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n,ui_tr("pointers.profileSavedSuffix"));b[n]=0;ui_set_status(b,1);}else ui_set_status(ui_tr("pointers.saveFailed"),3);InvalidateRect(g_hwnd,nullptr,0);}
static void ui_load_pointer_profile(){char path[260]{};if(!ui_pointer_file_dialog(false,path))return;if(!ui_load_pointer_profile_file(path)){ui_set_status(ui_tr("pointers.loadInvalid"),3);return;}uptr a=0;usize agree=0,res=0;if(g_process&&ui_resolve_pointer_profile(a,agree,res)){g_uiPointerTarget=a;g_uiPointerTargetValid=(agree*2>res);char b[380]{};usize n=0;append_str(b,sizeof(b),n,ui_tr("pointers.profileLoadedPrefix"));append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n,ui_tr("pointers.profileLoadedConsensus"));append_u64_dec(b,sizeof(b),n,agree);append_str(b,sizeof(b),n,"/");append_u64_dec(b,sizeof(b),n,res);append_str(b,sizeof(b),n,g_uiPointerTargetValid?ui_tr("pointers.profileLoadedSame"):ui_tr("pointers.profileLoadedAmbiguous"));b[n]=0;ui_set_status(b,g_uiPointerTargetValid?1:2);}else{g_uiPointerTargetValid=false;ui_set_status(ui_tr("pointers.profileLoadedAttach"),1);}InvalidateRect(g_hwnd,nullptr,0);}
static void ui_add_pointer_profile_to_watch(){
    if(!g_process||!g_pointerChainCount){ui_set_status(ui_tr("pointers.needProfile"),2);return;}ValueType t=(ValueType)g_uiPointerTargetType;if(t==ValueType::Invalid||t==ValueType::Mixed){ui_set_status(ui_tr("pointers.invalidProfileType"),3);return;}uptr address=0;usize agreeing=0,resolved=0;if(!ui_resolve_pointer_profile(address,agreeing,resolved)){ui_set_status(ui_tr("pointers.noResolvedChain"),3);return;}if(agreeing*2<=resolved){ui_set_status(ui_tr("pointers.ambiguousProfile"),3);return;}if(ui_find_watch(address,t)>=0){ui_set_status(ui_tr("pointers.resolvedAlreadyListed"),0);return;}int slot=-1;for(int i=0;i<(int)UI_WATCH_LIMIT;++i)if(!g_uiWatches[i].active){slot=i;break;}if(slot<0){ui_set_status(ui_tr("status.addressListFull"),3);return;}UiWatch_& w=g_uiWatches[slot];w.active=true;w.address=address;w.type=(u8)t;w.name[0]=0;memzero(w.scanValue,8);u8 raw[8]{};if(ui_read_value(address,t,raw))memcopy(w.scanValue,raw,type_size(t));++g_uiWatchCount;g_uiSelectedWatch=slot;ui_fill_watch_edit(true);ui_watch_list_changed(true);g_uiPointerTarget=address;g_uiPointerTargetValid=true;char b[340]{};usize n=0;append_str(b,sizeof(b),n,ui_tr("pointers.addedPrefix"));append_u64_dec(b,sizeof(b),n,agreeing);append_str(b,sizeof(b),n,"/");append_u64_dec(b,sizeof(b),n,resolved);append_str(b,sizeof(b),n,ui_tr("pointers.addedSuffix"));b[n]=0;ui_set_status(b,agreeing?1:2);g_uiView=UI_VIEW_SCANNER;InvalidateRect(g_hwnd,nullptr,0);
}


static void ui_add_pointer_chain_to_watch(int idx){
    if(!g_process||idx<0||(usize)idx>=g_pointerChainCount){ui_set_status(ui_tr("pointers.chainUnavailable"),2);return;}ValueType t=(ValueType)g_uiPointerTargetType;if(t==ValueType::Invalid||t==ValueType::Mixed){ui_set_status(ui_tr("pointers.invalidProfileType"),3);return;}uptr address=0;if(g_uiPointerResolveState[idx]==2)address=g_uiPointerResolvedCache[idx];else if(!resolve_pointer_chain(g_pointerChains[idx],address)){ui_set_status(ui_tr("pointers.chainResolveFailed"),3);return;}
    int ex=ui_find_watch(address,t);if(ex>=0){g_uiSelectedWatch=ex;ui_fill_watch_edit(true);g_uiView=UI_VIEW_SCANNER;ui_set_status(ui_tr("pointers.chainAlreadySelected"),0);InvalidateRect(g_hwnd,nullptr,0);return;}
    int slot=-1;for(int i=0;i<(int)UI_WATCH_LIMIT;++i)if(!g_uiWatches[i].active){slot=i;break;}if(slot<0){ui_set_status(ui_tr("status.addressListFull"),3);return;}UiWatch_& w=g_uiWatches[slot];w.active=true;w.address=address;w.type=(u8)t;w.name[0]=0;memzero(w.scanValue,8);u8 raw[8]{};if(ui_read_value(address,t,raw))memcopy(w.scanValue,raw,type_size(t));++g_uiWatchCount;g_uiSelectedWatch=slot;int row=ui_watch_row_for_slot(slot);int visible=ui_maxi(1,(g_ui.watchTable.h-34)/UI_WATCH_ROW_H);if(row>=g_uiWatchScroll+visible)g_uiWatchScroll=row-visible+1;ui_fill_watch_edit(true);ui_watch_list_changed(true);g_uiPointerTarget=address;g_uiPointerTargetValid=true;g_uiView=UI_VIEW_SCANNER;char b[220]{};usize n=0;append_str(b,sizeof(b),n,ui_tr("pointers.chainPrefix"));append_u64_dec(b,sizeof(b),n,(u64)idx);append_str(b,sizeof(b),n,ui_tr("pointers.chainAddedSuffix"));b[n]=0;ui_set_status(b,1);InvalidateRect(g_hwnd,nullptr,0);
}

static const char* ui_path_basename(const char* path){const char* last=path?path:"";for(const char* p=last;*p;++p)if(*p=='\\'||*p=='/')last=p+1;return last;}
static int ui_trainer_element_for_entry(int entryIndex){for(int i=0;i<g_uiTrainerElementCount;++i)if(g_uiTrainerElements[i].active&&g_uiTrainerElements[i].type==UI_TRAINER_FIELD&&g_uiTrainerElements[i].entryIndex==entryIndex)return i;return -1;}
static bool ui_trainer_append_element(u8 type,int entryIndex,const char* text){if(g_uiTrainerElementCount>=(int)UI_TRAINER_ELEMENT_LIMIT)return false;UiTrainerElement_& el=g_uiTrainerElements[g_uiTrainerElementCount];memzero(&el,sizeof(el));el.active=true;el.type=type;el.entryIndex=entryIndex;if(text)strcopy(el.text,sizeof(el.text),text);g_uiTrainerElementSelected=g_uiTrainerElementCount++;g_uiTrainerElementScroll=g_uiTrainerElementSelected;return true;}
static void ui_trainer_sync_fields(){if(g_uiTrainerSelected>=0&&g_uiTrainerSelected<g_uiTrainerCount){UiTrainerEntry_& e=g_uiTrainerEntries[g_uiTrainerSelected];strcopy(g_uiTrainerLabel,sizeof(g_uiTrainerLabel),e.label);strcopy(g_uiTrainerDefault,sizeof(g_uiTrainerDefault),e.defaultValue);}else{g_uiTrainerLabel[0]=0;g_uiTrainerDefault[0]=0;}if(g_uiTrainerElementSelected>=0&&g_uiTrainerElementSelected<g_uiTrainerElementCount){UiTrainerElement_& el=g_uiTrainerElements[g_uiTrainerElementSelected];if(el.type==UI_TRAINER_FIELD){g_uiTrainerSelected=el.entryIndex;g_uiTrainerElementText[0]=0;if(g_uiTrainerSelected>=0&&g_uiTrainerSelected<g_uiTrainerCount){UiTrainerEntry_& e=g_uiTrainerEntries[g_uiTrainerSelected];strcopy(g_uiTrainerLabel,sizeof(g_uiTrainerLabel),e.label);strcopy(g_uiTrainerDefault,sizeof(g_uiTrainerDefault),e.defaultValue);}}else{g_uiTrainerSelected=-1;g_uiTrainerLabel[0]=0;g_uiTrainerDefault[0]=0;strcopy(g_uiTrainerElementText,sizeof(g_uiTrainerElementText),el.text);}}else g_uiTrainerElementText[0]=0;}
static void ui_trainer_add_profile_path(const char* path){
    if(!path||!*path){ui_set_status(ui_tr("trainer.selectProfileFile"),2);return;}if(g_uiTrainerCount>=(int)UI_TRAINER_ENTRY_LIMIT){ui_set_status(ui_tr("trainer.entryLimit"),3);return;}
    char proc[260]{};u8 ty=(u8)ValueType::Invalid;u64 chains=0;if(!ui_pointer_profile_meta_file(path,proc,ty,chains)){ui_set_status(ui_tr("trainer.invalidProfile"),3);return;}if(!proc[0]){ui_set_status(ui_tr("trainer.profileNoProcess"),3);return;}
    if(g_uiTrainerProcess[0]&&!strieq(g_uiTrainerProcess,proc)){ui_set_status(ui_tr("trainer.profileOtherProcess"),3);return;}if(!g_uiTrainerProcess[0])strcopy(g_uiTrainerProcess,sizeof(g_uiTrainerProcess),proc);
    for(int i=0;i<g_uiTrainerCount;++i)if(strieq(g_uiTrainerEntries[i].profile,path)){g_uiTrainerSelected=i;g_uiTrainerElementSelected=ui_trainer_element_for_entry(i);ui_trainer_sync_fields();ui_set_status(ui_tr("trainer.profileAlreadyAdded"),0);InvalidateRect(g_hwnd,nullptr,0);return;}
    UiTrainerEntry_& e=g_uiTrainerEntries[g_uiTrainerCount];memzero(&e,sizeof(e));e.active=true;char id[64]{};usize n=0;append_str(id,sizeof(id),n,"entry");append_u64_dec(id,sizeof(id),n,(u64)(g_uiTrainerCount+1));id[n]=0;strcopy(e.id,sizeof(e.id),id);
    const char* base=ui_path_basename(path);char label[128]{};usize li=0;while(base[li]&&base[li]!='.'&&li+1<sizeof(label)){label[li]=base[li];++li;}label[li]=0;if(!label[0])strcopy(label,sizeof(label),id);strcopy(e.label,sizeof(e.label),label);strcopy(e.profile,sizeof(e.profile),path);e.defaultValue[0]=0;e.showCurrent=true;e.allowWrite=true;e.allowFreeze=true;
    ++g_uiTrainerCount;g_uiTrainerSelected=g_uiTrainerCount-1;if(!ui_trainer_append_element(UI_TRAINER_FIELD,g_uiTrainerSelected,nullptr)){--g_uiTrainerCount;memzero(&e,sizeof(e));ui_set_status(ui_tr("trainer.elementLimit"),3);return;}ui_trainer_sync_fields();if(strieq(g_uiTrainerTitle,"Trainer")){char t[128]{};n=0;append_str(t,sizeof(t),n,g_uiTrainerProcess);append_str(t,sizeof(t),n," Trainer");t[n]=0;strcopy(g_uiTrainerTitle,sizeof(g_uiTrainerTitle),t);}char m[260]{};n=0;append_str(m,sizeof(m),n,ui_tr("trainer.fieldAddedPrefix"));append_str(m,sizeof(m),n,ui_path_basename(path));append_str(m,sizeof(m),n," | ");append_u64_dec(m,sizeof(m),n,chains);append_str(m,sizeof(m),n,ui_tr("trainer.chainCountSuffix"));m[n]=0;ui_set_status(m,1);InvalidateRect(g_hwnd,nullptr,0);
}
static void ui_trainer_add_profile_file(){char path[260]{};if(!ui_pointer_file_dialog(false,path))return;ui_trainer_add_profile_path(path);}
static void ui_trainer_add_current_profile(){if(!g_uiPointerProfilePath[0]){ui_set_status(ui_tr("trainer.saveOrLoadProfile"),2);return;}ui_trainer_add_profile_path(g_uiPointerProfilePath);}
static void ui_trainer_add_text_element(u8 type){if(type!=UI_TRAINER_TITLE&&type!=UI_TRAINER_SUBTITLE)return;const char* text=type==UI_TRAINER_TITLE?ui_tr("trainer.newTitle"):ui_tr("trainer.newSubtitle");if(!ui_trainer_append_element(type,-1,text)){ui_set_status(ui_tr("trainer.elementLimit"),3);return;}g_uiTrainerSelected=-1;ui_trainer_sync_fields();g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;ui_set_status(type==UI_TRAINER_TITLE?ui_tr("trainer.titleAdded"):ui_tr("trainer.subtitleAdded"),1);InvalidateRect(g_hwnd,nullptr,0);}
static void ui_trainer_move_selected(int delta){if(g_uiTrainerElementSelected<0||g_uiTrainerElementSelected>=g_uiTrainerElementCount||!delta)return;int to=g_uiTrainerElementSelected+delta;if(to<0||to>=g_uiTrainerElementCount)return;UiTrainerElement_ tmp{};memcopy(&tmp,&g_uiTrainerElements[g_uiTrainerElementSelected],sizeof(tmp));memcopy(&g_uiTrainerElements[g_uiTrainerElementSelected],&g_uiTrainerElements[to],sizeof(tmp));memcopy(&g_uiTrainerElements[to],&tmp,sizeof(tmp));g_uiTrainerElementSelected=to;g_uiTrainerElementScroll=g_uiTrainerElementSelected;ui_trainer_sync_fields();g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;ui_set_status(delta<0?ui_tr("trainer.movedUp"):ui_tr("trainer.movedDown"),0);InvalidateRect(g_hwnd,nullptr,0);}
static void ui_trainer_remove_selected(){if(g_uiTrainerElementSelected<0||g_uiTrainerElementSelected>=g_uiTrainerElementCount)return;int removeElement=g_uiTrainerElementSelected;UiTrainerElement_ removed{};memcopy(&removed,&g_uiTrainerElements[removeElement],sizeof(removed));for(int i=removeElement;i+1<g_uiTrainerElementCount;++i)memcopy(&g_uiTrainerElements[i],&g_uiTrainerElements[i+1],sizeof(UiTrainerElement_));if(g_uiTrainerElementCount>0){--g_uiTrainerElementCount;memzero(&g_uiTrainerElements[g_uiTrainerElementCount],sizeof(UiTrainerElement_));}
    if(removed.type==UI_TRAINER_FIELD&&removed.entryIndex>=0&&removed.entryIndex<g_uiTrainerCount){int removedEntry=removed.entryIndex;for(int i=removedEntry;i+1<g_uiTrainerCount;++i)memcopy(&g_uiTrainerEntries[i],&g_uiTrainerEntries[i+1],sizeof(UiTrainerEntry_));if(g_uiTrainerCount>0){--g_uiTrainerCount;memzero(&g_uiTrainerEntries[g_uiTrainerCount],sizeof(UiTrainerEntry_));}for(int i=0;i<g_uiTrainerElementCount;++i)if(g_uiTrainerElements[i].type==UI_TRAINER_FIELD&&g_uiTrainerElements[i].entryIndex>removedEntry)--g_uiTrainerElements[i].entryIndex;if(!g_uiTrainerCount)g_uiTrainerProcess[0]=0;}
    if(g_uiTrainerElementSelected>=g_uiTrainerElementCount)g_uiTrainerElementSelected=g_uiTrainerElementCount-1;g_uiTrainerSelected=-1;ui_trainer_sync_fields();g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;ui_set_status(ui_tr("trainer.elementRemoved"),0);InvalidateRect(g_hwnd,nullptr,0);}
static int ui_hex_digit(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static bool ui_parse_hex_color(const char* s,COLORREF& out){if(!s)return false;if(*s=='#')++s;if(ui_text_len(s)!=6)return false;int v[6];for(int i=0;i<6;++i){v[i]=ui_hex_digit(s[i]);if(v[i]<0)return false;}out=rgb_((u8)(v[0]*16+v[1]),(u8)(v[2]*16+v[3]),(u8)(v[4]*16+v[5]));return true;}
static COLORREF ui_color_or(const char* s,COLORREF fallback){COLORREF c=fallback;ui_parse_hex_color(s,c);return c;}
static char ui_hex_upper(u8 v){return (char)(v<10?('0'+v):('A'+v-10));}
static void ui_format_hex_color(COLORREF c,char out[8]){u8 r=(u8)(c&0xFF),g=(u8)((c>>8)&0xFF),b=(u8)((c>>16)&0xFF);out[0]='#';out[1]=ui_hex_upper((u8)(r>>4));out[2]=ui_hex_upper((u8)(r&15));out[3]=ui_hex_upper((u8)(g>>4));out[4]=ui_hex_upper((u8)(g&15));out[5]=ui_hex_upper((u8)(b>>4));out[6]=ui_hex_upper((u8)(b&15));out[7]=0;}
static UiRect ui_color_swatch_rect(const UiRect& r){return UiRect{r.x+r.w-30,r.y+5,24,r.h-10};}
static bool ui_trainer_pick_color(char* target,COLORREF fallback){HINSTANCE lib=LoadLibraryA("comdlg32.dll");if(!lib){ui_set_status(ui_tr("trainer.colorUnavailable"),3);return false;}using Fn=BOOL (__stdcall *)(CHOOSECOLORA_*);auto fn=(Fn)GetProcAddress(lib,"ChooseColorA");if(!fn){ui_set_status(ui_tr("trainer.colorUnavailable"),3);return false;}static COLORREF custom[16]{};COLORREF initial=ui_color_or(target,fallback);CHOOSECOLORA_ cc{};cc.lStructSize=(DWORD)sizeof(cc);cc.hwndOwner=g_hwnd;cc.rgbResult=initial;cc.lpCustColors=custom;cc.Flags=0x00000001u|0x00000002u;if(!fn(&cc))return false;ui_format_hex_color(cc.rgbResult,target);g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;ui_set_status(ui_tr("trainer.colorUpdated"),1);InvalidateRect(g_hwnd,nullptr,0);return true;}
static bool ui_trainer_icon_dialog(char out[260]){HINSTANCE lib=LoadLibraryA("comdlg32.dll");if(!lib){ui_set_status(ui_tr("dialog.filePickerFailed"),3);return false;}using Fn=BOOL (__stdcall *)(OPENFILENAMEA_*);auto fn=(Fn)GetProcAddress(lib,"GetOpenFileNameA");if(!fn){ui_set_status(ui_tr("dialog.fileDialogUnavailable"),3);return false;}char filter[256]{};usize fnn=0;if(!ui_filter_pair(filter,sizeof(filter),fnn,ui_tr("dialog.windowsIcon"),"*.ico")||!ui_filter_pair(filter,sizeof(filter),fnn,ui_tr("dialog.allFiles"),"*.*"))return false;out[0]=0;OPENFILENAMEA_ ofn{};ofn.lStructSize=(DWORD)sizeof(ofn);ofn.hwndOwner=g_hwnd;ofn.lpstrFilter=filter;ofn.nFilterIndex=1;ofn.lpstrFile=out;ofn.nMaxFile=260;ofn.lpstrTitle=ui_tr("dialog.iconPickTitle");ofn.lpstrDefExt="ico";ofn.Flags=0x00080000u|0x00000800u|0x00000004u|0x00001000u;return fn(&ofn)!=0;}
static void ui_trainer_choose_icon(){char path[260]{};if(!ui_trainer_icon_dialog(path))return;strcopy(g_uiTrainerIcon,sizeof(g_uiTrainerIcon),path);ui_set_status(ui_tr("trainer.iconSelected"),1);InvalidateRect(g_hwnd,nullptr,0);}
struct GdiplusStartupInput_ { u32 GdiplusVersion; void* DebugEventCallback; BOOL SuppressBackgroundThread; BOOL SuppressExternalCodecs; };
struct CLSID_ { u32 Data1; u16 Data2; u16 Data3; u8 Data4[8]; };
static bool ui_trainer_image_dialog(char out[260]){HINSTANCE lib=LoadLibraryA("comdlg32.dll");if(!lib){ui_set_status(ui_tr("trainer.imagePickerFailed"),3);return false;}using Fn=BOOL (__stdcall *)(OPENFILENAMEA_*);auto fn=(Fn)GetProcAddress(lib,"GetOpenFileNameA");if(!fn){ui_set_status(ui_tr("dialog.fileDialogUnavailable"),3);return false;}char filter[320]{};usize fnn=0;if(!ui_filter_pair(filter,sizeof(filter),fnn,ui_tr("dialog.images"),"*.png;*.jpg;*.jpeg;*.bmp;*.gif")||!ui_filter_pair(filter,sizeof(filter),fnn,ui_tr("dialog.allFiles"),"*.*"))return false;out[0]=0;OPENFILENAMEA_ ofn{};ofn.lStructSize=(DWORD)sizeof(ofn);ofn.hwndOwner=g_hwnd;ofn.lpstrFilter=filter;ofn.nFilterIndex=1;ofn.lpstrFile=out;ofn.nMaxFile=260;ofn.lpstrTitle=ui_tr("dialog.imagePickTitle");ofn.Flags=0x00080000u|0x00000800u|0x00000004u|0x00001000u;return fn(&ofn)!=0;}
static bool ui_trainer_ico_save_dialog(char out[260]){HINSTANCE lib=LoadLibraryA("comdlg32.dll");if(!lib){ui_set_status(ui_tr("trainer.iconSaveDialogFailed"),3);return false;}using Fn=BOOL (__stdcall *)(OPENFILENAMEA_*);auto fn=(Fn)GetProcAddress(lib,"GetSaveFileNameA");if(!fn){ui_set_status(ui_tr("dialog.fileDialogUnavailable"),3);return false;}char filter[192]{};usize fnn=0;if(!ui_filter_pair(filter,sizeof(filter),fnn,ui_tr("dialog.windowsIcon"),"*.ico"))return false;out[0]=0;OPENFILENAMEA_ ofn{};ofn.lStructSize=(DWORD)sizeof(ofn);ofn.hwndOwner=g_hwnd;ofn.lpstrFilter=filter;ofn.nFilterIndex=1;ofn.lpstrFile=out;ofn.nMaxFile=260;ofn.lpstrTitle=ui_tr("dialog.iconSaveTitle");ofn.lpstrDefExt="ico";ofn.Flags=0x00080000u|0x00000800u|0x00000004u|0x00000002u;return fn(&ofn)!=0;}
static bool ui_read_heap_file(const char* path,u8*& data,DWORD& size){data=nullptr;size=0;HANDLE h=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ_,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS)return false;DWORD sz=GetFileSize(h,nullptr);if(!sz||sz==0xFFFFFFFFUL||sz>8u*1024u*1024u){CloseHandle(h);return false;}u8* p=(u8*)HeapAlloc(g_heap,0,sz);if(!p){CloseHandle(h);return false;}DWORD done=0;while(done<sz){DWORD got=0;if(!ReadFile(h,p+done,sz-done,&got,nullptr)||!got){HeapFree(g_heap,0,p);CloseHandle(h);return false;}done+=got;}CloseHandle(h);data=p;size=sz;return true;}
static void ui_put_u16le(u8* p,u16 v){p[0]=(u8)v;p[1]=(u8)(v>>8);}
static void ui_put_u32le(u8* p,u32 v){p[0]=(u8)v;p[1]=(u8)(v>>8);p[2]=(u8)(v>>16);p[3]=(u8)(v>>24);}
static bool ui_trainer_image_to_ico(const char* source,const char* output){
    HINSTANCE lib=LoadLibraryA("gdiplus.dll");if(!lib)return false;
    using StartupFn=int (__stdcall *)(ULONG_PTR*,const GdiplusStartupInput_*,void*);using ShutdownFn=void (__stdcall *)(ULONG_PTR);using LoadFn=int (__stdcall *)(const wchar_t*,void**);using DimFn=int (__stdcall *)(void*,UINT*);using CreateBmpFn=int (__stdcall *)(int,int,int,int,u8*,void**);using GraphicsFn=int (__stdcall *)(void*,void**);using ClearFn=int (__stdcall *)(void*,u32);using InterpFn=int (__stdcall *)(void*,int);using DrawFn=int (__stdcall *)(void*,void*,int,int,int,int);using SaveFn=int (__stdcall *)(void*,const wchar_t*,const CLSID_*,const void*);using DeleteGraphicsFn=int (__stdcall *)(void*);using DisposeFn=int (__stdcall *)(void*);
    auto startup=(StartupFn)GetProcAddress(lib,"GdiplusStartup");auto shutdown=(ShutdownFn)GetProcAddress(lib,"GdiplusShutdown");auto load=(LoadFn)GetProcAddress(lib,"GdipLoadImageFromFile");auto getW=(DimFn)GetProcAddress(lib,"GdipGetImageWidth");auto getH=(DimFn)GetProcAddress(lib,"GdipGetImageHeight");auto createBmp=(CreateBmpFn)GetProcAddress(lib,"GdipCreateBitmapFromScan0");auto getGraphics=(GraphicsFn)GetProcAddress(lib,"GdipGetImageGraphicsContext");auto clear=(ClearFn)GetProcAddress(lib,"GdipGraphicsClear");auto interp=(InterpFn)GetProcAddress(lib,"GdipSetInterpolationMode");auto draw=(DrawFn)GetProcAddress(lib,"GdipDrawImageRectI");auto save=(SaveFn)GetProcAddress(lib,"GdipSaveImageToFile");auto delGraphics=(DeleteGraphicsFn)GetProcAddress(lib,"GdipDeleteGraphics");auto dispose=(DisposeFn)GetProcAddress(lib,"GdipDisposeImage");
    if(!startup||!shutdown||!load||!getW||!getH||!createBmp||!getGraphics||!clear||!interp||!draw||!save||!delGraphics||!dispose)return false;
    GdiplusStartupInput_ si{1,nullptr,0,0};ULONG_PTR token=0;if(startup(&token,&si,nullptr)!=0)return false;wchar_t srcW[260]{};if(!MultiByteToWideChar(0,0,source,-1,srcW,260)){shutdown(token);return false;}void* src=nullptr;if(load(srcW,&src)!=0||!src){shutdown(token);return false;}UINT sw=0,sh=0;if(getW(src,&sw)!=0||getH(src,&sh)!=0||!sw||!sh){dispose(src);shutdown(token);return false;}
    static const int sizes[7]={16,24,32,48,64,128,256};u8* payload[7]{};DWORD payloadSize[7]{};bool ok=true;const int PixelFormat32bppARGB=0x26200A;const CLSID_ png={0x557cf406,0x1a04,0x11d3,{0x9a,0x73,0x00,0x00,0xf8,0x1e,0xf3,0x2e}};
    char tempDir[260]{};if(!GetTempPathA(260,tempDir))ok=false;
    for(int i=0;ok&&i<7;++i){int s=sizes[i];void* bmp=nullptr;void* gr=nullptr;if(createBmp(s,s,0,PixelFormat32bppARGB,nullptr,&bmp)!=0||!bmp){ok=false;break;}if(getGraphics(bmp,&gr)!=0||!gr){dispose(bmp);ok=false;break;}clear(gr,0x00000000u);interp(gr,7);int dw=s,dh=s,dx=0,dy=0;if(sw>sh){dh=(int)(((u64)sh*(u64)s)/(u64)sw);if(dh<1)dh=1;dy=(s-dh)/2;}else if(sh>sw){dw=(int)(((u64)sw*(u64)s)/(u64)sh);if(dw<1)dw=1;dx=(s-dw)/2;}if(draw(gr,src,dx,dy,dw,dh)!=0){delGraphics(gr);dispose(bmp);ok=false;break;}delGraphics(gr);char tmp[260]{};if(!GetTempFileNameA(tempDir,"MCI",0,tmp)){dispose(bmp);ok=false;break;}DeleteFileA(tmp);wchar_t tmpW[260]{};if(!MultiByteToWideChar(0,0,tmp,-1,tmpW,260)||save(bmp,tmpW,&png,nullptr)!=0){dispose(bmp);DeleteFileA(tmp);ok=false;break;}dispose(bmp);if(!ui_read_heap_file(tmp,payload[i],payloadSize[i]))ok=false;DeleteFileA(tmp);}
    dispose(src);shutdown(token);if(ok){HANDLE h=CreateFileA(output,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS)ok=false;else{u8 hdr[6]{};ui_put_u16le(hdr,0);ui_put_u16le(hdr+2,1);ui_put_u16le(hdr+4,7);ok=file_write_all(h,hdr,6);u32 offset=6+7*16;for(int i=0;ok&&i<7;++i){u8 e[16]{};e[0]=sizes[i]==256?0:(u8)sizes[i];e[1]=sizes[i]==256?0:(u8)sizes[i];e[2]=0;e[3]=0;ui_put_u16le(e+4,1);ui_put_u16le(e+6,32);ui_put_u32le(e+8,payloadSize[i]);ui_put_u32le(e+12,offset);offset+=payloadSize[i];ok=file_write_all(h,e,16);}for(int i=0;ok&&i<7;++i)ok=file_write_all(h,payload[i],payloadSize[i]);CloseHandle(h);}}
    for(int i=0;i<7;++i)if(payload[i])HeapFree(g_heap,0,payload[i]);if(!ok)DeleteFileA(output);return ok;
}
static void ui_trainer_convert_image(){char source[260]{};if(!ui_trainer_image_dialog(source))return;char output[260]{};if(!ui_trainer_ico_save_dialog(output))return;ui_set_status(ui_tr("trainer.convertingImage"),0);if(!ui_trainer_image_to_ico(source,output)){ui_set_status(ui_tr("trainer.convertFailed"),3);return;}strcopy(g_uiTrainerIcon,sizeof(g_uiTrainerIcon),output);ui_set_status(ui_tr("trainer.converted"),1);InvalidateRect(g_hwnd,nullptr,0);}
static bool ui_trainer_json_dialog(char out[260]){HINSTANCE lib=LoadLibraryA("comdlg32.dll");if(!lib){ui_set_status(ui_tr("dialog.filePickerFailed"),3);return false;}using Fn=BOOL (__stdcall *)(OPENFILENAMEA_*);auto fn=(Fn)GetProcAddress(lib,"GetSaveFileNameA");if(!fn){ui_set_status(ui_tr("dialog.fileDialogUnavailable"),3);return false;}char filter[256]{};usize fnn=0;if(!ui_filter_pair(filter,sizeof(filter),fnn,ui_tr("dialog.trainerProject"),"*.cwtrainer")||!ui_filter_pair(filter,sizeof(filter),fnn,ui_tr("dialog.allFiles"),"*.*"))return false;out[0]=0;OPENFILENAMEA_ ofn{};ofn.lStructSize=(DWORD)sizeof(ofn);ofn.hwndOwner=g_hwnd;ofn.lpstrFilter=filter;ofn.nFilterIndex=1;ofn.lpstrFile=out;ofn.nMaxFile=260;ofn.lpstrTitle=ui_tr("dialog.trainerSaveTitle");ofn.lpstrDefExt="cwtrainer";ofn.Flags=0x00080000u|0x00000800u|0x00000004u|0x00000002u;return fn(&ofn)!=0;}
static void ui_json_escape_append(char* b,usize cap,usize& n,const char* s){for(;s&&*s;++s){char c=*s;if(c=='"'||c=='\\'){append_char(b,cap,n,'\\');append_char(b,cap,n,c);}else if(c=='\n'){append_str(b,cap,n,"\\n");}else if(c=='\r'){append_str(b,cap,n,"\\r");}else if(c=='\t'){append_str(b,cap,n,"\\t");}else if((unsigned char)c>=32)append_char(b,cap,n,c);}}
static bool ui_save_trainer_json_file(const char* path){
    if(!path||!*path||!g_uiTrainerTitle[0]||!g_uiTrainerProcess[0]||!g_uiTrainerCount)return false;const usize cap=65536;char* b=(char*)HeapAlloc(g_heap,0,cap);if(!b)return false;usize n=0;
    append_str(b,cap,n,"{\r\n  \"format\": \"cheat-wizard-trainer\",\r\n  \"version\": 1,\r\n  \"trainer\": {\r\n    \"name\": \"");ui_json_escape_append(b,cap,n,g_uiTrainerTitle);append_str(b,cap,n,"\",\r\n    \"process\": \"");ui_json_escape_append(b,cap,n,g_uiTrainerProcess);append_str(b,cap,n,"\"\r\n  },\r\n  \"window\": { \"width\": 620, \"height\": 460 },\r\n  \"visual\": {\r\n    \"icon\": \"");ui_json_escape_append(b,cap,n,g_uiTrainerIcon);append_str(b,cap,n,"\",\r\n    \"background\": \"");ui_json_escape_append(b,cap,n,g_uiTrainerColorBg);append_str(b,cap,n,"\",\r\n    \"panel\": \"");ui_json_escape_append(b,cap,n,g_uiTrainerColorPanel);append_str(b,cap,n,"\",\r\n    \"surface\": \"");ui_json_escape_append(b,cap,n,g_uiTrainerColorSurface);append_str(b,cap,n,"\",\r\n    \"accent\": \"");ui_json_escape_append(b,cap,n,g_uiTrainerColorAccent);append_str(b,cap,n,"\",\r\n    \"text\": \"");ui_json_escape_append(b,cap,n,g_uiTrainerColorText);append_str(b,cap,n,"\",\r\n    \"muted\": \"");ui_json_escape_append(b,cap,n,g_uiTrainerColorMuted);append_str(b,cap,n,"\"\r\n  },\r\n  \"entries\": [\r\n");
    for(int i=0;i<g_uiTrainerCount;++i){UiTrainerEntry_& e=g_uiTrainerEntries[i];append_str(b,cap,n,"    { \"id\": \"");ui_json_escape_append(b,cap,n,e.id);append_str(b,cap,n,"\", \"label\": \"");ui_json_escape_append(b,cap,n,e.label);append_str(b,cap,n,"\", \"profile\": \"");ui_json_escape_append(b,cap,n,e.profile);append_str(b,cap,n,"\", \"defaultValue\": \"");ui_json_escape_append(b,cap,n,e.defaultValue);append_str(b,cap,n,"\", \"showCurrent\": ");append_str(b,cap,n,e.showCurrent?"true":"false");append_str(b,cap,n,", \"allowWrite\": ");append_str(b,cap,n,e.allowWrite?"true":"false");append_str(b,cap,n,", \"allowFreeze\": ");append_str(b,cap,n,e.allowFreeze?"true":"false");append_str(b,cap,n," }");if(i+1<g_uiTrainerCount)append_char(b,cap,n,',');append_str(b,cap,n,"\r\n");}
    append_str(b,cap,n,"  ],\r\n  \"layout\": [\r\n");for(int i=0;i<g_uiTrainerElementCount;++i){UiTrainerElement_& el=g_uiTrainerElements[i];append_str(b,cap,n,"    { \"type\": \"");if(el.type==UI_TRAINER_TITLE)append_str(b,cap,n,"title\", \"text\": \"");else if(el.type==UI_TRAINER_SUBTITLE)append_str(b,cap,n,"subtitle\", \"text\": \"");else append_str(b,cap,n,"field\", \"entry\": \"");if(el.type==UI_TRAINER_FIELD){if(el.entryIndex<0||el.entryIndex>=g_uiTrainerCount){HeapFree(g_heap,0,b);return false;}ui_json_escape_append(b,cap,n,g_uiTrainerEntries[el.entryIndex].id);}else ui_json_escape_append(b,cap,n,el.text);append_str(b,cap,n,"\" }");if(i+1<g_uiTrainerElementCount)append_char(b,cap,n,',');append_str(b,cap,n,"\r\n");}append_str(b,cap,n,"  ]\r\n}\r\n");HANDLE h=CreateFileA(path,GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);bool ok=(uptr)h!=INVALID_HANDLE_BITS&&file_write_all(h,b,n);if((uptr)h!=INVALID_HANDLE_BITS)CloseHandle(h);HeapFree(g_heap,0,b);return ok;
}
static void ui_save_trainer_json(){if(!g_uiTrainerCount){ui_set_status(ui_tr("trainer.saveNeedsProfile"),2);return;}char path[260]{};if(!ui_trainer_json_dialog(path))return;if(ui_save_trainer_json_file(path)){char m[420]{};usize n=0;append_str(m,sizeof(m),n,ui_tr("trainer.projectSavedPrefix"));append_str(m,sizeof(m),n,ui_path_basename(path));append_str(m,sizeof(m),n,ui_tr("trainer.projectSavedSuffix"));m[n]=0;ui_set_status(m,1);}else ui_set_status(ui_tr("trainer.projectSaveFailed"),3);InvalidateRect(g_hwnd,nullptr,0);}
static int ui_trainer_element_height(const UiTrainerElement_& el){return el.type==UI_TRAINER_TITLE?46:(el.type==UI_TRAINER_SUBTITLE?34:130);}
static UiRect ui_trainer_preview_window(const UiRect& area){return UiRect{area.x+8,area.y+8,ui_maxi(120,area.w-16),ui_maxi(120,area.h-16)};}
static bool ui_trainer_element_rect(int index,const UiRect& area,int scroll,UiRect& out){if(index<scroll||index<0||index>=g_uiTrainerElementCount)return false;UiRect win=ui_trainer_preview_window(area);int y=win.y+72;for(int i=scroll;i<index;++i)y+=ui_trainer_element_height(g_uiTrainerElements[i]);int step=ui_trainer_element_height(g_uiTrainerElements[index]);out={win.x+14,y,win.w-28,ui_maxi(24,step-8)};return out.y<win.y+win.h-8&&out.y+out.h>win.y+68;}
static int ui_trainer_row_at(int x,int y){if(!ui_contains(g_ui.trainerTable,x,y))return -1;for(int i=g_uiTrainerElementScroll;i<g_uiTrainerElementCount;++i){UiRect r{};if(!ui_trainer_element_rect(i,g_ui.trainerTable,g_uiTrainerElementScroll,r))break;if(ui_contains(r,x,y))return i;}return -1;}
static void ui_draw_trainer_preview(HDC dc,const UiRect& area,bool interactive){
    COLORREF cbg=ui_color_or(g_uiTrainerColorBg,Z950),cpanel=ui_color_or(g_uiTrainerColorPanel,Z900),csurf=ui_color_or(g_uiTrainerColorSurface,Z800),caccent=ui_color_or(g_uiTrainerColorAccent,BLUE600),ctext=ui_color_or(g_uiTrainerColorText,Z50),cmuted=ui_color_or(g_uiTrainerColorMuted,Z400);
    HBRUSH bg=CreateSolidBrush(cbg),panel=CreateSolidBrush(cpanel),surf=CreateSolidBrush(csurf),accent=CreateSolidBrush(caccent);HPEN border=CreatePen(PS_SOLID_,1,cmuted),accentPen=CreatePen(PS_SOLID_,1,caccent);
    ui_round(dc,area,g_brushSurface,g_penBorder,10);UiRect win=ui_trainer_preview_window(area);ui_round(dc,win,bg,border,10);
    ui_text(dc,g_uiTrainerTitle[0]?g_uiTrainerTitle:"Trainer",{win.x+14,win.y+8,win.w-28,28},ctext,g_fontTitle,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
    char proc[320]{};usize n=0;append_str(proc,sizeof(proc),n,ui_tr("trainer.connectedPrefix"));append_str(proc,sizeof(proc),n,g_uiTrainerProcess[0]?g_uiTrainerProcess:"game.exe");append_str(proc,sizeof(proc),n,"  |  PID 12345");proc[n]=0;ui_text(dc,proc,{win.x+14,win.y+38,win.w-28,20},ui_color_or("#34D399",GREEN400),g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
    int scroll=ui_clampi(g_uiTrainerElementScroll,0,ui_maxi(0,g_uiTrainerElementCount-1));int contentDc=SaveDC(dc);IntersectClipRect(dc,win.x+8,win.y+68,win.x+win.w-8,win.y+win.h-8);if(!g_uiTrainerElementCount){ui_text(dc,ui_tr("trainer.previewEmpty"),{win.x+40,win.y+88,win.w-80,ui_maxi(40,win.h-116)},cmuted,g_font,DT_CENTER_|DT_VCENTER_|DT_WORDBREAK_);}else for(int i=scroll;i<g_uiTrainerElementCount;++i){UiRect row{};if(!ui_trainer_element_rect(i,area,scroll,row))break;UiTrainerElement_& el=g_uiTrainerElements[i];bool sel=interactive&&i==g_uiTrainerElementSelected;HPEN itemPen=sel?accentPen:border;if(el.type==UI_TRAINER_TITLE){if(sel)ui_round(dc,row,bg,itemPen,7);ui_text(dc,el.text,{row.x+8,row.y,row.w-16,row.h},ctext,g_fontTitle,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);continue;}if(el.type==UI_TRAINER_SUBTITLE){if(sel)ui_round(dc,row,bg,itemPen,7);ui_text(dc,el.text,{row.x+8,row.y,row.w-16,row.h},cmuted,g_font,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);continue;}if(el.entryIndex<0||el.entryIndex>=g_uiTrainerCount)continue;UiTrainerEntry_& e=g_uiTrainerEntries[el.entryIndex];ui_round(dc,row,panel,itemPen,10);ui_text(dc,e.label,{row.x+14,row.y+7,row.w-28,22},ctext,g_fontBold,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);char info[160]{};usize infoN=0;if(e.showCurrent){append_str(info,sizeof(info),infoN,ui_tr("trainer.currentValuePrefix"));append_str(info,sizeof(info),infoN,"99999.0000");append_str(info,sizeof(info),infoN,ui_tr("trainer.consensusPrefix"));append_str(info,sizeof(info),infoN,"5/5");}else append_str(info,sizeof(info),infoN,ui_tr("trainer.currentHidden"));info[infoN]=0;ui_text(dc,info,{row.x+14,row.y+31,row.w-28,18},cmuted,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);int actionY=row.y+60;if(e.allowWrite){int reserve=e.allowFreeze?204:98;UiRect field{row.x+14,actionY,ui_maxi(120,row.w-28-reserve),34};ui_round(dc,field,surf,border,7);ui_text(dc,e.defaultValue[0]?e.defaultValue:"99999",{field.x+10,field.y,field.w-20,field.h},ctext,g_fontMono,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);UiRect apply{field.x+field.w+8,actionY,88,34};ui_round(dc,apply,accent,border,7);ui_text(dc,ui_tr("trainer.apply"),apply,ctext,g_fontBold,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);if(e.allowFreeze){UiRect freeze{apply.x+apply.w+8,actionY,96,34};ui_round(dc,freeze,surf,border,7);ui_text(dc,"Freeze",freeze,ctext,g_fontBold,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);}}else if(e.allowFreeze){UiRect freeze{row.x+14,actionY,108,34};ui_round(dc,freeze,surf,border,7);ui_text(dc,"Freeze",freeze,ctext,g_fontBold,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);}}
    if(contentDc)RestoreDC(dc,contentDc);if(g_uiTrainerElementCount>1){char page[64]{};usize pn=0;append_str(page,sizeof(page),pn,ui_tr("trainer.elementPrefix"));append_u64_dec(page,sizeof(page),pn,(u64)(scroll+1));append_str(page,sizeof(page),pn,"/");append_u64_dec(page,sizeof(page),pn,(u64)g_uiTrainerElementCount);page[pn]=0;ui_text(dc,page,{win.x+win.w-130,win.y+39,116,18},cmuted,g_fontSmall,DT_RIGHT_|DT_VCENTER_|DT_SINGLELINE_);}
    DeleteObject((HGDIOBJ)bg);DeleteObject((HGDIOBJ)panel);DeleteObject((HGDIOBJ)surf);DeleteObject((HGDIOBJ)accent);DeleteObject((HGDIOBJ)border);DeleteObject((HGDIOBJ)accentPen);
}
static UiRect ui_trainer_text_property_box(){return UiRect{g_ui.trainerLabelBox.x,g_ui.trainerLabelBox.y,g_ui.trainerDefaultBox.x+g_ui.trainerDefaultBox.w-g_ui.trainerLabelBox.x,g_ui.trainerLabelBox.h};}
static void ui_draw_trainer(HDC dc){
    ui_round(dc,g_ui.trainerProjectCard,g_brushPanel,g_penBorder,12);ui_card_title(dc,g_ui.trainerProjectCard,ui_tr("nav.trainer"),ui_tr("trainer.cardHint"));int x=g_ui.trainerProjectCard.x+18;
    ui_button(dc,g_ui.trainerSubConfig,ui_tr("trainer.configuration"),g_uiTrainerMode==0,true);ui_button(dc,g_ui.trainerSubVisual,ui_tr("trainer.visual"),g_uiTrainerMode==1,true);
    if(g_uiTrainerMode==1){
        ui_button_icon(dc,g_ui.trainerIconButton,g_uiTrainerIcon[0]?ui_tr("trainer.changeIcon"):ui_tr("trainer.chooseIcon"),UI_ICON_FILE,false,true);ui_button_icon(dc,g_ui.trainerIconConvert,ui_tr("trainer.convertIcon"),UI_ICON_CONVERT,false,true);
        struct VC{const char* label;UiRect r;const char* value;UiTextFocus_ focus;COLORREF fallback;};VC v[6]={{ui_tr("trainer.colorBackground"),g_ui.trainerColorBg,g_uiTrainerColorBg,UI_TEXT_COLOR_BG,Z950},{ui_tr("trainer.colorPanel"),g_ui.trainerColorPanel,g_uiTrainerColorPanel,UI_TEXT_COLOR_PANEL,Z900},{ui_tr("trainer.colorSurface"),g_ui.trainerColorSurface,g_uiTrainerColorSurface,UI_TEXT_COLOR_SURFACE,Z800},{ui_tr("trainer.colorAccent"),g_ui.trainerColorAccent,g_uiTrainerColorAccent,UI_TEXT_COLOR_ACCENT,BLUE600},{ui_tr("trainer.colorText"),g_ui.trainerColorText,g_uiTrainerColorText,UI_TEXT_COLOR_TEXT,Z50},{ui_tr("trainer.colorMuted"),g_ui.trainerColorMuted,g_uiTrainerColorMuted,UI_TEXT_COLOR_MUTED,Z400}};
        for(int i=0;i<6;++i){ui_text(dc,v[i].label,{v[i].r.x,v[i].r.y-19,v[i].r.w,16},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_input(dc,v[i].r,v[i].value,v[i].focus,true,g_fontMono,38);COLORREF c=ui_color_or(v[i].value,v[i].fallback);HBRUSH sw=CreateSolidBrush(c);UiRect sq=ui_color_swatch_rect(v[i].r);ui_round(dc,sq,sw,g_penBorder,5);DeleteObject((HGDIOBJ)sw);}
        char visualNote[320]{};usize vn=0;if(g_uiTrainerIcon[0]){append_str(visualNote,sizeof(visualNote),vn,ui_tr("trainer.iconPrefix"));append_str(visualNote,sizeof(visualNote),vn,ui_path_basename(g_uiTrainerIcon));append_str(visualNote,sizeof(visualNote),vn,". ");}append_str(visualNote,sizeof(visualNote),vn,ui_tr("trainer.colorHint"));visualNote[vn]=0;ui_text(dc,visualNote,{x,g_ui.trainerColorText.y+54,g_ui.trainerProjectCard.w-36,52},Z400,g_fontSmall,DT_LEFT_|DT_WORDBREAK_);
        ui_round(dc,g_ui.trainerEntryCard,g_brushPanel,g_penBorder,12);ui_card_title(dc,g_ui.trainerEntryCard,ui_tr("trainer.previewTitle"),ui_tr("trainer.previewVisualHint"));ui_draw_trainer_preview(dc,g_ui.trainerPreview,false);return;
    }
    ui_text(dc,ui_tr("trainer.name"),{x,g_ui.trainerTitleBox.y-18,g_ui.trainerProjectCard.w-36,16},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_input(dc,g_ui.trainerTitleBox,g_uiTrainerTitle,UI_TEXT_TRAINER_TITLE,!g_uiBusy,g_font);
    ui_text(dc,ui_tr("trainer.process"),{x,g_ui.trainerProcessBox.y-18,g_ui.trainerProjectCard.w-36,16},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_round(dc,g_ui.trainerProcessBox,g_brushSurface,g_penBorder,8);ui_text(dc,g_uiTrainerProcess[0]?g_uiTrainerProcess:ui_tr("trainer.processFromFirst"),{g_ui.trainerProcessBox.x+12,g_ui.trainerProcessBox.y,g_ui.trainerProcessBox.w-24,g_ui.trainerProcessBox.h},g_uiTrainerProcess[0]?Z100:Z600,g_font,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
    ui_text(dc,ui_tr("trainer.addElement"),{x,g_ui.trainerAddTitle.y-20,g_ui.trainerProjectCard.w-36,16},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_button(dc,g_ui.trainerAddTitle,ui_tr("trainer.addTitle"),false,!g_uiBusy&&g_uiTrainerElementCount<(int)UI_TRAINER_ELEMENT_LIMIT);ui_button(dc,g_ui.trainerAddSubtitle,ui_tr("trainer.addSubtitle"),false,!g_uiBusy&&g_uiTrainerElementCount<(int)UI_TRAINER_ELEMENT_LIMIT);ui_button(dc,g_ui.trainerAddProfile,ui_tr("trainer.addProfile"),true,!g_uiBusy&&g_uiTrainerCount<(int)UI_TRAINER_ENTRY_LIMIT);ui_button(dc,g_ui.trainerAddCurrent,ui_tr("trainer.addCurrent"),false,!g_uiBusy&&g_uiPointerProfilePath[0]&&g_uiTrainerCount<(int)UI_TRAINER_ENTRY_LIMIT);ui_button(dc,g_ui.trainerSaveJson,ui_tr("trainer.saveProject"),false,!g_uiBusy&&g_uiTrainerCount>0);
    char count[128]{};usize cn=0;append_u64_dec(count,sizeof(count),cn,(u64)g_uiTrainerElementCount);append_str(count,sizeof(count),cn,g_uiTrainerElementCount==1?ui_tr("trainer.elementSingular"):ui_tr("trainer.elementPlural"));append_u64_dec(count,sizeof(count),cn,(u64)g_uiTrainerCount);append_str(count,sizeof(count),cn,g_uiTrainerCount==1?ui_tr("trainer.fieldSingular"):ui_tr("trainer.fieldPlural"));count[cn]=0;ui_text(dc,count,{x,g_ui.trainerSaveJson.y+46,g_ui.trainerProjectCard.w-36,18},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_text(dc,ui_tr("trainer.selectionHint"),{x,g_ui.trainerSaveJson.y+70,g_ui.trainerProjectCard.w-36,70},Z400,g_fontSmall,DT_LEFT_|DT_WORDBREAK_);
    ui_round(dc,g_ui.trainerEntryCard,g_brushPanel,g_penBorder,12);ui_card_title(dc,g_ui.trainerEntryCard,ui_tr("trainer.previewTitle"),ui_tr("trainer.previewEditHint"));ui_draw_trainer_preview(dc,g_ui.trainerTable,true);
    bool elementSel=g_uiTrainerElementSelected>=0&&g_uiTrainerElementSelected<g_uiTrainerElementCount;bool fieldSel=elementSel&&g_uiTrainerElements[g_uiTrainerElementSelected].type==UI_TRAINER_FIELD&&g_uiTrainerSelected>=0&&g_uiTrainerSelected<g_uiTrainerCount;
    if(elementSel){UiTrainerElement_& el=g_uiTrainerElements[g_uiTrainerElementSelected];if(fieldSel){ui_text(dc,ui_tr("trainer.displayName"),{g_ui.trainerLabelBox.x,g_ui.trainerLabelBox.y-16,g_ui.trainerLabelBox.w,14},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_input(dc,g_ui.trainerLabelBox,g_uiTrainerLabel,UI_TEXT_TRAINER_LABEL,true,g_font);ui_text(dc,ui_tr("trainer.defaultValue"),{g_ui.trainerDefaultBox.x,g_ui.trainerDefaultBox.y-16,g_ui.trainerDefaultBox.w,14},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_input(dc,g_ui.trainerDefaultBox,g_uiTrainerDefault,UI_TEXT_TRAINER_DEFAULT,true,g_fontMono);UiTrainerEntry_& e=g_uiTrainerEntries[g_uiTrainerSelected];ui_button(dc,g_ui.trainerShowToggle,e.showCurrent?ui_tr("trainer.showValueYes"):ui_tr("trainer.showValueNo"),false,true);ui_button(dc,g_ui.trainerWriteToggle,e.allowWrite?ui_tr("trainer.allowEditYes"):ui_tr("trainer.allowEditNo"),false,true);ui_button(dc,g_ui.trainerFreezeToggle,e.allowFreeze?ui_tr("trainer.freezeYes"):ui_tr("trainer.freezeNo"),false,true);}else{UiRect textBox=ui_trainer_text_property_box();ui_text(dc,el.type==UI_TRAINER_TITLE?ui_tr("trainer.titleText"):ui_tr("trainer.subtitleText"),{textBox.x,textBox.y-16,textBox.w,14},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_input(dc,textBox,g_uiTrainerElementText,UI_TEXT_TRAINER_LABEL,true,g_font);ui_text(dc,ui_tr("trainer.textHint"),{g_ui.trainerShowToggle.x,g_ui.trainerShowToggle.y,g_ui.trainerFreezeToggle.x+g_ui.trainerFreezeToggle.w-g_ui.trainerShowToggle.x,g_ui.trainerShowToggle.h},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);}ui_button(dc,g_ui.trainerMoveUp,ui_tr("trainer.moveUp"),false,g_uiTrainerElementSelected>0);ui_button(dc,g_ui.trainerMoveDown,ui_tr("trainer.moveDown"),false,g_uiTrainerElementSelected+1<g_uiTrainerElementCount);ui_button(dc,g_ui.trainerRemove,ui_tr("trainer.remove"),false,true);}else{ui_text(dc,ui_tr("trainer.selectElement"),{g_ui.trainerLabelBox.x,g_ui.trainerLabelBox.y,g_ui.trainerDefaultBox.x+g_ui.trainerDefaultBox.w-g_ui.trainerLabelBox.x,70},Z500,g_fontSmall,DT_CENTER_|DT_VCENTER_|DT_WORDBREAK_);ui_button(dc,g_ui.trainerMoveUp,ui_tr("trainer.moveUp"),false,false);ui_button(dc,g_ui.trainerMoveDown,ui_tr("trainer.moveDown"),false,false);ui_button(dc,g_ui.trainerRemove,ui_tr("trainer.remove"),false,false);}
}

static void ui_start_pointer_scan(bool rescan){
    if(g_uiBusy)return;if(!g_process){ui_set_status(ui_tr("pointers.attachBeforeSearch"),2);return;}if(!g_uiPointerTargetValid){ui_set_status(ui_tr("pointers.chooseTarget"),2);return;}if(rescan&&!g_pointerChainCount){ui_set_status(ui_tr("pointers.noChainsRescan"),2);return;}
    u64 depth=0,maxOffset=0,maxNegative=0,maxChains=0,branch=0,indexLimit=0,alignment=0,searchBudget=0;bool writableOnly=false;ui_pointer_apply_preset(depth,maxOffset,maxNegative,maxChains,branch,indexLimit,alignment,searchBudget,writableOnly);g_uiTask.kind=rescan?4:3;g_uiTask.pointerTarget=g_uiPointerTarget;g_uiTask.pointerDepth=depth;g_uiTask.pointerMaxOffset=maxOffset;g_uiTask.pointerMaxNegative=maxNegative;g_uiTask.pointerMaxChains=maxChains;g_uiTask.pointerBranch=branch;g_uiTask.pointerIndexLimit=indexLimit;g_uiTask.pointerAlignment=alignment;g_uiTask.pointerSearchBudget=searchBudget;g_uiTask.pointerWritableOnly=writableOnly;g_uiTask.pointerRootAny=g_uiPointerRootAny;g_pointerCancelRequested=0;g_uiBusy=2;g_uiPopup=UI_POP_NONE;g_uiSelectedPointer=-1;g_uiPointerScroll=0;ui_pointer_reset_cache();ui_set_status(rescan?ui_tr("pointers.rescanning"):ui_tr("pointers.buildingIndex"),0);InvalidateRect(g_hwnd,nullptr,0);DWORD tid=0;HANDLE th=CreateThread(nullptr,0,ui_pointer_worker,nullptr,0,&tid);if(!th){g_uiBusy=0;ui_set_status(ui_tr("pointers.threadFailed"),3);}else CloseHandle(th);
}
static void ui_clear_pointer_chains(){clear_pointer_index();clear_pointer_chains();g_uiSelectedPointer=-1;g_uiPointerScroll=0;ui_pointer_reset_cache();ui_set_status(ui_tr("pointers.cleared"),0);InvalidateRect(g_hwnd,nullptr,0);}
static void ui_pointer_chain_text(usize idx,char base[320],char offsets[520],char resolved[64],char value[96],char state[48],bool& targetMatch,bool& readableChain){
    base[0]=offsets[0]=resolved[0]=value[0]=state[0]=0;targetMatch=false;readableChain=false;if(idx>=g_pointerChainCount)return;PointerChain_& c=g_pointerChains[idx];usize n=0;append_str(base,320,n,c.module);append_str(base,320,n,"+");append_hex(base,320,n,c.rootOffset);base[n]=0;n=0;for(u8 j=0;j<c.depth;++j){if(j)append_str(offsets,520,n,"  ->  ");if(c.offsets[j]<0){append_str(offsets,520,n,"-");u64 mag=(u64)(-(c.offsets[j]+1))+1ULL;append_hex(offsets,520,n,(uptr)mag);}else{append_str(offsets,520,n,"+");append_hex(offsets,520,n,(uptr)c.offsets[j]);}}offsets[n]=0;u8 st=g_uiPointerResolveState[idx];if(st==2){uptr addr=g_uiPointerResolvedCache[idx];readableChain=true;n=0;append_hex(resolved,64,n,addr);resolved[n]=0;ValueType t=(ValueType)g_uiPointerTargetType;if(g_uiPointerValueState[idx]==2&&t!=ValueType::Invalid&&t!=ValueType::Mixed){n=0;append_value(value,96,n,t,g_uiPointerValueCache[idx]);value[n]=0;}else strcopy(value,96,"-");targetMatch=g_uiPointerTargetValid&&addr==g_uiPointerTarget;strcopy(state,48,targetMatch?ui_tr("pointers.stateTarget"):"OK");}else if(st==1){strcopy(resolved,64,"-");strcopy(value,96,"-");strcopy(state,48,ui_tr("pointers.stateUnavailable"));}else{strcopy(resolved,64,"...");strcopy(value,96,"...");strcopy(state,48,ui_tr("pointers.stateChecking"));}
}
static int ui_pointer_row_at(int x,int y){if(!ui_contains(g_ui.pointerTable,x,y)||y<g_ui.pointerTable.y+34||g_uiBusy)return -1;int row=(y-(g_ui.pointerTable.y+34))/32;int idx=g_uiPointerScroll+row;return idx>=0&&(usize)idx<g_pointerChainCount?idx:-1;}
static void ui_draw_pointer_target(HDC dc){
    ui_round(dc,g_ui.pointerTargetBox,g_brushSurface,g_uiPointerTargetValid?g_penAccent:g_penBorder,8);if(!g_uiPointerTargetValid){ui_text(dc,ui_tr("pointers.noTarget"),{g_ui.pointerTargetBox.x+12,g_ui.pointerTargetBox.y,g_ui.pointerTargetBox.w-24,g_ui.pointerTargetBox.h},Z500,g_font,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);return;}
    char addr[64]{},value[96]{};usize n=0;append_hex(addr,sizeof(addr),n,g_uiPointerTarget);addr[n]=0;ValueType t=(ValueType)g_uiPointerTargetType;u8 raw[8]{};bool rd=ui_read_value(g_uiPointerTarget,t,raw);n=0;if(rd)append_value(value,sizeof(value),n,t,raw);else append_str(value,sizeof(value),n,ui_tr("common.unavailable"));value[n]=0;ui_text(dc,addr,{g_ui.pointerTargetBox.x+12,g_ui.pointerTargetBox.y+5,g_ui.pointerTargetBox.w-24,24},Z50,g_fontMono,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);char line[180]{};n=0;append_str(line,sizeof(line),n,type_name(t));append_str(line,sizeof(line),n,"  |  ");append_str(line,sizeof(line),n,ui_tr("pointers.currentPrefix"));append_str(line,sizeof(line),n,value);line[n]=0;ui_text(dc,line,{g_ui.pointerTargetBox.x+12,g_ui.pointerTargetBox.y+30,g_ui.pointerTargetBox.w-24,20},rd?Z400:AMBER400,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
}
static void ui_draw_pointer_controls(HDC dc){
    ui_round(dc,g_ui.pointerControlCard,g_brushPanel,g_penBorder,12);ui_card_title(dc,g_ui.pointerControlCard,ui_tr("pointers.title"),ui_tr("pointers.cardHint"));int x=g_ui.pointerControlCard.x+18;ui_text(dc,ui_tr("pointers.target"),{x,g_ui.pointerTargetBox.y-22,g_ui.pointerControlCard.w-36,18},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_draw_pointer_target(dc);ui_button(dc,g_ui.pointerUseSelected,ui_tr("pointers.useSelected"),false,!g_uiBusy&&g_uiSelectedWatch>=0);
    ui_text(dc,ui_tr("pointers.searchIntensity"),{x,g_ui.pointerPresetFast.y-22,g_ui.pointerControlCard.w-36,18},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);ui_button(dc,g_ui.pointerPresetFast,ui_tr("pointers.fast"),g_uiPointerPreset==0,!g_uiBusy);ui_button(dc,g_ui.pointerPresetBalanced,ui_tr("pointers.balanced"),g_uiPointerPreset==1,!g_uiBusy);ui_button(dc,g_ui.pointerPresetDeep,ui_tr("pointers.deep"),g_uiPointerPreset==2,!g_uiBusy);
    const char* presetDesc=g_uiPointerPreset==0?ui_tr("pointers.fastDesc"):(g_uiPointerPreset==2?ui_tr("pointers.deepDesc"):ui_tr("pointers.balancedDesc"));ui_text(dc,presetDesc,{x,g_ui.pointerPresetFast.y+38,g_ui.pointerControlCard.w-36,18},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);
    ui_text(dc,ui_tr("pointers.rootTitle"),{x,g_ui.pointerRootToggle.y-21,g_ui.pointerControlCard.w-36,18},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);char root[300]{};usize n=0;append_str(root,sizeof(root),n,ui_tr("pointers.rootPrefix"));append_str(root,sizeof(root),n,g_uiPointerRootAny?ui_tr("pointers.anyModule"):(g_uiAttachedName[0]?g_uiAttachedName:ui_tr("pointers.mainProcess")));root[n]=0;ui_button(dc,g_ui.pointerRootToggle,root,false,!g_uiBusy&&g_process);
    if(g_uiBusy==2)ui_button(dc,g_ui.pointerCancel,ui_tr("scanner.stop"),false,true);else ui_button(dc,g_ui.pointerStart,g_pointerChainCount?ui_tr("pointers.search"):ui_tr("pointers.search"),true,g_process&&g_uiPointerTargetValid);
    char rescan[100]{};n=0;append_str(rescan,sizeof(rescan),n,ui_tr("pointers.rescan"));if(g_pointerChainCount){append_str(rescan,sizeof(rescan),n," (");append_u64_dec(rescan,sizeof(rescan),n,g_pointerChainCount);append_str(rescan,sizeof(rescan),n,")");}rescan[n]=0;ui_button(dc,g_ui.pointerRescan,rescan,false,!g_uiBusy&&g_process&&g_uiPointerTargetValid&&g_pointerChainCount>0);ui_button(dc,g_ui.pointerClear,ui_tr("pointers.clearChains"),false,!g_uiBusy&&g_pointerChainCount>0);
    ui_button(dc,g_ui.pointerSave,ui_tr("pointers.saveProfile"),false,!g_uiBusy&&g_pointerChainCount>0);ui_button(dc,g_ui.pointerLoad,ui_tr("pointers.loadProfile"),false,!g_uiBusy);ui_button(dc,g_ui.pointerAddWatch,ui_tr("pointers.addResolved"),true,!g_uiBusy&&g_process&&g_pointerChainCount>0);
    int iy=g_ui.pointerAddWatch.y+46;int helpH=g_ui.pointerControlCard.h-(iy-g_ui.pointerControlCard.y)-24;if(helpH>=72){ui_text(dc,ui_tr("pointers.profileLabel"),{x,iy,g_ui.pointerControlCard.w-36,18},Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);const char* help=g_pointerChainCount?ui_tr("pointers.profileHelpLoaded"):ui_tr("pointers.profileHelpEmpty");ui_text(dc,help,{x,iy+24,g_ui.pointerControlCard.w-36,helpH-24},Z400,g_fontSmall,DT_LEFT_|DT_WORDBREAK_);}
}
static void ui_pointer_column_widths(int widths[6]){int avail=ui_maxi(420,g_ui.pointerTable.w-20);widths[0]=44;widths[3]=145;widths[4]=105;widths[5]=82;int flex=ui_maxi(160,avail-(widths[0]+widths[3]+widths[4]+widths[5]));int base=ui_clampi((flex*45)/100,80,245);int offs=flex-base;if(offs<80){offs=80;base=ui_maxi(80,flex-offs);}widths[1]=base;widths[2]=offs;}
static void ui_draw_pointer_table_header(HDC dc){UiRect h{g_ui.pointerTable.x,g_ui.pointerTable.y,g_ui.pointerTable.w,34};ui_round(dc,h,g_brushSurface,nullptr,5);int widths[6]{};ui_pointer_column_widths(widths);const char* names[6]={"#",ui_tr("pointers.colBase"),ui_tr("pointers.colOffsets"),ui_tr("pointers.colResolved"),ui_tr("pointers.colCurrent"),ui_tr("pointers.colStatus")};int x=h.x+10;for(int i=0;i<6;++i){ui_text(dc,names[i],{x,h.y,widths[i]-6,h.h},Z400,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_);x+=widths[i];}}
static void ui_draw_pointer_results(HDC dc){
    ui_round(dc,g_ui.pointerResultCard,g_brushPanel,g_penBorder,12);char subtitle[220]{};usize sn=0;if(g_uiBusy==2){
        if(g_uiPointerPhase==1){append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.phaseIndexingPrefix"));append_u64_dec(subtitle,sizeof(subtitle),sn,(u64)g_pointerCount);append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.phaseCandidatesSuffix"));}
        else if(g_uiPointerPhase==2||g_uiPointerPhase==3){append_str(subtitle,sizeof(subtitle),sn,g_uiPointerPhase==3?ui_tr("pointers.phaseFallbackPrefix"):ui_tr("pointers.phaseSearchingPrefix"));append_u64_dec(subtitle,sizeof(subtitle),sn,(u64)g_pointerSearchSteps);append_str(subtitle,sizeof(subtitle),sn," / ");append_u64_dec(subtitle,sizeof(subtitle),sn,g_pointerSearchBudget);append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.phaseStepsSuffix"));}
        else append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.phaseRescanning"));
    }else if(g_pointerChainCount){append_u64_dec(subtitle,sizeof(subtitle),sn,g_pointerChainCount);append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryChainsSuffix"));if(g_pointerChainsTruncated)append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryLimitReached"));append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryRestartRescan"));}else if(g_uiPointerTargetedUsed){append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryTargetedPrefix"));append_u64_dec(subtitle,sizeof(subtitle),sn,g_pointerLayerDepth);append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryMatches"));append_u64_dec(subtitle,sizeof(subtitle),sn,g_pointerLayerMatches);if(g_pointerLayerTruncated)append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryFrontierLimited"));if(g_uiPointerAutoRootFallback)append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryTriedAllModules"));}else if(g_uiPointerIndexed){append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryIndexPrefix"));append_u64_dec(subtitle,sizeof(subtitle),sn,g_uiPointerIndexed);if(g_uiPointerIndexTruncated)append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryPartial"));append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryDirectParents"));append_u64_dec(subtitle,sizeof(subtitle),sn,g_uiPointerLevel1Candidates);if(g_uiPointerAutoRootFallback)append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryTriedAllModules"));}else append_str(subtitle,sizeof(subtitle),sn,ui_tr("pointers.summaryEmpty"));subtitle[sn]=0;ui_card_title(dc,g_ui.pointerResultCard,ui_tr("pointers.resultsTitle"),subtitle);ui_draw_pointer_table_header(dc);
    int bodyY=g_ui.pointerTable.y+34,rowH=32;int visible=ui_maxi(1,(g_ui.pointerTable.h-34)/rowH);int total=(int)g_pointerChainCount;g_uiPointerScroll=ui_clampi(g_uiPointerScroll,0,ui_maxi(0,total-visible));if(g_uiBusy==2){UiRect e{g_ui.pointerTable.x,bodyY+20,g_ui.pointerTable.w,g_ui.pointerTable.h-50};char busy[260]{};usize bn=0;if(g_uiPointerPhase==1){append_str(busy,sizeof(busy),bn,ui_tr("pointers.busyIndexingPrefix"));append_u64_dec(busy,sizeof(busy),bn,(u64)g_pointerCount);append_str(busy,sizeof(busy),bn,ui_tr("pointers.busyIndexingSuffix"));}else if(g_uiPointerPhase==2||g_uiPointerPhase==3){append_str(busy,sizeof(busy),bn,g_uiPointerPhase==3?ui_tr("pointers.busyFallbackStepsPrefix"):ui_tr("pointers.busySearchingStepsPrefix"));append_u64_dec(busy,sizeof(busy),bn,(u64)g_pointerSearchSteps);append_str(busy,sizeof(busy),bn," / ");append_u64_dec(busy,sizeof(busy),bn,g_pointerSearchBudget);append_str(busy,sizeof(busy),bn,ui_tr("pointers.busyBoundedHint"));}else if(g_uiPointerPhase==5||g_uiPointerPhase==6){append_str(busy,sizeof(busy),bn,g_uiPointerPhase==6?ui_tr("pointers.busyDirectedAnyPrefix"):ui_tr("pointers.busyDirectedLayersPrefix"));append_u64_dec(busy,sizeof(busy),bn,g_pointerLayerDepth);append_str(busy,sizeof(busy),bn," / ");append_u64_dec(busy,sizeof(busy),bn,g_pointerLayerMaxDepth);append_str(busy,sizeof(busy),bn,ui_tr("pointers.busyFrontier"));append_u64_dec(busy,sizeof(busy),bn,g_pointerLayerFrontier);append_str(busy,sizeof(busy),bn,ui_tr("pointers.busySlotsRead"));append_u64_dec(busy,sizeof(busy),bn,g_pointerLayerSlots);append_str(busy,sizeof(busy),bn,ui_tr("pointers.busyMatches"));append_u64_dec(busy,sizeof(busy),bn,g_pointerLayerMatches);append_str(busy,sizeof(busy),bn,ui_tr("pointers.busyCancelHint"));}else append_str(busy,sizeof(busy),bn,ui_tr("pointers.busyRescanning"));busy[bn]=0;ui_text(dc,busy,e,Z500,g_font,DT_CENTER_|DT_VCENTER_|DT_WORDBREAK_);return;}if(!total){UiRect e{g_ui.pointerTable.x+40,bodyY+30,g_ui.pointerTable.w-80,g_ui.pointerTable.h-80};const char* msg=g_uiPointerTargetedUsed?(g_pointerLayerTruncated?ui_tr("pointers.emptyTargetedTruncated"):(g_pointerLayerMatches?ui_tr("pointers.emptyTargetedNoRoot"):ui_tr("pointers.emptyTargetedNoRefs"))):(g_uiPointerIndexed?(g_uiPointerIndexTruncated?ui_tr("pointers.emptyPartialIndex"):(g_uiPointerLevel1Candidates?ui_tr("pointers.emptyNoStaticRoot"):ui_tr("pointers.emptyNoNearbyPointer"))):ui_tr("pointers.empty"));ui_text(dc,msg,e,g_uiPointerIndexed?AMBER400:Z600,g_font,DT_CENTER_|DT_VCENTER_|DT_WORDBREAK_);return;}
    int widths[6]{};ui_pointer_column_widths(widths);for(int r=0;r<visible;++r){int idx=g_uiPointerScroll+r;if(idx>=total)break;UiRect row{g_ui.pointerTable.x,bodyY+r*rowH,g_ui.pointerTable.w-8,rowH-1};bool sel=g_uiSelectedPointer==idx;bool hov=ui_contains(row,g_uiMouseX,g_uiMouseY);if(sel)ui_round(dc,row,g_brushSelected,nullptr,5);else if(hov)ui_round(dc,row,g_brushHover,nullptr,5);char ix[32]{},base[320]{},offs[520]{},resolved[64]{},value[96]{},state[48]{};usize n=0;append_char(ix,sizeof(ix),n,'#');append_u64_dec(ix,sizeof(ix),n,(u64)idx);ix[n]=0;bool match=false,rd=false;ui_pointer_chain_text((usize)idx,base,offs,resolved,value,state,match,rd);const char* vals[6]={ix,base,offs,resolved,value,state};int x=row.x+10;for(int c=0;c<6;++c){COLORREF col=c==0?Z500:(c==5?(match?GREEN400:(rd?Z300:AMBER400)):(c==4?BLUE300:(c==2?Z400:Z200)));HFONT f=(c==1||c==2||c==3||c==4)?g_fontMono:g_fontSmall;ui_text(dc,vals[c],{x,row.y,widths[c]-6,row.h},col,f,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);x+=widths[c];}}
    ui_draw_scrollbar(dc,g_ui.pointerTable,total,g_uiPointerScroll,visible);
}
static void ui_draw_footer(HDC dc){ui_round(dc,g_ui.footer,g_brushPanel,nullptr,8);COLORREF c=g_uiStatusKind==1?GREEN400:(g_uiStatusKind==2?AMBER400:(g_uiStatusKind==3?RED400:Z500));UiRect dot{g_ui.footer.x+12,g_ui.footer.y+12,8,8};HBRUSH br=g_uiStatusKind==1?g_brushSuccess:(g_uiStatusKind==2?g_brushWarn:(g_uiStatusKind==3?g_brushError:g_brushSelected));ui_round(dc,dot,br,nullptr,8);UiRect t{g_ui.footer.x+28,g_ui.footer.y,ui_maxi(40,g_ui.locale.x-g_ui.footer.x-38),g_ui.footer.h};ui_text(dc,g_uiStatus,t,c,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);const char* code=(g_uiLocaleIndex>=0&&g_uiLocaleIndex<g_uiLocaleChoiceCount)?g_uiLocaleChoices[g_uiLocaleIndex].code:"en-US";ui_button(dc,g_ui.locale,code,false,true);}

static void ui_draw_popup(HDC dc){
    if(g_uiPopup==UI_POP_NONE)return;
    if(g_uiPopup==UI_POP_PROCESS){
        UiRect base{},search{},list{},footerText{},refresh{},attach{};ui_process_popup_geometry(base,search,list,footerText,refresh,attach);ui_round(dc,base,g_brushPanel,g_penStrong,10);
        bool filterFocused=g_uiTextFocus==UI_TEXT_PROCESS_FILTER;ui_input(dc,search,g_uiProcessFilter,UI_TEXT_PROCESS_FILTER,true,g_font,40);ui_draw_icon(dc,UI_ICON_SEARCH,search.x+20,search.y+search.h/2,filterFocused?BLUE300:Z300,255,18);if(!g_uiProcessFilter[0])ui_text(dc,ui_tr("process.searchPlaceholder"),{search.x+40,search.y,search.w-52,search.h},Z500,g_font,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);
        int rowH=30;for(int r=0;r<UI_PROCESS_POPUP_ROWS;++r){int logical=g_uiProcessScroll+r;if(logical>=g_uiProcessFilteredCount)break;int idx=g_uiProcessFiltered[logical];UiRect row{list.x,list.y+r*rowH,list.w-7,rowH};bool sel=idx==g_uiProcessSelected;if(sel)ui_round(dc,row,g_brushSelected,nullptr,6);else if(ui_hover(row))ui_round(dc,row,g_brushHover,nullptr,6);UiProcess_& p=g_uiProcesses[idx];ui_text(dc,p.name,{row.x+10,row.y,ui_maxi(100,row.w-118),row.h},sel?Z50:Z200,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);char pid[48]{};usize pn=0;append_str(pid,sizeof(pid),pn,"PID ");append_u64_dec(pid,sizeof(pid),pn,p.pid);pid[pn]=0;ui_text(dc,pid,{row.x+row.w-104,row.y,94,row.h},sel?Z300:Z500,g_fontSmall,DT_RIGHT_|DT_VCENTER_|DT_SINGLELINE_);}
        if(!g_uiProcessFilteredCount){ui_text(dc,ui_tr("process.none"),{list.x+18,list.y,list.w-36,list.h},Z500,g_fontSmall,DT_CENTER_|DT_VCENTER_|DT_SINGLELINE_);}else if(g_uiProcessFilteredCount>UI_PROCESS_POPUP_ROWS){int trackH=list.h-8,thumbH=ui_maxi(28,(trackH*UI_PROCESS_POPUP_ROWS)/g_uiProcessFilteredCount);int maxScroll=g_uiProcessFilteredCount-UI_PROCESS_POPUP_ROWS;int thumbY=list.y+4+(maxScroll?((trackH-thumbH)*g_uiProcessScroll)/maxScroll:0);UiRect tr{list.x+list.w-3,list.y+4,2,trackH};UiRect th{tr.x,thumbY,2,thumbH};ui_round(dc,tr,g_brushSurface,nullptr,2);ui_round(dc,th,g_brushSelected,nullptr,2);}
        char stats[96]{};usize sn=0;if(g_uiProcessFilter[0]){append_u64_dec(stats,sizeof(stats),sn,g_uiProcessFilteredCount);append_str(stats,sizeof(stats),sn,ui_tr("process.of"));}append_u64_dec(stats,sizeof(stats),sn,g_uiProcessCount);append_str(stats,sizeof(stats),sn,g_uiProcessCount==1?ui_tr("process.singular"):ui_tr("process.plural"));stats[sn]=0;ui_text(dc,stats,footerText,Z500,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);ui_button_icon(dc,refresh,ui_tr("header.refresh"),UI_ICON_REFRESH,false,true);bool same=ui_selected_is_attached();ui_button_icon(dc,attach,same?ui_tr("header.attached"):ui_tr("header.attach"),UI_ICON_ATTACH,true,g_uiProcessSelected>=0&&!same);return;
    }
    UiRect base{};int count=0,rowH=30;if(g_uiPopup==UI_POP_SCAN){count=ui_scan_popup_count();base={g_ui.scanType.x,g_ui.scanType.y+g_ui.scanType.h+6,g_ui.scanType.w,count*rowH+8};}else{base={g_ui.valueType.x,g_ui.valueType.y+g_ui.valueType.h+6,g_ui.valueType.w,7*rowH+8};count=7;}
    ui_round(dc,base,g_brushPanel,g_penStrong,10);int maxRows=(base.h-8)/rowH;for(int r=0;r<maxRows;++r){int idx=r;if(idx>=count)break;int actual=g_uiPopup==UI_POP_SCAN?ui_scan_popup_value(idx):idx;UiRect row{base.x+4,base.y+4+r*rowH,base.w-8,rowH};bool sel=g_uiPopup==UI_POP_SCAN?actual==g_uiScanType:idx==g_uiValueType;if(sel)ui_round(dc,row,g_brushSelected,nullptr,6);else if(ui_hover(row))ui_round(dc,row,g_brushHover,nullptr,6);const char* label=g_uiPopup==UI_POP_SCAN?ui_scan_type_name(actual):ui_value_type_name(idx);ui_text(dc,label,{row.x+10,row.y,row.w-20,row.h},sel?Z50:Z200,g_fontSmall,DT_LEFT_|DT_VCENTER_|DT_SINGLELINE_|DT_END_ELLIPSIS_);}
}

static void ui_render(HDC dc){
    ui_compute_layout();RECT_ client{};GetClientRect(g_hwnd,&client);FillRect(dc,&client,g_brushBg);ui_draw_header2(dc);if(g_uiView==UI_VIEW_SCANNER){ui_draw_scan_panel(dc);ui_draw_results(dc);ui_draw_watch(dc);}else if(g_uiView==UI_VIEW_POINTERS){ui_draw_pointer_controls(dc);ui_draw_pointer_results(dc);}else{ui_draw_trainer(dc);}ui_draw_footer(dc);ui_draw_popup(dc);
}

static void ui_set_popup(UiPopup_ p){
    if(p==UI_POP_PROCESS){if(g_uiPopup==UI_POP_PROCESS){g_uiPopup=UI_POP_NONE;g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;}else{g_uiPopup=UI_POP_PROCESS;g_uiProcessFilter[0]=0;g_uiProcessScroll=0;ui_rebuild_process_filter();ui_set_text_focus(UI_TEXT_PROCESS_FILTER);}ui_sync_edits();InvalidateRect(g_hwnd,nullptr,0);return;}
    if(g_uiTextFocus==UI_TEXT_PROCESS_FILTER){g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;}g_uiPopup=(g_uiPopup==p)?UI_POP_NONE:p;ui_sync_edits();InvalidateRect(g_hwnd,nullptr,0);
}
static bool ui_popup_click(int x,int y){
    if(g_uiPopup==UI_POP_NONE)return false;
    if(g_uiPopup==UI_POP_PROCESS){
        UiRect base{},search{},list{},footerText{},refresh{},attach{};ui_process_popup_geometry(base,search,list,footerText,refresh,attach);
        if(!ui_contains(base,x,y)){bool targetClick=ui_contains(g_ui.target,x,y);g_uiPopup=UI_POP_NONE;g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;ui_sync_edits();InvalidateRect(g_hwnd,nullptr,0);return targetClick;}
        if(ui_contains(search,x,y)){ui_set_text_focus_at(UI_TEXT_PROCESS_FILTER,search,x,g_font,40);return true;}
        if(ui_contains(refresh,x,y)){ui_refresh_processes();ui_set_text_focus(UI_TEXT_PROCESS_FILTER);return true;}
        if(ui_contains(attach,x,y)){if(g_uiProcessSelected>=0&&!ui_selected_is_attached())ui_attach_selected();g_uiPopup=UI_POP_NONE;g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;ui_sync_edits();InvalidateRect(g_hwnd,nullptr,0);return true;}
        if(ui_contains(list,x,y)){int row=(y-list.y)/30;int logical=g_uiProcessScroll+row;if(row>=0&&row<UI_PROCESS_POPUP_ROWS&&logical>=0&&logical<g_uiProcessFilteredCount){g_uiProcessSelected=g_uiProcessFiltered[logical];InvalidateRect(g_hwnd,nullptr,0);}return true;}
        return true;
    }
    UiRect base{};int count=0,rowH=30;if(g_uiPopup==UI_POP_SCAN){count=ui_scan_popup_count();base={g_ui.scanType.x,g_ui.scanType.y+g_ui.scanType.h+6,g_ui.scanType.w,count*rowH+8};}else{base={g_ui.valueType.x,g_ui.valueType.y+g_ui.valueType.h+6,g_ui.valueType.w,7*rowH+8};count=7;}
    if(!ui_contains(base,x,y)){g_uiPopup=UI_POP_NONE;ui_sync_edits();InvalidateRect(g_hwnd,nullptr,0);return false;}int row=(y-(base.y+4))/rowH;int idx=row;if(row>=0&&idx>=0&&idx<count){if(g_uiPopup==UI_POP_SCAN){g_uiScanType=ui_scan_popup_value(idx);if(!ui_scan_value_visible()&&g_uiTextFocus==UI_TEXT_SCAN){g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;}}else g_uiValueType=idx;g_uiPopup=UI_POP_NONE;ui_sync_edits();InvalidateRect(g_hwnd,nullptr,0);return true;}return true;
}

static int ui_result_row_at(int x,int y){if(!ui_contains(g_ui.resultTable,x,y)||y<g_ui.resultTable.y+34||g_uiBusy)return -1;int row=(y-(g_ui.resultTable.y+34))/30;int logical=g_uiResultScroll+row;int total=ui_result_display_total();if(logical<0||logical>=total)return -1;usize idx=ui_result_display_index(logical);return idx<g_resultCount?(int)idx:-1;}
static int ui_watch_slot_at(int x,int y){if(!ui_contains(g_ui.watchTable,x,y)||y<g_ui.watchTable.y+34)return -1;int row=(y-(g_ui.watchTable.y+34))/UI_WATCH_ROW_H;int logical=g_uiWatchScroll+row;return logical>=0&&logical<g_uiWatchCount?ui_watch_slot_for_row(logical):-1;}
static bool ui_watch_row_rect_for_slot(int slot,UiRect& row){int logical=ui_watch_row_for_slot(slot);if(logical<0)return false;int visual=logical-g_uiWatchScroll;int visible=ui_maxi(1,(g_ui.watchTable.h-34)/UI_WATCH_ROW_H);if(visual<0||visual>=visible)return false;row={g_ui.watchTable.x,g_ui.watchTable.y+34+visual*UI_WATCH_ROW_H,g_ui.watchTable.w-8,UI_WATCH_ROW_H-1};return true;}

static void ui_click(int x,int y){
    if(ui_popup_click(x,y))return;
    if(ui_contains(g_ui.locale,x,y)&&g_uiLocaleChoiceCount>0){int next=(g_uiLocaleIndex+1)%g_uiLocaleChoiceCount;ui_select_locale(next,true,true);return;}
    if(!g_uiBusy){if(ui_contains(g_ui.tabScanner,x,y)){g_uiView=UI_VIEW_SCANNER;g_uiPopup=UI_POP_NONE;InvalidateRect(g_hwnd,nullptr,0);return;}if(ui_contains(g_ui.tabPointers,x,y)){g_uiView=UI_VIEW_POINTERS;g_uiPopup=UI_POP_NONE;InvalidateRect(g_hwnd,nullptr,0);return;}if(ui_contains(g_ui.tabTrainer,x,y)){g_uiView=UI_VIEW_TRAINER;g_uiPopup=UI_POP_NONE;InvalidateRect(g_hwnd,nullptr,0);return;}}
    if(g_uiBusy){if(g_uiBusy==2&&g_uiView==UI_VIEW_POINTERS&&ui_contains(g_ui.pointerCancel,x,y)){g_pointerCancelRequested=1;ui_set_status(ui_tr("pointers.cancelRequested"),2);}return;}
    if(ui_contains(g_ui.target,x,y)){ui_set_popup(UI_POP_PROCESS);return;}if(ui_contains(g_ui.refresh,x,y)){ui_refresh_processes();return;}if(ui_contains(g_ui.attach,x,y)){if(!ui_selected_is_attached())ui_attach_selected();return;}
    if(g_uiView==UI_VIEW_TRAINER){
        if(ui_contains(g_ui.trainerSubConfig,x,y)){g_uiTrainerMode=0;g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;InvalidateRect(g_hwnd,nullptr,0);return;}
        if(ui_contains(g_ui.trainerSubVisual,x,y)){g_uiTrainerMode=1;g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;InvalidateRect(g_hwnd,nullptr,0);return;}
        if(g_uiTrainerMode==1){
            if(ui_contains(g_ui.trainerIconButton,x,y)){ui_trainer_choose_icon();return;}if(ui_contains(g_ui.trainerIconConvert,x,y)){ui_trainer_convert_image();return;}
            if(ui_contains(ui_color_swatch_rect(g_ui.trainerColorBg),x,y)){ui_trainer_pick_color(g_uiTrainerColorBg,Z950);return;}if(ui_contains(g_ui.trainerColorBg,x,y)){ui_set_text_focus_at(UI_TEXT_COLOR_BG,g_ui.trainerColorBg,x,g_fontMono);return;}
            if(ui_contains(ui_color_swatch_rect(g_ui.trainerColorPanel),x,y)){ui_trainer_pick_color(g_uiTrainerColorPanel,Z900);return;}if(ui_contains(g_ui.trainerColorPanel,x,y)){ui_set_text_focus_at(UI_TEXT_COLOR_PANEL,g_ui.trainerColorPanel,x,g_fontMono);return;}
            if(ui_contains(ui_color_swatch_rect(g_ui.trainerColorSurface),x,y)){ui_trainer_pick_color(g_uiTrainerColorSurface,Z800);return;}if(ui_contains(g_ui.trainerColorSurface,x,y)){ui_set_text_focus_at(UI_TEXT_COLOR_SURFACE,g_ui.trainerColorSurface,x,g_fontMono);return;}
            if(ui_contains(ui_color_swatch_rect(g_ui.trainerColorAccent),x,y)){ui_trainer_pick_color(g_uiTrainerColorAccent,BLUE600);return;}if(ui_contains(g_ui.trainerColorAccent,x,y)){ui_set_text_focus_at(UI_TEXT_COLOR_ACCENT,g_ui.trainerColorAccent,x,g_fontMono);return;}
            if(ui_contains(ui_color_swatch_rect(g_ui.trainerColorText),x,y)){ui_trainer_pick_color(g_uiTrainerColorText,Z50);return;}if(ui_contains(g_ui.trainerColorText,x,y)){ui_set_text_focus_at(UI_TEXT_COLOR_TEXT,g_ui.trainerColorText,x,g_fontMono);return;}
            if(ui_contains(ui_color_swatch_rect(g_ui.trainerColorMuted),x,y)){ui_trainer_pick_color(g_uiTrainerColorMuted,Z400);return;}if(ui_contains(g_ui.trainerColorMuted,x,y)){ui_set_text_focus_at(UI_TEXT_COLOR_MUTED,g_ui.trainerColorMuted,x,g_fontMono);return;}
            g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;InvalidateRect(g_hwnd,nullptr,0);return;
        }
        if(ui_contains(g_ui.trainerTitleBox,x,y)){ui_set_text_focus_at(UI_TEXT_TRAINER_TITLE,g_ui.trainerTitleBox,x,g_font);return;}
        if(ui_contains(g_ui.trainerAddTitle,x,y)){ui_trainer_add_text_element(UI_TRAINER_TITLE);return;}
        if(ui_contains(g_ui.trainerAddSubtitle,x,y)){ui_trainer_add_text_element(UI_TRAINER_SUBTITLE);return;}
        if(ui_contains(g_ui.trainerAddProfile,x,y)){ui_trainer_add_profile_file();return;}
        if(ui_contains(g_ui.trainerAddCurrent,x,y)){ui_trainer_add_current_profile();return;}
        if(ui_contains(g_ui.trainerSaveJson,x,y)){ui_save_trainer_json();return;}
        int tr=ui_trainer_row_at(x,y);if(tr>=0){g_uiTrainerElementSelected=tr;ui_trainer_sync_fields();g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;InvalidateRect(g_hwnd,nullptr,0);return;}
        if(g_uiTrainerElementSelected>=0&&g_uiTrainerElementSelected<g_uiTrainerElementCount){UiTrainerElement_& el=g_uiTrainerElements[g_uiTrainerElementSelected];bool field=el.type==UI_TRAINER_FIELD&&el.entryIndex>=0&&el.entryIndex<g_uiTrainerCount;if(field){g_uiTrainerSelected=el.entryIndex;UiTrainerEntry_& e=g_uiTrainerEntries[g_uiTrainerSelected];if(ui_contains(g_ui.trainerLabelBox,x,y)){ui_set_text_focus_at(UI_TEXT_TRAINER_LABEL,g_ui.trainerLabelBox,x,g_font);return;}if(ui_contains(g_ui.trainerDefaultBox,x,y)){ui_set_text_focus_at(UI_TEXT_TRAINER_DEFAULT,g_ui.trainerDefaultBox,x,g_fontMono);return;}if(ui_contains(g_ui.trainerShowToggle,x,y)){e.showCurrent=!e.showCurrent;InvalidateRect(g_hwnd,nullptr,0);return;}if(ui_contains(g_ui.trainerWriteToggle,x,y)){e.allowWrite=!e.allowWrite;InvalidateRect(g_hwnd,nullptr,0);return;}if(ui_contains(g_ui.trainerFreezeToggle,x,y)){e.allowFreeze=!e.allowFreeze;InvalidateRect(g_hwnd,nullptr,0);return;}}else{UiRect textBox=ui_trainer_text_property_box();if(ui_contains(textBox,x,y)){ui_set_text_focus_at(UI_TEXT_TRAINER_LABEL,textBox,x,g_font);return;}}if(ui_contains(g_ui.trainerMoveUp,x,y)){ui_trainer_move_selected(-1);return;}if(ui_contains(g_ui.trainerMoveDown,x,y)){ui_trainer_move_selected(1);return;}if(ui_contains(g_ui.trainerRemove,x,y)){ui_trainer_remove_selected();return;}}
        g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;InvalidateRect(g_hwnd,nullptr,0);return;
    }
    if(g_uiView==UI_VIEW_POINTERS){
        if(ui_contains(g_ui.pointerUseSelected,x,y)){ui_pointer_take_selected_watch();return;}if(ui_contains(g_ui.pointerPresetFast,x,y)){g_uiPointerPreset=0;ui_set_status(ui_tr("pointers.fastStatus"),0);InvalidateRect(g_hwnd,nullptr,0);return;}if(ui_contains(g_ui.pointerPresetBalanced,x,y)){g_uiPointerPreset=1;ui_set_status(ui_tr("pointers.balancedStatus"),0);InvalidateRect(g_hwnd,nullptr,0);return;}if(ui_contains(g_ui.pointerPresetDeep,x,y)){g_uiPointerPreset=2;ui_set_status(ui_tr("pointers.deepStatus"),2);InvalidateRect(g_hwnd,nullptr,0);return;}if(ui_contains(g_ui.pointerRootToggle,x,y)){g_uiPointerRootAny=!g_uiPointerRootAny;ui_set_status(g_uiPointerRootAny?ui_tr("pointers.rootAnyStatus"):ui_tr("pointers.rootMainStatus"),0);InvalidateRect(g_hwnd,nullptr,0);return;}if(ui_contains(g_ui.pointerStart,x,y)){ui_start_pointer_scan(false);return;}if(ui_contains(g_ui.pointerRescan,x,y)){ui_start_pointer_scan(true);return;}if(ui_contains(g_ui.pointerClear,x,y)){ui_clear_pointer_chains();return;}if(ui_contains(g_ui.pointerSave,x,y)){ui_save_pointer_profile();return;}if(ui_contains(g_ui.pointerLoad,x,y)){ui_load_pointer_profile();return;}if(ui_contains(g_ui.pointerAddWatch,x,y)){ui_add_pointer_profile_to_watch();return;}int pr=ui_pointer_row_at(x,y);if(pr>=0){g_uiSelectedPointer=pr;InvalidateRect(g_hwnd,nullptr,0);return;}return;
    }
    if(ui_contains(g_ui.wizardGoal,x,y)){g_guidedGoal=(GuidedGoal_)(((u8)g_guidedGoal+1u)%4u);g_rankingDirty=true;if(g_rankingEnabled&&!g_snapshotActive&&g_resultCount)rebuild_result_ranking();char b[220]{};usize n=0;append_str(b,sizeof(b),n,ui_tr("status.wizardGoalPrefix"));append_str(b,sizeof(b),n,guided_goal_name(g_guidedGoal));append_str(b,sizeof(b),n,". ");if(g_type!=ValueType::Invalid)append_str(b,sizeof(b),n,guided_action_text());b[n]=0;ui_set_status(b,1);InvalidateRect(g_hwnd,nullptr,0);return;}
    if(ui_contains(g_ui.guideChanged,x,y)){ui_start_guided(2);return;}if(ui_contains(g_ui.guideUnchanged,x,y)){ui_start_guided(3);return;}if(ui_contains(g_ui.guideIncreased,x,y)){ui_start_guided(4);return;}if(ui_contains(g_ui.guideDecreased,x,y)){ui_start_guided(5);return;}
    if(ui_contains(g_ui.rankToggle,x,y)&&!g_snapshotActive&&g_resultCount){g_rankingEnabled=!g_rankingEnabled;g_uiResultScroll=0;if(g_rankingEnabled){g_rankingDirty=true;rebuild_result_ranking();g_uiSelectedResult=g_rankedCount?(int)g_rankedIndices[0]:-1;ui_set_status(g_rankAnchorCount?ui_tr("results.rankingEnabledNear"):ui_tr("results.rankingEnabledBase"),1);}else{g_uiSelectedResult=0;ui_set_status(ui_tr("results.rankingDisabled"),0);}InvalidateRect(g_hwnd,nullptr,0);return;}
    if(g_snapshotActive&&g_type==ValueType::Mixed){const ValueType types[6]={ValueType::Byte,ValueType::Int16,ValueType::Int32,ValueType::Int64,ValueType::Float,ValueType::Double};for(int ti=0;ti<6;++ti){if(ui_type_filter_count(ti)&&ui_contains(ui_type_filter_rect(ti),x,y)){usize before=g_snapshotCandidates;if(disable_mixed_type(types[ti])){char b[260]{};usize n=0;append_str(b,sizeof(b),n,ui_tr("status.typeRemovedPrefix"));append_str(b,sizeof(b),n,type_name(types[ti]));append_str(b,sizeof(b),n,ui_tr("status.typeRemovedMiddle"));ui_append_compact_count(b,sizeof(b),n,before);append_str(b,sizeof(b),n," -> ");ui_append_compact_count(b,sizeof(b),n,g_snapshotCandidates);append_str(b,sizeof(b),n,ui_tr("status.typeRemovedCandidates"));if(g_snapshotCandidates<=MAX_RESULTS)append_str(b,sizeof(b),n,ui_tr("status.materializeNext"));b[n]=0;ui_set_status(b,1);}InvalidateRect(g_hwnd,nullptr,0);return;}}}
    int ws=ui_watch_slot_at(x,y);if(ws>=0){UiRect row{};if(ui_watch_row_rect_for_slot(ws,row)){UiRect cols[7]{};ui_watch_column_rects(row,cols);UiRect pointerRect{},removeRect{},valueEdit{},saveRect{};ui_watch_action_rects(row,pointerRect,removeRect);ui_watch_value_edit_rects(row,valueEdit,saveRect);bool nameHit=ui_contains(cols[1],x,y),valueHit=ui_contains(cols[5],x,y);bool editingValue=ws==g_uiSelectedWatch&&g_uiTextFocus==UI_TEXT_WATCH;if(editingValue&&ui_contains(saveRect,x,y)){ui_write_selected_watch();return;}if(nameHit){if(ws!=g_uiSelectedWatch){ui_finish_watch_inline_edit(true);g_uiSelectedWatch=ws;ui_fill_watch_edit(true);}else if(g_uiTextFocus==UI_TEXT_WATCH)ui_finish_watch_inline_edit(false);UiRect edit{cols[1].x,row.y+4,ui_maxi(24,cols[1].w-6),row.h-8};ui_set_text_focus_at(UI_TEXT_WATCH_NAME,edit,x,g_fontSmall);return;}if(valueHit){bool keepTyped=ws==g_uiSelectedWatch&&g_uiTextFocus==UI_TEXT_WATCH;if(g_uiTextFocus==UI_TEXT_WATCH_NAME)ui_finish_watch_inline_edit(true);else if(g_uiTextFocus==UI_TEXT_WATCH&&ws!=g_uiSelectedWatch)ui_finish_watch_inline_edit(false);if(ws!=g_uiSelectedWatch)g_uiSelectedWatch=ws;if(!keepTyped)ui_fill_watch_edit(true);int focusX=ui_clampi(x,valueEdit.x,valueEdit.x+ui_maxi(1,valueEdit.w)-1);ui_set_text_focus_at(UI_TEXT_WATCH,valueEdit,focusX,g_fontMono);return;}ui_finish_watch_inline_edit(true);if(ws!=g_uiSelectedWatch){g_uiSelectedWatch=ws;ui_fill_watch_edit(true);}if(ui_contains(pointerRect,x,y)){ui_pointer_take_selected_watch();return;}if(ui_contains(removeRect,x,y)){ui_remove_selected_watch();return;}if(ui_contains(cols[0],x,y)){ui_toggle_selected_freeze(true);return;}g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;InvalidateRect(g_hwnd,nullptr,0);return;}}
    ui_finish_watch_inline_edit(true);if(ui_contains(g_ui.scanValueBox,x,y)){ui_set_text_focus_at(UI_TEXT_SCAN,g_ui.scanValueBox,x,g_font);return;}g_uiTextFocus=UI_TEXT_NONE;g_uiTextCursor=g_uiTextAnchor=0;
    if(ui_contains(g_ui.scanType,x,y)){ui_set_popup(UI_POP_SCAN);return;}if(ui_contains(g_ui.valueType,x,y)){ui_set_popup(UI_POP_VALUE);return;}if(ui_contains(g_ui.alignment,x,y)){g_alignmentByte=!g_alignmentByte;ui_set_status(g_alignmentByte?ui_tr("status.alignmentByteOn"):ui_tr("status.alignmentNaturalOn"),0);InvalidateRect(g_hwnd,nullptr,0);return;}
    if(ui_contains(g_ui.firstScan,x,y)){ui_start_scan(true);return;}if(ui_contains(g_ui.nextScan,x,y)){ui_start_scan(false);return;}if(ui_contains(g_ui.newScan,x,y)){ui_new_scan();return;}if(ui_contains(g_ui.addResult,x,y)){ui_add_selected_result();return;}
    int rr=ui_result_row_at(x,y);if(rr>=0){g_uiSelectedResult=rr;InvalidateRect(g_hwnd,nullptr,0);return;}if(ui_contains(g_ui.clearWatch,x,y)){ui_clear_watches(true);ui_set_status(ui_tr("watch.cleared"),0);InvalidateRect(g_hwnd,nullptr,0);return;}
}
static void ui_scroll(int delta,int x,int y){
    if(g_uiPopup==UI_POP_PROCESS){int maxScroll=ui_maxi(0,g_uiProcessFilteredCount-UI_PROCESS_POPUP_ROWS);g_uiProcessScroll=ui_clampi(g_uiProcessScroll+(delta<0?3:-3),0,maxScroll);InvalidateRect(g_hwnd,nullptr,0);return;}
    if(g_uiView==UI_VIEW_POINTERS&&ui_contains(g_ui.pointerTable,x,y)){int visible=ui_maxi(1,(g_ui.pointerTable.h-34)/32);g_uiPointerScroll=ui_clampi(g_uiPointerScroll+(delta<0?3:-3),0,ui_maxi(0,(int)g_pointerChainCount-visible));ui_pointer_refresh_visible_cache();InvalidateRect(g_hwnd,nullptr,0);return;}
    if(g_uiView==UI_VIEW_TRAINER){UiRect trainerScrollArea=g_uiTrainerMode==0?g_ui.trainerTable:g_ui.trainerPreview;if(ui_contains(trainerScrollArea,x,y)){g_uiTrainerElementScroll=ui_clampi(g_uiTrainerElementScroll+(delta<0?1:-1),0,ui_maxi(0,g_uiTrainerElementCount-1));InvalidateRect(g_hwnd,nullptr,0);return;}}
    if(ui_contains(g_ui.resultTable,x,y)){int visible=ui_maxi(1,(g_ui.resultTable.h-34)/30);int total=ui_result_display_total();g_uiResultScroll=ui_clampi(g_uiResultScroll+(delta<0?3:-3),0,ui_maxi(0,total-visible));InvalidateRect(g_hwnd,nullptr,0);return;}
    if(ui_contains(g_ui.watchTable,x,y)){int visible=ui_maxi(1,(g_ui.watchTable.h-34)/UI_WATCH_ROW_H);g_uiWatchScroll=ui_clampi(g_uiWatchScroll+(delta<0?2:-2),0,ui_maxi(0,g_uiWatchCount-visible));InvalidateRect(g_hwnd,nullptr,0);}
}
static void ui_create_resources(){
    g_brushBg=CreateSolidBrush(Z950);g_brushPanel=CreateSolidBrush(Z900);g_brushSurface=CreateSolidBrush(Z800);g_brushHover=CreateSolidBrush(Z750);g_brushSelected=CreateSolidBrush(Z700);g_brushAccent=CreateSolidBrush(BLUE600);g_brushAccentHover=CreateSolidBrush(BLUE500);g_brushDanger=CreateSolidBrush(rgb_(69,10,10));g_brushSuccess=CreateSolidBrush(rgb_(6,78,59));g_brushWarn=CreateSolidBrush(rgb_(120,53,15));g_brushError=CreateSolidBrush(rgb_(127,29,29));g_brushAccentSoft=CreateSolidBrush(rgb_(30,58,138));
    g_penBorder=CreatePen(PS_SOLID_,1,Z800);g_penStrong=CreatePen(PS_SOLID_,1,Z700);g_penAccent=CreatePen(PS_SOLID_,1,BLUE500);g_penGreen=CreatePen(PS_SOLID_,2,Z50);
    g_font=CreateFontA(-15,0,0,0,FW_NORMAL_,0,0,0,1,0,0,CLEARTYPE_QUALITY_,0,"Segoe UI Variable Text");if(!g_font)g_font=(HFONT)GetStockObject(DEFAULT_GUI_FONT_);
    g_fontSmall=CreateFontA(-13,0,0,0,FW_NORMAL_,0,0,0,1,0,0,CLEARTYPE_QUALITY_,0,"Segoe UI Variable Text");if(!g_fontSmall)g_fontSmall=g_font;
    g_fontBold=CreateFontA(-15,0,0,0,FW_SEMIBOLD_,0,0,0,1,0,0,CLEARTYPE_QUALITY_,0,"Segoe UI Variable Text");if(!g_fontBold)g_fontBold=g_font;
    g_fontTitle=CreateFontA(-22,0,0,0,FW_SEMIBOLD_,0,0,0,1,0,0,CLEARTYPE_QUALITY_,0,"Segoe UI Variable Display");if(!g_fontTitle)g_fontTitle=g_fontBold;
    g_fontMono=CreateFontA(-14,0,0,0,FW_NORMAL_,0,0,0,1,0,0,CLEARTYPE_QUALITY_,0,"Consolas");if(!g_fontMono)g_fontMono=g_font;
}
static void ui_destroy_resources(){HGDIOBJ objs[]={g_brushBg,g_brushPanel,g_brushSurface,g_brushHover,g_brushSelected,g_brushAccent,g_brushAccentHover,g_brushDanger,g_brushSuccess,g_brushWarn,g_brushError,g_brushAccentSoft,g_penBorder,g_penStrong,g_penAccent,g_penGreen};for(unsigned i=0;i<sizeof(objs)/sizeof(objs[0]);++i)if(objs[i])DeleteObject(objs[i]);if(g_font&&g_font!=(HFONT)GetStockObject(DEFAULT_GUI_FONT_))DeleteObject((HGDIOBJ)g_font);if(g_fontSmall&&g_fontSmall!=g_font)DeleteObject((HGDIOBJ)g_fontSmall);if(g_fontBold&&g_fontBold!=g_font)DeleteObject((HGDIOBJ)g_fontBold);if(g_fontTitle&&g_fontTitle!=g_fontBold)DeleteObject((HGDIOBJ)g_fontTitle);if(g_fontMono&&g_fontMono!=g_font)DeleteObject((HGDIOBJ)g_fontMono);}

static void ui_create_controls(){
    ui_create_resources();
    ui_compute_layout();
    ui_refresh_processes();
}

static void ui_try_dark_titlebar(HWND hwnd){HINSTANCE dwm=LoadLibraryA("dwmapi.dll");if(!dwm)return;using Fn=int (__stdcall *)(HWND,DWORD,LPCVOID,DWORD);auto fn=(Fn)GetProcAddress(dwm,"DwmSetWindowAttribute");if(!fn)return;BOOL dark=1;fn(hwnd,20,&dark,(DWORD)sizeof(dark));fn(hwnd,19,&dark,(DWORD)sizeof(dark));}

static LRESULT __stdcall ui_wndproc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam){
    if(msg==WM_CREATE_){g_hwnd=hwnd;ui_create_controls();SetTimer(hwnd,1,1000,nullptr);return 0;}
    if(msg==WM_GETMINMAXINFO_){MINMAXINFO_* mm=(MINMAXINFO_*)lParam;if(mm){mm->ptMinTrackSize.x=1024;mm->ptMinTrackSize.y=720;}return 0;}
    if(msg==WM_SIZE_){ui_compute_layout();ui_sync_edits();InvalidateRect(hwnd,nullptr,0);return 0;}
    if(msg==WM_ERASEBKGND_)return 1;
    if(msg==0x0100 /* WM_KEYDOWN */){ui_text_keydown((UINT)wParam);return 0;}
    if(msg==0x0102 /* WM_CHAR */){ui_text_input_char((char)(wParam&0xFF));return 0;}
    if(msg==WM_MOUSEMOVE_){g_uiMouseX=(short)(lParam&0xFFFF);g_uiMouseY=(short)((lParam>>16)&0xFFFF);InvalidateRect(hwnd,nullptr,0);return 0;}
    if(msg==WM_LBUTTONDOWN_){int x=(short)(lParam&0xFFFF),y=(short)((lParam>>16)&0xFFFF);g_uiMouseX=x;g_uiMouseY=y;ui_click(x,y);return 0;}
    if(msg==WM_LBUTTONDBLCLK_){int x=(short)(lParam&0xFFFF),y=(short)((lParam>>16)&0xFFFF);
        if(g_uiView==UI_VIEW_SCANNER){if(ui_contains(g_ui.scanValueBox,x,y)){ui_set_text_focus(UI_TEXT_SCAN);ui_select_all_text(UI_TEXT_SCAN);return 0;}if(ui_contains(g_ui.watchNameBox,x,y)&&g_uiSelectedWatch>=0){ui_set_text_focus(UI_TEXT_WATCH_NAME);ui_select_all_text(UI_TEXT_WATCH_NAME);return 0;}if(ui_contains(g_ui.watchValueBox,x,y)&&g_uiSelectedWatch>=0){ui_set_text_focus(UI_TEXT_WATCH);ui_select_all_text(UI_TEXT_WATCH);return 0;}int rr=ui_result_row_at(x,y);if(rr>=0){g_uiSelectedResult=rr;ui_add_selected_result();return 0;}}
        else if(g_uiView==UI_VIEW_POINTERS){int pr=ui_pointer_row_at(x,y);if(pr>=0){g_uiSelectedPointer=pr;ui_add_pointer_chain_to_watch(pr);return 0;}}
        else if(g_uiView==UI_VIEW_TRAINER){
            if(g_uiTrainerMode==1){
                if(ui_contains(g_ui.trainerColorBg,x,y)){ui_set_text_focus(UI_TEXT_COLOR_BG);ui_select_all_text(UI_TEXT_COLOR_BG);return 0;}
                if(ui_contains(g_ui.trainerColorPanel,x,y)){ui_set_text_focus(UI_TEXT_COLOR_PANEL);ui_select_all_text(UI_TEXT_COLOR_PANEL);return 0;}
                if(ui_contains(g_ui.trainerColorSurface,x,y)){ui_set_text_focus(UI_TEXT_COLOR_SURFACE);ui_select_all_text(UI_TEXT_COLOR_SURFACE);return 0;}
                if(ui_contains(g_ui.trainerColorAccent,x,y)){ui_set_text_focus(UI_TEXT_COLOR_ACCENT);ui_select_all_text(UI_TEXT_COLOR_ACCENT);return 0;}
                if(ui_contains(g_ui.trainerColorText,x,y)){ui_set_text_focus(UI_TEXT_COLOR_TEXT);ui_select_all_text(UI_TEXT_COLOR_TEXT);return 0;}
                if(ui_contains(g_ui.trainerColorMuted,x,y)){ui_set_text_focus(UI_TEXT_COLOR_MUTED);ui_select_all_text(UI_TEXT_COLOR_MUTED);return 0;}
            }else{
                if(ui_contains(g_ui.trainerTitleBox,x,y)){ui_set_text_focus(UI_TEXT_TRAINER_TITLE);ui_select_all_text(UI_TEXT_TRAINER_TITLE);return 0;}
                if(g_uiTrainerElementSelected>=0&&g_uiTrainerElementSelected<g_uiTrainerElementCount){UiTrainerElement_& el=g_uiTrainerElements[g_uiTrainerElementSelected];if(el.type==UI_TRAINER_FIELD){if(ui_contains(g_ui.trainerLabelBox,x,y)){ui_set_text_focus(UI_TEXT_TRAINER_LABEL);ui_select_all_text(UI_TEXT_TRAINER_LABEL);return 0;}if(ui_contains(g_ui.trainerDefaultBox,x,y)){ui_set_text_focus(UI_TEXT_TRAINER_DEFAULT);ui_select_all_text(UI_TEXT_TRAINER_DEFAULT);return 0;}}else{UiRect textBox=ui_trainer_text_property_box();if(ui_contains(textBox,x,y)){ui_set_text_focus(UI_TEXT_TRAINER_LABEL);ui_select_all_text(UI_TEXT_TRAINER_LABEL);return 0;}}}
            }
        }return 0;}
    if(msg==WM_MOUSEWHEEL_){POINT_ p{(short)(lParam&0xFFFF),(short)((lParam>>16)&0xFFFF)};ScreenToClient(hwnd,&p);short d=(short)((wParam>>16)&0xFFFF);ui_scroll((int)d,(int)p.x,(int)p.y);return 0;}
    if(msg==WM_TIMER_){if(!g_uiBusy&&g_uiView==UI_VIEW_POINTERS)ui_pointer_refresh_visible_cache();if(!g_uiBusy||g_uiBusy==2)InvalidateRect(hwnd,nullptr,0);return 0;}
    if(msg==WM_APP_SCAN_DONE_){g_uiBusy=0;if(g_uiTask.kind==1){if(wParam)g_uiScanType=g_uiUnknownFlow?ui_scan_type_from_next_mode(guided_recommended_mode()):0;else{g_uiUnknownFlow=false;g_uiUnknownInitialMode=0;g_uiScanType=0;}}if(!g_snapshotActive&&g_resultCount)g_uiSelectedResult=(g_rankingEnabled&&g_rankedCount&&!g_rankingDirty)?(int)g_rankedIndices[0]:0;else g_uiSelectedResult=-1;g_uiResultScroll=0;ui_sync_edits();if(wParam){char b[260];usize n=0;if(g_snapshotActive){append_str(b,sizeof(b),n,ui_tr("status.unknownReadyPrefix"));ui_append_compact_count(b,sizeof(b),n,g_snapshotCandidates);append_str(b,sizeof(b),n,ui_tr("status.unknownReadyMiddle"));append_u64_dec(b,sizeof(b),n,g_snapshotBytes/(1024*1024));append_str(b,sizeof(b),n,ui_tr("status.unknownReadySuffix"));}else{append_str(b,sizeof(b),n,ui_tr("status.scanDonePrefix"));ui_append_compact_count(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n,ui_tr("status.scanDoneSuffix"));}b[n]=0;ui_set_status(b,1);}else ui_set_status(ui_tr("status.scanFailed"),3);InvalidateRect(hwnd,nullptr,0);return 0;}
    if(msg==WM_APP_POINTER_DONE_){int kind=(int)lParam;g_uiBusy=0;g_uiPointerPhase=0;g_pointerCancelRequested=0;g_uiSelectedPointer=g_pointerChainCount?0:-1;g_uiPointerScroll=0;ui_pointer_reset_cache();ui_pointer_refresh_visible_cache();if(wParam==2){ui_set_status(ui_tr("pointers.cancelled"),2);}else if(!wParam){ui_set_status(kind==4?ui_tr("pointers.rescanFailed"):ui_tr("pointers.scanFailed"),3);}else{char b[300];usize n=0;if(kind==4){append_str(b,sizeof(b),n,ui_tr("pointers.rescanDonePrefix"));append_u64_dec(b,sizeof(b),n,g_uiPointerBefore);append_str(b,sizeof(b),n," -> ");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n,ui_tr("pointers.stableChainsSuffix"));}else{append_str(b,sizeof(b),n,ui_tr("pointers.scanDonePrefix"));append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n,ui_tr("pointers.chainsSuffix"));if(g_uiPointerTargetedUsed){append_str(b,sizeof(b),n,ui_tr("pointers.targetedLevel"));append_u64_dec(b,sizeof(b),n,g_pointerLayerDepth);append_str(b,sizeof(b),n,ui_tr("pointers.matches"));append_u64_dec(b,sizeof(b),n,g_pointerLayerMatches);if(g_pointerLayerTruncated)append_str(b,sizeof(b),n,ui_tr("pointers.frontierLimited"));}else{append_str(b,sizeof(b),n,ui_tr("pointers.indexPrefix"));append_u64_dec(b,sizeof(b),n,g_uiPointerIndexed);if(g_uiPointerIndexTruncated)append_str(b,sizeof(b),n,ui_tr("pointers.partial"));append_str(b,sizeof(b),n,ui_tr("pointers.targetParents"));append_u64_dec(b,sizeof(b),n,g_uiPointerLevel1Candidates);if(g_uiPointerSearchBudgetHit)append_str(b,sizeof(b),n,ui_tr("pointers.budgetHit"));else if(g_uiPointerSearchTruncated)append_str(b,sizeof(b),n,ui_tr("pointers.searchLimited"));}if(g_uiPointerAutoRootFallback)append_str(b,sizeof(b),n,ui_tr("pointers.fallbackModules"));append_str(b,sizeof(b),n,".");}b[n]=0;ui_set_status(b,(kind==3&&g_pointerChainCount==0)?2:1);}InvalidateRect(hwnd,nullptr,0);return 0;}
    if(msg==WM_PAINT_){PAINTSTRUCT_ ps{};HDC dc=BeginPaint(hwnd,&ps);RECT_ c{};GetClientRect(hwnd,&c);int w=(int)(c.right-c.left),h=(int)(c.bottom-c.top);HDC mem=CreateCompatibleDC(dc);HBITMAP bmp=CreateCompatibleBitmap(dc,w,h);HGDIOBJ old=SelectObject(mem,(HGDIOBJ)bmp);ui_render(mem);BitBlt(dc,0,0,w,h,mem,0,0,SRCCOPY_);SelectObject(mem,old);DeleteObject((HGDIOBJ)bmp);DeleteDC(mem);EndPaint(hwnd,&ps);return 0;}
    if(msg==WM_CLOSE_&&g_uiBusy){ui_set_status(g_uiBusy==2?ui_tr("status.closePointerBusy"):ui_tr("status.closeScanBusy"),2);return 0;}
    if(msg==WM_DESTROY_){KillTimer(hwnd,1);close_target();free_pointer_maps();if(g_results)HeapFree(g_heap,0,g_results);if(g_aobResults)HeapFree(g_heap,0,g_aobResults);if(g_pointerIndex)HeapFree(g_heap,0,g_pointerIndex);if(g_pointerChains)HeapFree(g_heap,0,g_pointerChains);if(g_snapshotBlocks)HeapFree(g_heap,0,g_snapshotBlocks);ui_destroy_resources();PostQuitMessage(0);return 0;}
    return DefWindowProcA(hwnd,msg,wParam,lParam);
}

extern "C" void guiCRTStartup(){
    SetProcessDPIAware();g_heap=GetProcessHeap();ui_locale_initialize();strcopy(g_uiStatus,sizeof(g_uiStatus),ui_tr("status.ready"));g_out=CreateFileA("NUL",GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);DWORD tid=0;HANDLE fth=CreateThread(nullptr,0,freeze_thread,nullptr,0,&tid);if(fth)CloseHandle(fth);
    HINSTANCE inst=GetModuleHandleA(nullptr);WNDCLASSEXA_ wc{};wc.cbSize=(UINT)sizeof(wc);wc.style=CS_DBLCLKS_;wc.lpfnWndProc=ui_wndproc;wc.hInstance=inst;wc.hCursor=LoadCursorA(nullptr,(const char*)(uptr)32512);wc.hbrBackground=nullptr;wc.lpszClassName="CheatWizardGuiV2";
    if(!RegisterClassExA(&wc)){MessageBoxA(nullptr,"RegisterClassExA failed.",ui_tr("app.name"),MB_OK_|MB_ICONERROR_);ExitProcess(1);}DWORD style=WS_OVERLAPPED_|WS_CAPTION_|WS_SYSMENU_|WS_MINIMIZEBOX_|WS_MAXIMIZEBOX_|WS_THICKFRAME_;
    HWND hwnd=CreateWindowExA(0,"CheatWizardGuiV2","Cheat Wizard v1.7.0 - Memory Scanner, Pointers & Trainer Projects",style,70,45,1320,860,nullptr,nullptr,inst,nullptr);if(!hwnd){MessageBoxA(nullptr,"CreateWindowExA failed.",ui_tr("app.name"),MB_OK_|MB_ICONERROR_);ExitProcess(2);}g_hwnd=hwnd;ui_set_localized_window_title();ui_try_dark_titlebar(hwnd);ShowWindow(hwnd,SW_SHOW_);UpdateWindow(hwnd);
    MSG_ m{};while(GetMessageA(&m,nullptr,0,0)>0){TranslateMessage(&m);DispatchMessageA(&m);}if(g_out)CloseHandle(g_out);ExitProcess(0);
}
