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
// Volatile byte loops are intentional: optimized MSVC builds must not fold these
// no-CRT implementations back into calls to memcpy/memset themselves.
extern "C" void* memcpy(void* d, const void* s, usize n) { auto* dd=(volatile u8*)d; auto* ss=(const volatile u8*)s; for(usize i=0;i<n;++i) dd[i]=ss[i]; return d; }
extern "C" void* memset(void* d, int c, usize n) { auto* dd=(volatile u8*)d; for(usize i=0;i<n;++i) dd[i]=(u8)c; return d; }

static constexpr DWORD STD_INPUT_HANDLE  = (DWORD)-10;
static constexpr DWORD STD_OUTPUT_HANDLE = (DWORD)-11;
static constexpr DWORD GENERIC_READ = 0x80000000UL;
static constexpr DWORD GENERIC_WRITE = 0x40000000UL;
static constexpr DWORD CREATE_ALWAYS = 2;
static constexpr DWORD OPEN_EXISTING = 3;
static constexpr DWORD FILE_ATTRIBUTE_NORMAL = 0x80;
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
static constexpr usize MAX_POINTER_CHAINS = 10000ULL;
static constexpr usize MAX_POINTER_DEPTH = 8ULL;
static constexpr usize MAX_MODULES = 256ULL;
static constexpr usize MAX_POINTER_MAPS = 4ULL;
static constexpr usize MAX_SNAPSHOT_BLOCKS = 4096ULL;
static constexpr u64 MAX_SNAPSHOT_BYTES = 512ULL * 1024ULL * 1024ULL;

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
    usize size;
    usize candidateBytes;
    u8* bytes;
};

enum class ValueType : u8 { Byte, Int16, Int32, Int64, Float, Double, Mixed, Invalid };
enum class NextMode : u8 { Exact, Changed, Unchanged, Increased, Decreased, Bigger, Smaller };

struct FreezeEntry {
    volatile LONG active;
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
static ValueType g_profileType = ValueType::Invalid;
static char g_profileProcess[260] = {};
static char g_profilePath[260] = {};
static bool g_pointerIndexTruncated = false;
static bool g_pointerChainsTruncated = false;
static usize g_pointerIndexLimit = MAX_POINTER_ENTRIES;
static usize g_pointerAlignment = 0; // 0 = natural target-pointer alignment
static bool g_pointerWritableOnly = false;
static bool g_pointerPrivateOnly = false;
static usize g_pointerBranchCap = 4096;
static u64 g_pointerSearchSteps = 0;
static u64 g_pointerSearchBudget = 1500000ULL;
static bool g_pointerSearchBudgetHit = false;
static char g_pointerRootModule[256] = {};
static PointerMap_ g_pointerMaps[MAX_POINTER_MAPS] = {};
static usize g_pointerMapCount = 0;
static SnapshotBlock_ g_snapshotBlocks[MAX_SNAPSHOT_BLOCKS] = {};
static usize g_snapshotCount = 0;
static u64 g_snapshotBytes = 0;
static usize g_snapshotCandidates = 0;
static bool g_snapshotAllUnknown = false;
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

static bool encode_value(ValueType t,const char* s,u8 out[8]){ memzero(out,8); i64 iv=0; double dv=0; switch(t){case ValueType::Byte: if(!parse_i64(s,iv)||iv<0||iv>255)return false; {u8 x=(u8)iv;memcopy(out,&x,1);}return true; case ValueType::Int16:if(!parse_i64(s,iv)||iv<-32768||iv>32767)return false;{i16 x=(i16)iv;memcopy(out,&x,2);}return true; case ValueType::Int32:if(!parse_i64(s,iv)||iv<(-2147483647LL-1)||iv>2147483647LL)return false;{i32 x=(i32)iv;memcopy(out,&x,4);}return true; case ValueType::Int64:if(!parse_i64(s,iv))return false;{i64 x=iv;memcopy(out,&x,8);}return true; case ValueType::Float:if(!parse_double_simple(s,dv))return false;{float x=(float)dv;memcopy(out,&x,4);}return true; case ValueType::Double:if(!parse_double_simple(s,dv))return false;{double x=dv;memcopy(out,&x,8);}return true; default:return false;} }

static void append_value(char* b,usize cap,usize& n,ValueType t,const u8* raw){ switch(t){case ValueType::Byte:{u8 x=0;memcopy(&x,raw,1);append_u64_dec(b,cap,n,x);break;}case ValueType::Int16:{i16 x=0;memcopy(&x,raw,2);append_i64_dec(b,cap,n,x);break;}case ValueType::Int32:{i32 x=0;memcopy(&x,raw,4);append_i64_dec(b,cap,n,x);break;}case ValueType::Int64:{i64 x=0;memcopy(&x,raw,8);append_i64_dec(b,cap,n,x);break;}case ValueType::Float:{float x=0;memcopy(&x,raw,4);append_double(b,cap,n,(double)x);break;}case ValueType::Double:{double x=0;memcopy(&x,raw,8);append_double(b,cap,n,x);break;}default:append_str(b,cap,n,"?");}}

static bool readable(DWORD p){ if(p&PAGE_GUARD)return false; DWORD x=p&0xFF; return x==PAGE_READONLY||x==PAGE_READWRITE||x==PAGE_WRITECOPY||x==PAGE_EXECUTE_READ||x==PAGE_EXECUTE_READWRITE||x==PAGE_EXECUTE_WRITECOPY; }
static bool writable(DWORD p){ if(p&PAGE_GUARD)return false; DWORD x=p&0xFF; return x==PAGE_READWRITE||x==PAGE_WRITECOPY||x==PAGE_EXECUTE_READWRITE||x==PAGE_EXECUTE_WRITECOPY; }
static bool executable(DWORD p){ if(p&PAGE_GUARD)return false; DWORD x=p&0xFF; return x==0x10||x==PAGE_EXECUTE_READ||x==PAGE_EXECUTE_READWRITE||x==PAGE_EXECUTE_WRITECOPY; }

static usize scan_start_offset(uptr base,usize alignment);
static void clear_results(){ g_resultCount=0; }
static bool reserve_results(usize need){ if(need<=g_resultCap)return true; usize nc=g_resultCap?g_resultCap:4096; while(nc<need){usize next=nc*2;if(next<nc){nc=need;break;}nc=next;if(nc>MAX_RESULTS){nc=MAX_RESULTS;break;}} if(nc<need)return false; SIZE_T bytes=nc*(SIZE_T)sizeof(Result); void* p=g_results?HeapReAlloc(g_heap,0,g_results,bytes):HeapAlloc(g_heap,0,bytes); if(!p)return false;g_results=(Result*)p;g_resultCap=nc;return true; }
static bool add_result(uptr addr,const u8* raw,u8 sz,ValueType t){ if(g_resultCount>=MAX_RESULTS)return false; if(!reserve_results(g_resultCount+1))return false; Result& r=g_results[g_resultCount++];r.address=addr;memzero(r.previous,8);memcopy(r.previous,raw,sz);r.type=(u8)t;return true; }


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

static void clear_snapshot(){
    for(usize i=0;i<g_snapshotCount;++i){
        if(g_snapshotBlocks[i].bytes)HeapFree(g_heap,0,g_snapshotBlocks[i].bytes);
        memzero(&g_snapshotBlocks[i],sizeof(SnapshotBlock_));
    }
    g_snapshotCount=0;g_snapshotBytes=0;g_snapshotCandidates=0;g_snapshotAllUnknown=false;
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
static bool add_snapshot_block(uptr base,const u8* data,usize size,usize candidateBytes){
    if(!data||!size||g_snapshotCount>=MAX_SNAPSHOT_BLOCKS||g_snapshotBytes>=MAX_SNAPSHOT_BYTES)return false;
    u64 remaining=MAX_SNAPSHOT_BYTES-g_snapshotBytes;
    usize keep=(u64)size<remaining?size:(usize)remaining;
    if(!keep)return false;
    u8* copy=(u8*)HeapAlloc(g_heap,0,keep);if(!copy)return false;
    memcopy(copy,data,keep);
    SnapshotBlock_& b=g_snapshotBlocks[g_snapshotCount++];b.base=base;b.size=keep;b.candidateBytes=candidateBytes<keep?candidateBytes:keep;b.bytes=copy;
    g_snapshotBytes+=keep;
    const usize sizes[6]={1,2,4,8,4,8};
    for(int i=0;i<6;++i){
        usize c=candidate_count_for(base,keep,b.candidateBytes,sizes[i]);usize max=(usize)-1;
        if(c>max-g_snapshotCandidates)g_snapshotCandidates=max;else g_snapshotCandidates+=c;
    }
    return keep==size;
}

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
static bool build_pointer_index(){
    if(!g_process){println("Attach to a process first.");return false;}
    clear_pointer_index();
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);
    uptr min=(uptr)si.lpMinimumApplicationAddress,max=(uptr)si.lpMaximumApplicationAddress;
    usize alignment=g_pointerAlignment?g_pointerAlignment:(usize)g_pointerSize;
    if(!(alignment==1||alignment==2||alignment==4||alignment==8)){println("Invalid pointer alignment setting.");return false;}
    u8* buf=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!buf){println("Out of memory.");return false;}
    uptr cur=min;usize regions=0;
    while(cur<max&&!g_pointerIndexTruncated){
        MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx((HANDLE)g_process,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;
        uptr base=(uptr)mbi.BaseAddress,end=base+(uptr)mbi.RegionSize;if(end<=cur)break;
        bool allowed=mbi.State==MEM_COMMIT&&readable(mbi.Protect);
        if(allowed&&g_pointerWritableOnly&&!writable(mbi.Protect))allowed=false;
        if(allowed&&g_pointerPrivateOnly&&mbi.Type!=MEM_PRIVATE)allowed=false;
        if(allowed){
            ++regions;
            for(uptr p=base;p<end&&!g_pointerIndexTruncated;){
                usize primary=(usize)((end-p)>SCAN_CHUNK?SCAN_CHUNK:(end-p));
                usize extra=(p+primary<end)?(usize)(g_pointerSize-1):0;
                usize toRead=primary+extra;if(p+toRead>end)toRead=(usize)(end-p);
                SIZE_T got=0;ReadProcessMemory((HANDLE)g_process,(LPCVOID)p,buf,toRead,&got);
                if(got>=g_pointerSize){
                    usize startOff=0;usize rem=(usize)(p%alignment);if(rem)startOff=alignment-rem;
                    for(usize off=startOff;off<primary&&off+g_pointerSize<=(usize)got;off+=alignment){
                        uptr value=0;
                        if(g_pointerSize==4){u32 v=0;memcopy(&v,buf+off,4);value=(uptr)v;}
                        else{u64 v=0;memcopy(&v,buf+off,8);value=(uptr)v;}
                        if(value>=min&&value<max){if(!add_pointer_entry(value,p+off))break;}
                    }
                }
                p+=primary;
            }
        }
        cur=end;
    }
    HeapFree(g_heap,0,buf);sort_pointer_index();
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
    if(g_pointerSearchBudgetHit||revCount>=maxDepth||g_pointerChainCount>=maxChains)return;
    uptr low=current>=maxOffset?current-maxOffset:0;
    uptr high=(~(uptr)0-current<maxNegativeOffset)?~(uptr)0:current+maxNegativeOffset;
    usize begin=lower_pointer_value(low),end=upper_pointer_value(high);if(begin>=end)return;
    usize right=lower_pointer_value(current);if(right<begin)right=begin;if(right>end)right=end;usize left=right,candidates=0;
    while(left>begin||right<end){
        if(++candidates>g_pointerBranchCap){g_pointerChainsTruncated=true;break;}
        if(++g_pointerSearchSteps>g_pointerSearchBudget){g_pointerSearchBudgetHit=true;g_pointerChainsTruncated=true;break;}
        bool takeLeft=false;if(left>begin&&right<end){uptr lv=g_pointerIndex[left-1].value,rv=g_pointerIndex[right].value;uptr ld=current>=lv?current-lv:lv-current;uptr rd=current>=rv?current-rv:rv-current;takeLeft=ld<=rd;}else takeLeft=left>begin;
        usize i=takeLeft?--left:right++;const PointerEntry& e=g_pointerIndex[i];i64 offset=0;
        if(e.value<=current){uptr diff=current-e.value;if(diff>maxOffset||diff>0x7FFFFFFFFFFFFFFFULL)continue;offset=(i64)diff;}
        else{uptr diff=e.value-current;if(diff>maxNegativeOffset||diff>0x7FFFFFFFFFFFFFFFULL)continue;offset=-(i64)diff;}
        uptr slot=e.address;if(path_has(path,pathCount,slot))continue;int mi=module_for_address(slot);
        if(mi>=0){if(!add_pointer_chain(mi,slot,slot-g_modules[mi].base,rev,revCount,offset,maxChains))return;continue;}
        if(revCount+1<maxDepth){rev[revCount]=offset;path[pathCount]=slot;pointer_dfs(slot,maxDepth,maxOffset,maxNegativeOffset,maxChains,rev,(u8)(revCount+1),path,(u8)(pathCount+1));if(g_pointerChainCount>=maxChains||g_pointerSearchBudgetHit)return;}
    }
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
    append_str(b,sizeof(b),n," | branch=");append_u64_dec(b,sizeof(b),n,g_pointerBranchCap);append_str(b,sizeof(b),n," | budget=");append_u64_dec(b,sizeof(b),n,g_pointerSearchBudget);
    append_str(b,sizeof(b),n," | root=");append_str(b,sizeof(b),n,g_pointerRootModule[0]?g_pointerRootModule:"any module");append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);
}
static void cmd_pointer_settings(const char* key,const char* value){
    if(!key){print_pointer_settings();return;}if(!value){println("Usage: pointer-settings <alignment|writable|private|branch|budget|root> <value>");return;}
    if(strieq(key,"alignment")){
        if(strieq(value,"natural")||strieq(value,"aligned"))g_pointerAlignment=0;
        else if(strieq(value,"byte")||streq(value,"1")||strieq(value,"unaligned"))g_pointerAlignment=1;
        else{u64 x=0;if(!parse_u64(value,x)||(x!=2&&x!=4&&x!=8)){println("Alignment must be natural, byte, 2, 4 or 8.");return;}g_pointerAlignment=(usize)x;}
    }else if(strieq(key,"writable")){bool v=false;if(!parse_onoff(value,v)){println("Writable must be on/off.");return;}g_pointerWritableOnly=v;
    }else if(strieq(key,"private")){bool v=false;if(!parse_onoff(value,v)){println("Private must be on/off.");return;}g_pointerPrivateOnly=v;
    }else if(strieq(key,"branch")||strieq(key,"branching")){u64 x=0;if(!parse_u64(value,x)||x<1||x>65536){println("Branch cap must be 1..65536.");return;}g_pointerBranchCap=(usize)x;
    }else if(strieq(key,"budget")){u64 x=0;if(!parse_u64(value,x)||x<1000||x>100000000ULL){println("Search budget must be 1000..100000000.");return;}g_pointerSearchBudget=x;
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
    g_pointerSearchSteps=0;g_pointerSearchBudgetHit=false;i64 rev[MAX_POINTER_DEPTH]={};uptr path[MAX_POINTER_DEPTH+1]={};path[0]=target;pointer_dfs(target,(u8)depth,(uptr)maxOffset,(uptr)maxNegativeOffset,(usize)maxChains,rev,0,path,1);
    char b[360];usize n=0;append_str(b,sizeof(b),n,"Pointer scan found ");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n," chain(s), pointer width ");append_u64_dec(b,sizeof(b),n,(u64)g_pointerSize*8);append_str(b,sizeof(b),n,"-bit, max negative offset ");append_hex(b,sizeof(b),n,(uptr)maxNegativeOffset);if(g_pointerSearchBudgetHit)append_str(b,sizeof(b),n," [SEARCH BUDGET HIT]");else if(g_pointerChainsTruncated)append_str(b,sizeof(b),n," [TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);usize preview=g_pointerChainCount<20?g_pointerChainCount:20;for(usize i=0;i<preview;++i)print_pointer_chain(i);
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
    if(g_snapshotAllUnknown){println("Mixed unknown raw snapshots are not persisted. Run a Next Scan first.");return;}
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
    g_type=mixed?ValueType::Mixed:primaryType;g_alignmentByte=alignment!=0;
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
static bool write_address(uptr addr,ValueType t,const char* value);
static bool load_pointer_profile_file(const char* path){
    if(!path||!*path)return false;HANDLE h=CreateFileA(path,GENERIC_READ,1,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if((uptr)h==INVALID_HANDLE_BITS)return false;const char expect[8]={'C','W','P','R','O','F','0','1'};const char legacy[8]={'M','C','E','P','R','O','F','1'};char magic[8]{};u32 ver=0,ps=0,ty=0;u16 plen=0;u64 count=0;bool ok=file_read_exact(h,magic,8)&&file_read_exact(h,&ver,4)&&file_read_exact(h,&ps,4)&&file_read_exact(h,&ty,4)&&file_read_exact(h,&plen,2)&&file_read_exact(h,&count,8);
    if(!ok||(!memequal(magic,expect,8)&&!memequal(magic,legacy,8))||ver!=1||(ps!=4&&ps!=8)||ty>(u32)ValueType::Double||plen>=260||count==0||count>MAX_POINTER_CHAINS){CloseHandle(h);return false;}char proc[260]{};if(plen&&!file_read_exact(h,proc,plen)){CloseHandle(h);return false;}proc[plen]=0;if(g_process&&ps!=g_pointerSize){CloseHandle(h);return false;}clear_pointer_index();clear_pointer_chains();if(!reserve_pointer_chains((usize)count)){CloseHandle(h);return false;}
    for(u64 i=0;i<count&&ok;++i){PointerChain_ c{};u16 ml=0;u64 root=0;u32 depth=0;if(!file_read_exact(h,&ml,2)||ml==0||ml>=256||!file_read_exact(h,c.module,ml)||!file_read_exact(h,&root,8)||!file_read_exact(h,&depth,4)||depth==0||depth>MAX_POINTER_DEPTH){ok=false;break;}c.module[ml]=0;c.rootOffset=(uptr)root;c.depth=(u8)depth;for(u32 j=0;j<depth;++j){u64 raw=0;if(!file_read_exact(h,&raw,8)){ok=false;break;}memcopy(&c.offsets[j],&raw,8);}if(ok)g_pointerChains[g_pointerChainCount++]=c;}
    CloseHandle(h);if(!ok){clear_pointer_chains();return false;}g_chainPointerSize=(u8)ps;g_profileType=(ValueType)ty;strcopy(g_profileProcess,sizeof(g_profileProcess),proc);strcopy(g_profilePath,sizeof(g_profilePath),path);return true;
}
static void sort_profile_addresses(uptr* a,usize count){if(!a||count<2)return;auto sift=[&](usize start,usize n){usize root=start;for(;;){usize child=root*2+1;if(child>=n)return;usize best=root;if(a[best]<a[child])best=child;if(child+1<n&&a[best]<a[child+1])best=child+1;if(best==root)return;uptr v=a[root];a[root]=a[best];a[best]=v;root=best;}};for(usize i=count/2;i>0;--i)sift(i-1,count);for(usize end=count;end>1;--end){uptr v=a[0];a[0]=a[end-1];a[end-1]=v;sift(0,end-1);}}
static bool resolve_loaded_profile(uptr& address,usize& agreeing,usize& resolvedCount){
    address=0;agreeing=0;resolvedCount=0;if(!g_process||!g_pointerChainCount)return false;if(!refresh_modules())return false;uptr* values=(uptr*)HeapAlloc(g_heap,0,g_pointerChainCount*sizeof(uptr));if(!values)return false;for(usize i=0;i<g_pointerChainCount;++i){uptr r=0;if(resolve_pointer_chain(g_pointerChains[i],r))values[resolvedCount++]=r;}if(!resolvedCount){HeapFree(g_heap,0,values);return false;}sort_profile_addresses(values,resolvedCount);uptr best=values[0];usize bestCount=1,run=1;for(usize i=1;i<resolvedCount;++i){if(values[i]==values[i-1])++run;else{if(run>bestCount){bestCount=run;best=values[i-1];}run=1;}}if(run>bestCount){bestCount=run;best=values[resolvedCount-1];}HeapFree(g_heap,0,values);address=best;agreeing=bestCount;return true;
}
static void cmd_profile_load(const char* path){if(!load_pointer_profile_file(path)){println("PROFILE_ERR load_failed");return;}char b[620];usize n=0;append_str(b,sizeof(b),n,"PROFILE_OK loaded chains=");append_u64_dec(b,sizeof(b),n,g_pointerChainCount);append_str(b,sizeof(b),n," type=");append_str(b,sizeof(b),n,type_name(g_profileType));append_str(b,sizeof(b),n," process=");append_str(b,sizeof(b),n,g_profileProcess[0]?g_profileProcess:"?");append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}
static void cmd_profile_read(){if(!g_process){println("PROFILE_ERR not_attached");return;}if(g_profileType==ValueType::Invalid||!g_pointerChainCount){println("PROFILE_ERR no_profile");return;}uptr a=0;usize agree=0,res=0;if(!resolve_loaded_profile(a,agree,res)){println("PROFILE_ERR unresolved");return;}if(agree*2<=res){char b[180];usize n=0;append_str(b,sizeof(b),n,"PROFILE_ERR ambiguous agree=");append_u64_dec(b,sizeof(b),n,agree);append_char(b,sizeof(b),n,'/');append_u64_dec(b,sizeof(b),n,res);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);return;}u8 raw[8]{};u8 sz=type_size(g_profileType);SIZE_T got=0;if(!ReadProcessMemory((HANDLE)g_process,(LPCVOID)a,raw,sz,&got)||got!=sz){println("PROFILE_ERR unreadable");return;}char b[520];usize n=0;append_str(b,sizeof(b),n,"PROFILE_OK address=");append_hex(b,sizeof(b),n,a);append_str(b,sizeof(b),n," type=");append_str(b,sizeof(b),n,type_name(g_profileType));append_str(b,sizeof(b),n," agree=");append_u64_dec(b,sizeof(b),n,agree);append_char(b,sizeof(b),n,'/');append_u64_dec(b,sizeof(b),n,res);append_str(b,sizeof(b),n," value=");append_value(b,sizeof(b),n,g_profileType,raw);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}
static void cmd_profile_write(const char* value){if(!g_process){println("PROFILE_ERR not_attached");return;}if(g_profileType==ValueType::Invalid||!g_pointerChainCount){println("PROFILE_ERR no_profile");return;}uptr a=0;usize agree=0,res=0;if(!resolve_loaded_profile(a,agree,res)){println("PROFILE_ERR unresolved");return;}if(agree*2<=res){println("PROFILE_ERR ambiguous");return;}if(!write_address(a,g_profileType,value)){println("PROFILE_ERR write_failed");return;}char b[360];usize n=0;append_str(b,sizeof(b),n,"PROFILE_OK written address=");append_hex(b,sizeof(b),n,a);append_str(b,sizeof(b),n," agree=");append_u64_dec(b,sizeof(b),n,agree);append_char(b,sizeof(b),n,'/');append_u64_dec(b,sizeof(b),n,res);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}
static void cmd_profile_freeze(const char* value){if(!g_process){println("PROFILE_ERR not_attached");return;}if(g_profileType==ValueType::Invalid||!g_pointerChainCount){println("PROFILE_ERR no_profile");return;}uptr a=0;usize agree=0,res=0;if(!resolve_loaded_profile(a,agree,res)){println("PROFILE_ERR unresolved");return;}if(agree*2<=res){println("PROFILE_ERR ambiguous");return;}u8 raw[8]{};if(!encode_value(g_profileType,value,raw)){println("PROFILE_ERR bad_value");return;}int slot=-1;for(int i=0;i<MAX_FREEZES;++i)if(!g_freezes[i].active){slot=i;break;}if(slot<0){println("PROFILE_ERR freeze_full");return;}FreezeEntry& f=g_freezes[slot];f.address=a;f.size=type_size(g_profileType);f.type=(u8)g_profileType;memzero(f.bytes,8);memcopy(f.bytes,raw,f.size);f.active=1;write_address(a,g_profileType,value);char b[360];usize n=0;append_str(b,sizeof(b),n,"PROFILE_OK freeze=");append_u64_dec(b,sizeof(b),n,slot);append_str(b,sizeof(b),n," address=");append_hex(b,sizeof(b),n,a);append_str(b,sizeof(b),n," agree=");append_u64_dec(b,sizeof(b),n,agree);append_char(b,sizeof(b),n,'/');append_u64_dec(b,sizeof(b),n,res);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}

static bool ptr_addr_less(const PointerEntry& a,const PointerEntry& b){return a.address<b.address||(a.address==b.address&&a.value<b.value);}
static void sort_entries_by_address(PointerEntry* a,usize count){if(!a||count<2)return;auto sift=[&](usize start,usize n){usize root=start;for(;;){usize child=root*2+1;if(child>=n)return;usize best=root;if(ptr_addr_less(a[best],a[child]))best=child;if(child+1<n&&ptr_addr_less(a[best],a[child+1]))best=child+1;if(best==root)return;PointerEntry t=a[root];a[root]=a[best];a[best]=t;root=best;}};for(usize i=count/2;i>0;--i)sift(i-1,count);for(usize end=count;end>1;--end){PointerEntry t=a[0];a[0]=a[end-1];a[end-1]=t;sift(0,end-1);}}
static bool map_pointer_at(PointerMap_& m,uptr address,uptr& value){if(!m.entriesByAddress){sort_entries_by_address(m.entries,m.entryCount);m.entriesByAddress=true;}usize lo=0,hi=m.entryCount;while(lo<hi){usize mid=lo+(hi-lo)/2;if(m.entries[mid].address<address)lo=mid+1;else hi=mid;}if(lo>=m.entryCount||m.entries[lo].address!=address)return false;value=m.entries[lo].value;return true;}
static int map_module_by_name(PointerMap_& m,const char* name){for(usize i=0;i<m.moduleCount;++i)if(strieq(m.modules[i].name,name))return (int)i;return -1;}
static bool resolve_chain_map(PointerMap_& m,const PointerChain_& c,uptr& resolved){int mi=map_module_by_name(m,c.module);if(mi<0||c.rootOffset>=m.modules[mi].size)return false;uptr addr=m.modules[mi].base+c.rootOffset;for(u8 i=0;i<c.depth;++i){uptr pv=0;if(!map_pointer_at(m,addr,pv))return false;if(!add_signed_offset(pv,c.offsets[i],addr))return false;}resolved=addr;return true;}
static void free_pointer_maps(){for(usize i=0;i<g_pointerMapCount;++i){if(g_pointerMaps[i].entries)HeapFree(g_heap,0,g_pointerMaps[i].entries);g_pointerMaps[i]={};}g_pointerMapCount=0;}
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
static void close_target(){ clear_freezes(); HANDLE old=(HANDLE)g_process; g_process=nullptr; if(old)CloseHandle(old); g_pid=0; clear_results(); clear_snapshot(); clear_pointer_index(); g_moduleCount=0; g_type=ValueType::Invalid; }
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
static void cmd_clear(){ clear_results(); clear_snapshot(); clear_aob(); g_type=ValueType::Invalid; println("Value scan/snapshot and AOB results cleared."); }

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


static bool scan_all_unknown(){
    HANDLE proc=(HANDLE)g_process;if(!proc){println("Attach to a process first.");return false;}
    clear_results();clear_snapshot();g_type=ValueType::Mixed;
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);uptr cur=(uptr)si.lpMinimumApplicationAddress,max=(uptr)si.lpMaximumApplicationAddress;
    u8* buf=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!buf){println("Out of memory.");return false;}
    usize regions=0;bool truncated=false;
    while(cur<max&&!truncated){
        MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx(proc,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;
        uptr base=(uptr)mbi.BaseAddress,end=base+(uptr)mbi.RegionSize;if(end<=cur)break;
        if(mbi.State==MEM_COMMIT&&readable(mbi.Protect)){
            ++regions;uptr p=base;
            while(p<end){
                usize primary=(usize)((end-p)>SCAN_CHUNK?SCAN_CHUNK:(end-p));usize extra=(p+primary<end)?7:0;
                usize toRead=primary+extra;if(p+toRead>end)toRead=(usize)(end-p);SIZE_T got=0;
                ReadProcessMemory(proc,(LPCVOID)p,buf,toRead,&got);
                if(got>0){
                    usize candidateBytes=primary<(usize)got?primary:(usize)got;
                    if(!add_snapshot_block(p,buf,(usize)got,candidateBytes)){truncated=true;break;}
                }
                p+=primary;
            }
        }
        cur=end;
    }
    HeapFree(g_heap,0,buf);g_snapshotAllUnknown=g_snapshotCount>0;
    char b[360];usize n=0;append_str(b,sizeof(b),n,"Mixed unknown snapshot: ");append_u64_dec(b,sizeof(b),n,g_snapshotCount);append_str(b,sizeof(b),n," block(s), ");append_u64_dec(b,sizeof(b),n,g_snapshotBytes);append_str(b,sizeof(b),n," byte(s), ");append_u64_dec(b,sizeof(b),n,g_snapshotCandidates);append_str(b,sizeof(b),n," typed candidate(s) across ");append_u64_dec(b,sizeof(b),n,regions);append_str(b,sizeof(b),n," readable region(s)");if(truncated)append_str(b,sizeof(b),n," [TRUNCATED]");append_str(b,sizeof(b),n,". Change the value, then run next.\r\n");flush_buf(b,n);
    return g_snapshotAllUnknown;
}

static bool scan_unknown(ValueType t){
    HANDLE proc=(HANDLE)g_process;if(!proc){println("Attach to a process first.");return false;}
    clear_results();clear_snapshot();g_type=t;u8 sz=type_size(t);usize step=g_alignmentByte?1:sz;
    SYSTEM_INFO_ si{};GetNativeSystemInfo(&si);uptr cur=(uptr)si.lpMinimumApplicationAddress,max=(uptr)si.lpMaximumApplicationAddress;
    u8* buf=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!buf){println("Out of memory.");return false;}
    usize regions=0;bool truncated=false;
    while(cur<max){
        MEMORY_BASIC_INFORMATION_ mbi{};SIZE_T q=VirtualQueryEx(proc,(LPCVOID)cur,&mbi,sizeof(mbi));if(!q)break;
        uptr base=(uptr)mbi.BaseAddress,end=base+(uptr)mbi.RegionSize;if(end<=cur)break;
        if(mbi.State==MEM_COMMIT&&readable(mbi.Protect)){
            ++regions;uptr p=base;
            while(p<end){
                usize primary=(usize)((end-p)>SCAN_CHUNK?SCAN_CHUNK:(end-p));usize extra=(p+primary<end)?(usize)(sz-1):0;usize toRead=primary+extra;if(p+toRead>end)toRead=(usize)(end-p);SIZE_T got=0;
                if(ReadProcessMemory(proc,(LPCVOID)p,buf,toRead,&got)&&got>=sz){usize startOff=scan_start_offset(p,sz);for(usize off=startOff;off<primary&&off+sz<=(usize)got;off+=step){if(!add_result(p+off,buf+off,sz,t)){truncated=true;break;}}}
                if(truncated)break;p+=primary;
            }
        }
        if(truncated)break;cur=end;
    }
    HeapFree(g_heap,0,buf);char b[256];usize n=0;append_str(b,sizeof(b),n,"Unknown scan captured ");append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n," candidate(s) across ");append_u64_dec(b,sizeof(b),n,regions);append_str(b,sizeof(b),n," readable region(s)");if(truncated)append_str(b,sizeof(b),n," [TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);return true;
}

static int cmp_numeric(ValueType t,const u8* a,const u8* b){ switch(t){case ValueType::Byte:{u8 x=0,y=0;memcopy(&x,a,1);memcopy(&y,b,1);return x<y?-1:x>y?1:0;}case ValueType::Int16:{i16 x=0,y=0;memcopy(&x,a,2);memcopy(&y,b,2);return x<y?-1:x>y?1:0;}case ValueType::Int32:{i32 x=0,y=0;memcopy(&x,a,4);memcopy(&y,b,4);return x<y?-1:x>y?1:0;}case ValueType::Int64:{i64 x=0,y=0;memcopy(&x,a,8);memcopy(&y,b,8);return x<y?-1:x>y?1:0;}case ValueType::Float:{float x=0,y=0;memcopy(&x,a,4);memcopy(&y,b,4);return x<y?-1:x>y?1:0;}case ValueType::Double:{double x=0,y=0;memcopy(&x,a,8);memcopy(&y,b,8);return x<y?-1:x>y?1:0;}default:return 0;} }


static void next_scan_all_unknown(NextMode mode,const char* wantedText,bool hasWanted){
    HANDLE proc=(HANDLE)g_process;if(!proc||!g_snapshotAllUnknown){println("No mixed unknown snapshot is active.");return;}
    clear_results();
    const ValueType types[6]={ValueType::Byte,ValueType::Int16,ValueType::Int32,ValueType::Int64,ValueType::Float,ValueType::Double};
    u8* current=(u8*)HeapAlloc(g_heap,0,SCAN_CHUNK+8);if(!current){println("Out of memory.");return;}
    bool truncated=false;
    for(usize bi=0;bi<g_snapshotCount&&!truncated;++bi){
        SnapshotBlock_& block=g_snapshotBlocks[bi];if(!block.bytes||!block.size)continue;
        if(block.size>SCAN_CHUNK+8){truncated=true;break;}
        SIZE_T got=0;ReadProcessMemory(proc,(LPCVOID)block.base,current,block.size,&got);if(got==0)continue;
        usize available=(usize)got;
        for(int ti=0;ti<6&&!truncated;++ti){
            ValueType t=types[ti];u8 sz=type_size(t);if(available<sz)continue;
            u8 wanted[8]{};if(hasWanted&&!encode_value(t,wantedText,wanted))continue;
            usize step=g_alignmentByte?1:sz;usize start=scan_start_offset(block.base,sz);
            usize candidateBytes=block.candidateBytes<available?block.candidateBytes:available;
            for(usize off=start;off<candidateBytes&&off+sz<=available&&off+sz<=block.size;off+=step){
                const u8* now=current+off;const u8* previous=block.bytes+off;bool keep=false;int prevCmp=cmp_numeric(t,now,previous);
                switch(mode){
                    case NextMode::Exact:keep=hasWanted&&memequal(now,wanted,sz);break;
                    case NextMode::Changed:keep=!memequal(now,previous,sz);break;
                    case NextMode::Unchanged:keep=memequal(now,previous,sz);break;
                    case NextMode::Increased:keep=prevCmp>0;break;
                    case NextMode::Decreased:keep=prevCmp<0;break;
                    case NextMode::Bigger:keep=hasWanted&&cmp_numeric(t,now,wanted)>0;break;
                    case NextMode::Smaller:keep=hasWanted&&cmp_numeric(t,now,wanted)<0;break;
                }
                if(keep&&!add_result(block.base+off,now,sz,t)){truncated=true;break;}
            }
        }
    }
    HeapFree(g_heap,0,current);clear_snapshot();g_type=ValueType::Mixed;
    char b[220];usize n=0;append_str(b,sizeof(b),n,"Mixed unknown Next Scan materialized ");append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n," result(s)");if(truncated)append_str(b,sizeof(b),n," [TRUNCATED]");append_str(b,sizeof(b),n,".\r\n");flush_buf(b,n);
}

static void next_scan_text(NextMode mode,const char* wantedText,bool hasWanted){
    HANDLE proc=(HANDLE)g_process;if(!proc||g_type==ValueType::Invalid){println("Run a scan first.");return;}
    if(g_snapshotAllUnknown){next_scan_all_unknown(mode,wantedText,hasWanted);return;}
    usize out=0;u8 current[8];u8 wanted[8];
    for(usize i=0;i<g_resultCount;++i){
        ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[i].type:g_type;u8 sz=type_size(t);if(!sz)continue;
        if(hasWanted&&!encode_value(t,wantedText,wanted))continue;
        SIZE_T got=0;memzero(current,8);if(!ReadProcessMemory(proc,(LPCVOID)g_results[i].address,current,sz,&got)||got!=sz)continue;
        bool keep=false;int prevCmp=cmp_numeric(t,current,g_results[i].previous);
        switch(mode){case NextMode::Exact:keep=hasWanted&&memequal(current,wanted,sz);break;case NextMode::Changed:keep=!memequal(current,g_results[i].previous,sz);break;case NextMode::Unchanged:keep=memequal(current,g_results[i].previous,sz);break;case NextMode::Increased:keep=prevCmp>0;break;case NextMode::Decreased:keep=prevCmp<0;break;case NextMode::Bigger:keep=hasWanted&&cmp_numeric(t,current,wanted)>0;break;case NextMode::Smaller:keep=hasWanted&&cmp_numeric(t,current,wanted)<0;break;}
        if(keep){if(out!=i)g_results[out]=g_results[i];memcopy(g_results[out].previous,current,sz);g_results[out].type=(u8)t;++out;}
    }
    g_resultCount=out;char b[128];usize n=0;append_str(b,sizeof(b),n,"Next scan: ");append_u64_dec(b,sizeof(b),n,g_resultCount);append_str(b,sizeof(b),n," result(s).\r\n");flush_buf(b,n);
}

static bool parse_index(const char* s,usize& idx){if(!s)return false;if(*s=='#')++s;u64 v=0;if(!parse_u64(s,v))return false;if(v>=g_resultCount)return false;idx=(usize)v;return true;}

static void cmd_results(const char* countStr){
    if(g_snapshotAllUnknown){println("Mixed Unknown Initial Value snapshot is active. Change the target value and run next first.");return;}
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
static void cmd_freeze_at(const char* addressStr,const char* typeStr,const char* value){if(!g_process){println("Attach to a process first.");return;}u64 a=0;if(!parse_u64(addressStr,a)){println("Invalid address.");return;}ValueType t=parse_type(typeStr);if(t==ValueType::Invalid){println("Invalid type.");return;}u8 raw[8];if(!encode_value(t,value,raw)){println("Invalid value for type.");return;}int slot=-1;for(int i=0;i<MAX_FREEZES;++i)if(!g_freezes[i].active){slot=i;break;}if(slot<0){println("Freeze table full.");return;}FreezeEntry& f=g_freezes[slot];f.address=(uptr)a;f.size=type_size(t);f.type=(u8)t;memzero(f.bytes,8);memcopy(f.bytes,raw,f.size);f.active=1;write_address(f.address,t,value);char b[220];usize n=0;append_str(b,sizeof(b),n,"Freeze #");append_u64_dec(b,sizeof(b),n,(u64)slot);append_str(b,sizeof(b),n," active at ");append_hex(b,sizeof(b),n,f.address);append_str(b,sizeof(b),n," [");append_str(b,sizeof(b),n,type_name(t));append_str(b,sizeof(b),n,"] (50 ms worker).\r\n");flush_buf(b,n);}
static void cmd_set(const char* idxStr,const char* value){usize idx=0;if(!parse_index(idxStr,idx)){println("Invalid result index.");return;}ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[idx].type:g_type;u8 raw[8];if(!encode_value(t,value,raw)){println("Invalid value for this result type.");return;}if(!write_address(g_results[idx].address,t,value)){print_last_error("Write failed");return;}memcopy(g_results[idx].previous,raw,type_size(t));println("Value written.");}

static DWORD __stdcall freeze_thread(LPVOID){for(;;){HANDLE proc=(HANDLE)g_process;if(proc){for(int i=0;i<MAX_FREEZES;++i){if(g_freezes[i].active){SIZE_T wrote=0;WriteProcessMemory(proc,(LPVOID)g_freezes[i].address,g_freezes[i].bytes,g_freezes[i].size,&wrote);}}}Sleep(50);} }
static void cmd_freeze(const char* idxStr,const char* value){usize idx=0;if(!parse_index(idxStr,idx)){println("Invalid result index.");return;}ValueType t=g_type==ValueType::Mixed?(ValueType)g_results[idx].type:g_type;u8 raw[8];if(!encode_value(t,value,raw)){println("Invalid value for this result type.");return;}int slot=-1;for(int i=0;i<MAX_FREEZES;++i)if(!g_freezes[i].active){slot=i;break;}if(slot<0){println("Freeze table full.");return;}FreezeEntry& f=g_freezes[slot];f.address=g_results[idx].address;f.size=type_size(t);f.type=(u8)t;memzero(f.bytes,8);memcopy(f.bytes,raw,f.size);f.active=1;write_address(f.address,t,value);char b[160];usize n=0;append_str(b,sizeof(b),n,"Freeze #");append_u64_dec(b,sizeof(b),n,(u64)slot);append_str(b,sizeof(b),n," active at ");append_hex(b,sizeof(b),n,f.address);append_str(b,sizeof(b),n," [");append_str(b,sizeof(b),n,type_name(t));append_str(b,sizeof(b),n,"].\r\n");flush_buf(b,n);}
static void cmd_freezes(){bool any=false;for(int i=0;i<MAX_FREEZES;++i){if(!g_freezes[i].active)continue;any=true;char b[256];usize n=0;append_char(b,sizeof(b),n,'#');append_u64_dec(b,sizeof(b),n,(u64)i);append_str(b,sizeof(b),n,"  ");append_hex(b,sizeof(b),n,g_freezes[i].address);append_str(b,sizeof(b),n,"  ");append_value(b,sizeof(b),n,(ValueType)g_freezes[i].type,g_freezes[i].bytes);append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);}if(!any)println("No active freezes.");}
static void cmd_unfreeze(const char* s){if(streq(s,"all")){clear_freezes();println("All freezes removed.");return;}u64 x=0;if(!parse_u64(s,x)||x>=MAX_FREEZES){println("Invalid freeze id.");return;}g_freezes[x].active=0;println("Freeze removed.");}

static void show_help(){
    println("Cheat Wizard v1.7.2 x64 - scanner + scan sessions + AOB + pointer maps");
    println("  processes | ps");println("  attach <pid>");println("  attach-name <exe-name>");println("  detach");
    println("  scan <byte|int16|int32|int64|float|double> <value|unknown>");println("  scan all <value|unknown>");
    println("  next <value> | next exact <value>");println("  next changed | unchanged | increased | decreased");println("  next bigger <value> | smaller <value>");
    println("  results [count] | inspect <#index|address>");println("  read-at <address> <type> | write-at <address> <type> <value>");println("  freeze-at <address> <type> <value> (50 ms)");println("  scan-save <file.cwscan> | scan-load <file.cwscan> [force]");println("  set <#index> <value> | freeze <#index> <value>");println("  freezes | unfreeze <id|all>");
    println("  modules");println("  aob <byte...> | aob-code <byte...>");println("  aob-module <module> <byte...> | aob-module-code <module> <byte...>");println("  aob-results [count]");
    println("  aob-resolve <#aob-index|address> <disp_offset> <instruction_size>");println("      CALL/JMP E8/E9: aob-resolve #0 1 5");println("      RIP-relative example: aob-resolve #0 3 7");
    println("  aob-decode <#aob-index|address>");println("  aob-save <file.cwaob> | aob-load <file.cwaob> | aob-rerun <file.cwaob>");println("  aob-clear");
    println("  pointer-settings");println("  pointer-settings alignment <natural|byte|2|4|8>");println("  pointer-settings writable <on|off>");println("  pointer-settings private <on|off>");println("  pointer-settings branch <1..65536>");println("  pointer-settings root <any|module-name>");
    println("  pointer-scan <target> [depth] [max_offset] [max_chains] [max_negative_offset]");println("  pointer-results [count]");println("  pointer-resolve <chain-index>");println("  pointer-rescan <#index|address>");println("  pointer-save <file.cwchain> | pointer-load <file.cwchain>");println("  profile-load <file.cwptr> | profile-read | profile-write <value> | profile-freeze <value>");
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
    append_str(b,sizeof(b),n," | mixed snapshot: ");append_str(b,sizeof(b),n,g_snapshotAllUnknown?"active":"none");
    append_str(b,sizeof(b),n,"\r\n");flush_buf(b,n);
}

extern "C" void mainCRTStartup(){
    g_out=GetStdHandle(STD_OUTPUT_HANDLE);g_in=GetStdHandle(STD_INPUT_HANDLE);g_heap=GetProcessHeap();
    DWORD tid=0;HANDLE th=CreateThread(nullptr,0,freeze_thread,nullptr,0,&tid);if(th)CloseHandle(th);
    println("Cheat Wizard v1.7.2 (Windows x64)");
    println("Real process scanner with AOB signatures and pointer maps. Type 'help'.");
    char line[2048];char* tok[128];
    for(;;){
        print("cw> ");if(!read_line(line,sizeof(line)))break;int c=tokenize(line,tok,128);if(c==0)continue;
        if(streq(tok[0],"quit")||streq(tok[0],"exit"))break;
        else if(streq(tok[0],"help"))show_help();
        else if(streq(tok[0],"version"))println("Cheat Wizard v1.7.2 (Windows x64)");
        else if(streq(tok[0],"processes")||streq(tok[0],"ps"))cmd_processes();
        else if(streq(tok[0],"attach")&&c>=2)cmd_attach(tok[1]);
        else if(streq(tok[0],"attach-name")&&c>=2)cmd_attach_name(tok[1]);
        else if(streq(tok[0],"detach"))cmd_detach();
        else if(streq(tok[0],"clear"))cmd_clear();
        else if(streq(tok[0],"scan")&&c>=3){if(streq(tok[1],"all")){if(streq(tok[2],"unknown")||streq(tok[2],"?"))scan_all_unknown();else scan_all_exact(tok[2]);}else{ValueType t=parse_type(tok[1]);u8 raw[8];if(t==ValueType::Invalid)println("Invalid type.");else if(streq(tok[2],"unknown")||streq(tok[2],"?"))scan_unknown(t);else if(!encode_value(t,tok[2],raw))println("Invalid value.");else scan_exact(t,raw);}}
        else if(streq(tok[0],"next")&&c>=2){if(streq(tok[1],"changed"))next_scan_text(NextMode::Changed,nullptr,false);else if(streq(tok[1],"unchanged"))next_scan_text(NextMode::Unchanged,nullptr,false);else if(streq(tok[1],"increased"))next_scan_text(NextMode::Increased,nullptr,false);else if(streq(tok[1],"decreased"))next_scan_text(NextMode::Decreased,nullptr,false);else if((streq(tok[1],"exact")||streq(tok[1],"bigger")||streq(tok[1],"smaller"))&&c>=3)next_scan_text(streq(tok[1],"exact")?NextMode::Exact:streq(tok[1],"bigger")?NextMode::Bigger:NextMode::Smaller,tok[2],true);else next_scan_text(NextMode::Exact,tok[1],true);}
        else if(streq(tok[0],"results"))cmd_results(c>=2?tok[1]:nullptr);
        else if((streq(tok[0],"scan-save")||streq(tok[0],"ssave"))&&c>=2)cmd_scan_save(tok[1]);
        else if((streq(tok[0],"scan-load")||streq(tok[0],"sload"))&&c>=2){bool force=c>=3&&streq(tok[2],"force");if(c>3||(c==3&&!force))println("Usage: scan-load <file.cwscan> [force]");else cmd_scan_load(tok[1],force);}
        else if(streq(tok[0],"inspect")&&c>=2)cmd_inspect(tok[1]);
        else if(streq(tok[0],"read-at")&&c>=3)cmd_read_at(tok[1],tok[2]);
        else if(streq(tok[0],"write-at")&&c>=4)cmd_write_at(tok[1],tok[2],tok[3]);
        else if(streq(tok[0],"freeze-at")&&c>=4)cmd_freeze_at(tok[1],tok[2],tok[3]);
        else if(streq(tok[0],"set")&&c>=3)cmd_set(tok[1],tok[2]);
        else if(streq(tok[0],"freeze")&&c>=3)cmd_freeze(tok[1],tok[2]);
        else if(streq(tok[0],"freezes"))cmd_freezes();
        else if(streq(tok[0],"unfreeze")&&c>=2)cmd_unfreeze(tok[1]);
        else if(streq(tok[0],"modules"))cmd_modules();
        else if(streq(tok[0],"aob")&&c>=2)scan_aob_tokens(tok,1,c,false,nullptr);
        else if(streq(tok[0],"aob-code")&&c>=2)scan_aob_tokens(tok,1,c,true,nullptr);
        else if(streq(tok[0],"aob-module")&&c>=3)scan_aob_tokens(tok,2,c,false,tok[1]);
        else if(streq(tok[0],"aob-module-code")&&c>=3)scan_aob_tokens(tok,2,c,true,tok[1]);
        else if(streq(tok[0],"aob-results"))cmd_aob_results(c>=2?tok[1]:nullptr);
        else if((streq(tok[0],"aob-resolve")||streq(tok[0],"aresolve"))&&c>=4)cmd_aob_resolve(tok[1],tok[2],tok[3]);
        else if((streq(tok[0],"aob-decode")||streq(tok[0],"adecode"))&&c>=2)cmd_aob_decode(tok[1]);
        else if(streq(tok[0],"aob-save")&&c>=2)cmd_aob_save(tok[1]);
        else if(streq(tok[0],"aob-load")&&c>=2)cmd_aob_load(tok[1]);
        else if(streq(tok[0],"aob-rerun")&&c>=2)cmd_aob_rerun(tok[1]);
        else if(streq(tok[0],"aob-clear")){clear_aob();println("AOB matches cleared.");}
        else if(streq(tok[0],"pointer-settings")||streq(tok[0],"psettings"))cmd_pointer_settings(c>=2?tok[1]:nullptr,c>=3?tok[2]:nullptr);
        else if((streq(tok[0],"pointer-scan")||streq(tok[0],"pscan"))&&c>=2)cmd_pointer_scan(tok[1],c>=3?tok[2]:nullptr,c>=4?tok[3]:nullptr,c>=5?tok[4]:nullptr,c>=6?tok[5]:nullptr);
        else if(streq(tok[0],"pointer-results")||streq(tok[0],"pointers"))cmd_pointer_results(c>=2?tok[1]:nullptr);
        else if((streq(tok[0],"pointer-resolve")||streq(tok[0],"presolve"))&&c>=2)cmd_pointer_resolve(tok[1]);
        else if((streq(tok[0],"pointer-rescan")||streq(tok[0],"prescan"))&&c>=2)cmd_pointer_rescan(tok[1]);
        else if((streq(tok[0],"pointer-save")||streq(tok[0],"psave"))&&c>=2)cmd_pointer_save(tok[1]);
        else if((streq(tok[0],"pointer-load")||streq(tok[0],"pload"))&&c>=2)cmd_pointer_load(tok[1]);
        else if(streq(tok[0],"profile-load")&&c>=2)cmd_profile_load(tok[1]);
        else if(streq(tok[0],"profile-read"))cmd_profile_read();
        else if(streq(tok[0],"profile-write")&&c>=2)cmd_profile_write(tok[1]);
        else if(streq(tok[0],"profile-freeze")&&c>=2)cmd_profile_freeze(tok[1]);
        else if((streq(tok[0],"pmap-capture")||streq(tok[0],"pmcapture"))&&c>=3)cmd_pmap_capture(tok[1],tok[2],c>=4?tok[3]:nullptr);
        else if((streq(tok[0],"pmap-load")||streq(tok[0],"pmload"))&&c>=2)cmd_pmap_load(tok[1]);
        else if(streq(tok[0],"pmap-list")||streq(tok[0],"pmlist"))cmd_pmap_list();
        else if(streq(tok[0],"pmap-compare")||streq(tok[0],"pmcompare"))cmd_pmap_compare(c>=2?tok[1]:nullptr,c>=3?tok[2]:nullptr,c>=4?tok[3]:nullptr,c>=5?tok[4]:nullptr);
        else if(streq(tok[0],"pmap-compare-files")||streq(tok[0],"pmcompare-files"))cmd_pmap_compare_files(tok+1,c-1);
        else if(streq(tok[0],"pmap-clear")||streq(tok[0],"pmclear"))cmd_pmap_clear();
        else if(streq(tok[0],"pointer-clear")||streq(tok[0],"pclear"))cmd_pointer_clear();
        else if(streq(tok[0],"settings")&&c>=3&&streq(tok[1],"alignment")){if(streq(tok[2],"byte")){g_alignmentByte=true;println("Alignment set to byte.");}else if(streq(tok[2],"natural")){g_alignmentByte=false;println("Alignment set to natural.");}else println("Use natural or byte.");}
        else if(streq(tok[0],"status"))cmd_status();
        else println("Unknown/incomplete command. Type 'help'.");
    }
    close_target();free_pointer_maps();if(g_results)HeapFree(g_heap,0,g_results);if(g_aobResults)HeapFree(g_heap,0,g_aobResults);if(g_pointerIndex)HeapFree(g_heap,0,g_pointerIndex);if(g_pointerChains)HeapFree(g_heap,0,g_pointerChains);ExitProcess(0);
}
