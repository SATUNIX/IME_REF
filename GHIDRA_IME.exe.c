typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef unsigned short    wchar16;
typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct tagMSG tagMSG, *PtagMSG;

typedef struct tagMSG MSG;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef ulong DWORD;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

typedef long LONG;

struct tagPOINT {
    LONG x;
    LONG y;
};

struct tagMSG {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
};

struct HWND__ {
    int unused;
};

typedef LONG_PTR LRESULT;

typedef LRESULT (* WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct tagMSG * LPMSG;

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef int BOOL;

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef BOOL (* LOCALE_ENUMPROCW)(LPWSTR);

typedef struct _cpinfo * LPCPINFO;

typedef DWORD LCTYPE;

typedef DWORD CALID;

typedef BOOL (* CALINFO_ENUMPROCW)(LPWSTR);

typedef DWORD CALTYPE;

typedef struct _SYSTEM_INFO _SYSTEM_INFO, *P_SYSTEM_INFO;

typedef struct _SYSTEM_INFO * LPSYSTEM_INFO;

typedef union _union_530 _union_530, *P_union_530;

typedef void * LPVOID;

typedef ulong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef ushort WORD;

typedef struct _struct_531 _struct_531, *P_struct_531;

struct _struct_531 {
    WORD wProcessorArchitecture;
    WORD wReserved;
};

union _union_530 {
    DWORD dwOemId;
    struct _struct_531 s;
};

struct _SYSTEM_INFO {
    union _union_530 u;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef union _union_518 _union_518, *P_union_518;

typedef void * HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void * PVOID;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef BYTE * LPBYTE;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _STARTUPINFOW * LPSTARTUPINFOW;

typedef struct _WIN32_FIND_DATAW _WIN32_FIND_DATAW, *P_WIN32_FIND_DATAW;

typedef struct _WIN32_FIND_DATAW * LPWIN32_FIND_DATAW;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[260];
    WCHAR cAlternateFileName[14];
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _PROCESS_INFORMATION * LPPROCESS_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _SYSTEMTIME * LPSYSTEMTIME;

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

typedef ULONG_PTR SIZE_T;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION _SYSTEM_LOGICAL_PROCESSOR_INFORMATION, *P_SYSTEM_LOGICAL_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION * PSYSTEM_LOGICAL_PROCESSOR_INFORMATION;

typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP {
    RelationProcessorCore=0,
    RelationNumaNode=1,
    RelationCache=2,
    RelationProcessorPackage=3,
    RelationGroup=4,
    RelationAll=65535
} _LOGICAL_PROCESSOR_RELATIONSHIP;

typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP LOGICAL_PROCESSOR_RELATIONSHIP;

typedef union _union_148 _union_148, *P_union_148;

typedef struct _struct_149 _struct_149, *P_struct_149;

typedef struct _struct_150 _struct_150, *P_struct_150;

typedef struct _CACHE_DESCRIPTOR _CACHE_DESCRIPTOR, *P_CACHE_DESCRIPTOR;

typedef struct _CACHE_DESCRIPTOR CACHE_DESCRIPTOR;

typedef double ULONGLONG;

typedef enum _PROCESSOR_CACHE_TYPE {
    CacheUnified=0,
    CacheInstruction=1,
    CacheData=2,
    CacheTrace=3
} _PROCESSOR_CACHE_TYPE;

typedef enum _PROCESSOR_CACHE_TYPE PROCESSOR_CACHE_TYPE;

struct _struct_149 {
    BYTE Flags;
};

struct _struct_150 {
    DWORD NodeNumber;
};

struct _CACHE_DESCRIPTOR {
    BYTE Level;
    BYTE Associativity;
    WORD LineSize;
    DWORD Size;
    PROCESSOR_CACHE_TYPE Type;
};

union _union_148 {
    struct _struct_149 ProcessorCore;
    struct _struct_150 NumaNode;
    CACHE_DESCRIPTOR Cache;
    ULONGLONG Reserved[2];
};

struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
    ULONG_PTR ProcessorMask;
    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
    union _union_148 u;
};

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef struct _OSVERSIONINFOEXW _OSVERSIONINFOEXW, *P_OSVERSIONINFOEXW;

struct _OSVERSIONINFOEXW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
    WORD wServicePackMajor;
    WORD wServicePackMinor;
    WORD wSuiteMask;
    BYTE wProductType;
    BYTE wReserved;
};

typedef char CHAR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _OSVERSIONINFOEXW * LPOSVERSIONINFOEXW;

typedef struct _TOKEN_PRIVILEGES _TOKEN_PRIVILEGES, *P_TOKEN_PRIVILEGES;

typedef struct _LUID_AND_ATTRIBUTES _LUID_AND_ATTRIBUTES, *P_LUID_AND_ATTRIBUTES;

typedef struct _LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES;

typedef struct _LUID _LUID, *P_LUID;

typedef struct _LUID LUID;

struct _LUID {
    DWORD LowPart;
    LONG HighPart;
};

struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    DWORD Attributes;
};

struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
};

typedef WCHAR * PCNZWCH;

typedef struct _SID_IDENTIFIER_AUTHORITY _SID_IDENTIFIER_AUTHORITY, *P_SID_IDENTIFIER_AUTHORITY;

typedef struct _SID_IDENTIFIER_AUTHORITY * PSID_IDENTIFIER_AUTHORITY;

struct _SID_IDENTIFIER_AUTHORITY {
    BYTE Value[6];
};

typedef WCHAR * LPCWSTR;

typedef struct _LUID * PLUID;

typedef struct _OSVERSIONINFOW _OSVERSIONINFOW, *P_OSVERSIONINFOW;

typedef struct _OSVERSIONINFOW * LPOSVERSIONINFOW;

struct _OSVERSIONINFOW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
};

typedef CHAR * LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION * PMEMORY_BASIC_INFORMATION;

typedef ULONGLONG DWORDLONG;

typedef LONG * PLONG;

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser=1,
    TokenGroups=2,
    TokenPrivileges=3,
    TokenOwner=4,
    TokenPrimaryGroup=5,
    TokenDefaultDacl=6,
    TokenSource=7,
    TokenType=8,
    TokenImpersonationLevel=9,
    TokenStatistics=10,
    TokenRestrictedSids=11,
    TokenSessionId=12,
    TokenGroupsAndPrivileges=13,
    TokenSessionReference=14,
    TokenSandBoxInert=15,
    TokenAuditPolicy=16,
    TokenOrigin=17,
    TokenElevationType=18,
    TokenLinkedToken=19,
    TokenElevation=20,
    TokenHasRestrictions=21,
    TokenAccessInformation=22,
    TokenVirtualizationAllowed=23,
    TokenVirtualizationEnabled=24,
    TokenIntegrityLevel=25,
    TokenUIAccess=26,
    TokenMandatoryPolicy=27,
    TokenLogonSid=28,
    MaxTokenInfoClass=29
} _TOKEN_INFORMATION_CLASS;

typedef CHAR * LPSTR;

typedef PVOID PSID;

typedef CONTEXT * PCONTEXT;

typedef WORD LANGID;

typedef struct _TOKEN_PRIVILEGES * PTOKEN_PRIVILEGES;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

typedef enum _TOKEN_INFORMATION_CLASS TOKEN_INFORMATION_CLASS;

typedef HANDLE * PHANDLE;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[192]; // Actual DOS program
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef WCHAR OLECHAR;

typedef OLECHAR * BSTR;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef DWORD * PDWORD;

typedef uint * PUINT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ * HMENU;

struct HMENU__ {
    int unused;
};

typedef int (* FARPROC)(void);

typedef int INT;

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef HANDLE HGLOBAL;

typedef BOOL * LPBOOL;

typedef void * LPCVOID;

typedef struct HRSRC__ * HRSRC;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

struct IMAGE_THUNK_DATA32 {
    dword StartAddressOfRawData;
    dword EndAddressOfRawData;
    dword AddressOfIndex;
    dword AddressOfCallBacks;
    dword SizeOfZeroFill;
    dword Characteristics;
};

typedef struct IMAGE_IMPORT_BY_NAME_10 IMAGE_IMPORT_BY_NAME_10, *PIMAGE_IMPORT_BY_NAME_10;

struct IMAGE_IMPORT_BY_NAME_10 {
    word Hint;
    char Name[10];
};

typedef struct IMAGE_IMPORT_BY_NAME_31 IMAGE_IMPORT_BY_NAME_31, *PIMAGE_IMPORT_BY_NAME_31;

struct IMAGE_IMPORT_BY_NAME_31 {
    word Hint;
    char Name[31];
};

typedef struct IMAGE_IMPORT_BY_NAME_12 IMAGE_IMPORT_BY_NAME_12, *PIMAGE_IMPORT_BY_NAME_12;

struct IMAGE_IMPORT_BY_NAME_12 {
    word Hint;
    char Name[12];
};

typedef struct IMAGE_IMPORT_BY_NAME_11 IMAGE_IMPORT_BY_NAME_11, *PIMAGE_IMPORT_BY_NAME_11;

struct IMAGE_IMPORT_BY_NAME_11 {
    word Hint;
    char Name[11];
};

typedef struct IMAGE_IMPORT_BY_NAME_14 IMAGE_IMPORT_BY_NAME_14, *PIMAGE_IMPORT_BY_NAME_14;

struct IMAGE_IMPORT_BY_NAME_14 {
    word Hint;
    char Name[14];
};

typedef struct IMAGE_IMPORT_BY_NAME_13 IMAGE_IMPORT_BY_NAME_13, *PIMAGE_IMPORT_BY_NAME_13;

struct IMAGE_IMPORT_BY_NAME_13 {
    word Hint;
    char Name[13];
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_IMPORT_BY_NAME_16 IMAGE_IMPORT_BY_NAME_16, *PIMAGE_IMPORT_BY_NAME_16;

struct IMAGE_IMPORT_BY_NAME_16 {
    word Hint;
    char Name[16];
};

typedef struct IMAGE_IMPORT_BY_NAME_15 IMAGE_IMPORT_BY_NAME_15, *PIMAGE_IMPORT_BY_NAME_15;

struct IMAGE_IMPORT_BY_NAME_15 {
    word Hint;
    char Name[15];
};

typedef struct IMAGE_IMPORT_BY_NAME_18 IMAGE_IMPORT_BY_NAME_18, *PIMAGE_IMPORT_BY_NAME_18;

struct IMAGE_IMPORT_BY_NAME_18 {
    word Hint;
    char Name[18];
};

typedef struct IMAGE_IMPORT_BY_NAME_9 IMAGE_IMPORT_BY_NAME_9, *PIMAGE_IMPORT_BY_NAME_9;

struct IMAGE_IMPORT_BY_NAME_9 {
    word Hint;
    char Name[9];
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct IMAGE_IMPORT_BY_NAME_17 IMAGE_IMPORT_BY_NAME_17, *PIMAGE_IMPORT_BY_NAME_17;

struct IMAGE_IMPORT_BY_NAME_17 {
    word Hint;
    char Name[17];
};

typedef struct IMAGE_IMPORT_BY_NAME_8 IMAGE_IMPORT_BY_NAME_8, *PIMAGE_IMPORT_BY_NAME_8;

struct IMAGE_IMPORT_BY_NAME_8 {
    word Hint;
    char Name[8];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_16 IMAGE_RESOURCE_DIR_STRING_U_16, *PIMAGE_RESOURCE_DIR_STRING_U_16;

struct IMAGE_RESOURCE_DIR_STRING_U_16 {
    word Length;
    wchar16 NameString[8];
};

typedef struct IMAGE_IMPORT_BY_NAME_19 IMAGE_IMPORT_BY_NAME_19, *PIMAGE_IMPORT_BY_NAME_19;

struct IMAGE_IMPORT_BY_NAME_19 {
    word Hint;
    char Name[19];
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_12 IMAGE_RESOURCE_DIR_STRING_U_12, *PIMAGE_RESOURCE_DIR_STRING_U_12;

struct IMAGE_RESOURCE_DIR_STRING_U_12 {
    word Length;
    wchar16 NameString[6];
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct ImgDelayDescr ImgDelayDescr, *PImgDelayDescr;

struct ImgDelayDescr {
    dword grAttrs;
    ImageBaseOffset32 szName;
    ImageBaseOffset32 phmod;
    ImageBaseOffset32 pIAT;
    ImageBaseOffset32 pINT;
    ImageBaseOffset32 pBoundIAT;
    ImageBaseOffset32 pUnloadIAT;
    dword dwTimeStamp;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_IMPORT_BY_NAME_21 IMAGE_IMPORT_BY_NAME_21, *PIMAGE_IMPORT_BY_NAME_21;

struct IMAGE_IMPORT_BY_NAME_21 {
    word Hint;
    char Name[21];
};

typedef struct IMAGE_IMPORT_BY_NAME_20 IMAGE_IMPORT_BY_NAME_20, *PIMAGE_IMPORT_BY_NAME_20;

struct IMAGE_IMPORT_BY_NAME_20 {
    word Hint;
    char Name[20];
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef struct IMAGE_IMPORT_BY_NAME_22 IMAGE_IMPORT_BY_NAME_22, *PIMAGE_IMPORT_BY_NAME_22;

struct IMAGE_IMPORT_BY_NAME_22 {
    word Hint;
    char Name[22];
};

typedef struct IMAGE_IMPORT_BY_NAME_24 IMAGE_IMPORT_BY_NAME_24, *PIMAGE_IMPORT_BY_NAME_24;

struct IMAGE_IMPORT_BY_NAME_24 {
    word Hint;
    char Name[24];
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_IMPORT_BY_NAME_26 IMAGE_IMPORT_BY_NAME_26, *PIMAGE_IMPORT_BY_NAME_26;

struct IMAGE_IMPORT_BY_NAME_26 {
    word Hint;
    char Name[26];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_22 IMAGE_RESOURCE_DIR_STRING_U_22, *PIMAGE_RESOURCE_DIR_STRING_U_22;

struct IMAGE_RESOURCE_DIR_STRING_U_22 {
    word Length;
    wchar16 NameString[11];
};

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef char * va_list;




BOOL __stdcall CloseHandle(HANDLE hObject)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402748. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CloseHandle(hObject);
  return BVar1;
}



HANDLE __stdcall GetStdHandle(DWORD nStdHandle)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402750. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GetStdHandle(nStdHandle);
  return pvVar1;
}



BOOL __stdcall
WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,
         LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402758. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = WriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
  return BVar1;
}



BOOL __stdcall FindClose(HANDLE hFindFile)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402760. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FindClose(hFindFile);
  return BVar1;
}



HANDLE __stdcall FindFirstFileW(LPCWSTR lpFileName,LPWIN32_FIND_DATAW lpFindFileData)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402768. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = FindFirstFileW(lpFileName,lpFindFileData);
  return pvVar1;
}



void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x00402770. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeCriticalSection(lpCriticalSection);
  return;
}



void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x00402778. Too many branches
                    // WARNING: Treating indirect jump as call
  DeleteCriticalSection(lpCriticalSection);
  return;
}



DWORD __stdcall GetCurrentThreadId(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402780. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetCurrentThreadId();
  return DVar1;
}



BOOL __stdcall SwitchToThread(void)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402788. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SwitchToThread();
  return BVar1;
}



void __stdcall ExitProcess(UINT uExitCode)

{
                    // WARNING: Could not recover jumptable at 0x00402790. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  ExitProcess(uExitCode);
  return;
}



LONG __stdcall UnhandledExceptionFilter(_EXCEPTION_POINTERS *ExceptionInfo)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027a8. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = UnhandledExceptionFilter(ExceptionInfo);
  return LVar1;
}



DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027b0. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetLastError();
  return DVar1;
}



BOOL __stdcall FreeLibrary(HMODULE hLibModule)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027b8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FreeLibrary(hLibModule);
  return BVar1;
}



int __stdcall LoadStringW(HINSTANCE hInstance,UINT uID,LPWSTR lpBuffer,int cchBufferMax)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027c0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = LoadStringW(hInstance,uID,lpBuffer,cchBufferMax);
  return iVar1;
}



LPWSTR __stdcall GetCommandLineW(void)

{
  LPWSTR pWVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027c8. Too many branches
                    // WARNING: Treating indirect jump as call
  pWVar1 = GetCommandLineW();
  return pWVar1;
}



DWORD __stdcall GetModuleFileNameW(HMODULE hModule,LPWSTR lpFilename,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027d0. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetModuleFileNameW(hModule,lpFilename,nSize);
  return DVar1;
}



HMODULE __stdcall GetModuleHandleW(LPCWSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027d8. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetModuleHandleW(lpModuleName);
  return pHVar1;
}



FARPROC __stdcall GetProcAddress(HMODULE hModule,LPCSTR lpProcName)

{
  FARPROC pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027e0. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = GetProcAddress(hModule,lpProcName);
  return pFVar1;
}



void __stdcall GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)

{
                    // WARNING: Could not recover jumptable at 0x004027e8. Too many branches
                    // WARNING: Treating indirect jump as call
  GetStartupInfoW(lpStartupInfo);
  return;
}



HMODULE __stdcall LoadLibraryExW(LPCWSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027f0. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = LoadLibraryExW(lpLibFileName,hFile,dwFlags);
  return pHVar1;
}



UINT __stdcall GetACP(void)

{
  UINT UVar1;
  
                    // WARNING: Could not recover jumptable at 0x004027f8. Too many branches
                    // WARNING: Treating indirect jump as call
  UVar1 = GetACP();
  return UVar1;
}



int __stdcall
MultiByteToWideChar(UINT CodePage,DWORD dwFlags,LPCSTR lpMultiByteStr,int cbMultiByte,
                   LPWSTR lpWideCharStr,int cchWideChar)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402800. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MultiByteToWideChar(CodePage,dwFlags,lpMultiByteStr,cbMultiByte,lpWideCharStr,cchWideChar)
  ;
  return iVar1;
}



int __stdcall
WideCharToMultiByte(UINT CodePage,DWORD dwFlags,LPCWSTR lpWideCharStr,int cchWideChar,
                   LPSTR lpMultiByteStr,int cbMultiByte,LPCSTR lpDefaultChar,
                   LPBOOL lpUsedDefaultChar)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402808. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = WideCharToMultiByte(CodePage,dwFlags,lpWideCharStr,cchWideChar,lpMultiByteStr,cbMultiByte,
                              lpDefaultChar,lpUsedDefaultChar);
  return iVar1;
}



BOOL __stdcall SetThreadLocale(LCID Locale)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402810. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetThreadLocale(Locale);
  return BVar1;
}



LPWSTR __stdcall CharNextW(LPCWSTR lpsz)

{
  LPWSTR pWVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402818. Too many branches
                    // WARNING: Treating indirect jump as call
  pWVar1 = CharNextW(lpsz);
  return pWVar1;
}



int __stdcall
CompareStringW(LCID Locale,DWORD dwCmpFlags,PCNZWCH lpString1,int cchCount1,PCNZWCH lpString2,
              int cchCount2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402820. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = CompareStringW(Locale,dwCmpFlags,lpString1,cchCount1,lpString2,cchCount2);
  return iVar1;
}



undefined4
FUN_00402828(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined4 param_6)

{
  undefined4 in_stack_00000000;
  
  thunk_FUN_0040b40c(param_1,param_2,param_3,&ImgDelayDescr_00431020,in_stack_00000000);
  LOCK();
  UNLOCK();
  return param_6;
}



void DelayLoad_MessageBoxA(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_00402828((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



int __stdcall MessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402848. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MessageBoxA(hWnd,lpText,lpCaption,uType);
  return iVar1;
}



LSTATUS __stdcall RegCloseKey(HKEY hKey)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402850. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegCloseKey(hKey);
  return LVar1;
}



LSTATUS __stdcall
RegOpenKeyExW(HKEY hKey,LPCWSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402858. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegOpenKeyExW(hKey,lpSubKey,ulOptions,samDesired,phkResult);
  return LVar1;
}



LSTATUS __stdcall
RegQueryValueExW(HKEY hKey,LPCWSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,
                LPDWORD lpcbData)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402860. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegQueryValueExW(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
  return LVar1;
}



DWORD __stdcall GetVersion(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402868. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetVersion();
  return DVar1;
}



void __stdcall GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)

{
                    // WARNING: Could not recover jumptable at 0x00402870. Too many branches
                    // WARNING: Treating indirect jump as call
  GetSystemInfo(lpSystemInfo);
  return;
}



DWORD __stdcall GetTickCount(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402878. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetTickCount();
  return DVar1;
}



BOOL __stdcall QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402880. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = QueryPerformanceCounter(lpPerformanceCount);
  return BVar1;
}



SIZE_T __stdcall VirtualQuery(LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength)

{
  SIZE_T SVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402888. Too many branches
                    // WARNING: Treating indirect jump as call
  SVar1 = VirtualQuery(lpAddress,lpBuffer,dwLength);
  return SVar1;
}



BSTR __stdcall SysAllocStringLen(OLECHAR *strIn,UINT ui)

{
  BSTR pOVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402890. Too many branches
                    // WARNING: Treating indirect jump as call
  pOVar1 = SysAllocStringLen(strIn,ui);
  return pOVar1;
}



INT __stdcall SysReAllocStringLen(BSTR *pbstr,OLECHAR *psz,uint len)

{
  INT IVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402898. Too many branches
                    // WARNING: Treating indirect jump as call
  IVar1 = SysReAllocStringLen(pbstr,psz,len);
  return IVar1;
}



void __stdcall SysFreeString(BSTR bstrString)

{
                    // WARNING: Could not recover jumptable at 0x004028a0. Too many branches
                    // WARNING: Treating indirect jump as call
  SysFreeString(bstrString);
  return;
}



int __stdcall lstrlenW(LPCWSTR lpString)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004028a8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = lstrlenW(lpString);
  return iVar1;
}



undefined4
FUN_004028b0(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined4 param_6)

{
  undefined4 in_stack_00000000;
  
  thunk_FUN_0040b40c(param_1,param_2,param_3,&ImgDelayDescr_00431000,in_stack_00000000);
  LOCK();
  UNLOCK();
  return param_6;
}



void DelayLoad_GetLogicalProcessorInformation(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_004028b0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
GetLogicalProcessorInformation(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer,PDWORD ReturnedLength)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004028d0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetLogicalProcessorInformation(Buffer,ReturnedLength);
  return BVar1;
}



WORD FUN_004028d8(void)

{
  WORD WVar1;
  undefined local_48 [48];
  WORD local_18;
  
  local_48._0_4_ = 0x44;
  GetStartupInfoW((LPSTARTUPINFOW)local_48);
  WVar1 = 10;
  if ((local_48[44] & 1) != 0) {
    WVar1 = local_18;
  }
  return WVar1;
}



LPVOID __stdcall VirtualAlloc(LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00402904. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = VirtualAlloc(lpAddress,dwSize,flAllocationType,flProtect);
  return pvVar1;
}



BOOL __stdcall VirtualFree(LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040290c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = VirtualFree(lpAddress,dwSize,dwFreeType);
  return BVar1;
}



void __stdcall Sleep(DWORD dwMilliseconds)

{
                    // WARNING: Could not recover jumptable at 0x00402914. Too many branches
                    // WARNING: Treating indirect jump as call
  Sleep(dwMilliseconds);
  return;
}



BOOL __stdcall
WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,
         LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040291c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = WriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
  return BVar1;
}



void FUN_00402b3c(int param_1,int param_2,int param_3)

{
  longlong lVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar3 = param_3 + -0xc;
  iVar2 = param_1 + iVar3;
  iVar5 = param_2 + iVar3;
  iVar4 = -iVar3;
  if (0 < iVar3) {
    do {
      lVar1 = *(longlong *)(iVar4 + iVar2);
      *(longlong *)(iVar4 + 8 + iVar5) = (longlong)ROUND((float10)*(longlong *)(iVar4 + 8 + iVar2));
      *(longlong *)(iVar4 + iVar5) = (longlong)ROUND((float10)lVar1);
      iVar4 = iVar4 + 0x10;
    } while (iVar4 < 0);
  }
  *(longlong *)(iVar4 + iVar5) = (longlong)ROUND((float10)*(longlong *)(iVar4 + iVar2));
  *(undefined4 *)(iVar4 + 8 + iVar5) = *(undefined4 *)(iVar4 + 8 + iVar2);
  return;
}



void FUN_00402b6c(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_3 + -4;
  iVar2 = -iVar1;
  do {
    *(longlong *)(iVar2 + param_2 + iVar1) =
         (longlong)ROUND((float10)*(longlong *)(iVar2 + param_1 + iVar1));
    iVar2 = iVar2 + 8;
  } while (iVar2 < 0);
  *(undefined4 *)(iVar2 + param_2 + iVar1) = *(undefined4 *)(iVar2 + param_1 + iVar1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00402b88(int **param_1)

{
  uint *puVar1;
  int *piVar2;
  int *piVar3;
  byte bVar4;
  uint uVar5;
  
  piVar2 = param_1[1];
  piVar3 = *param_1;
  *piVar2 = (int)piVar3;
  piVar3[1] = (int)piVar2;
  if (piVar2 == piVar3) {
    uVar5 = (uint)(piVar2 + -0x10a6dd) >> 8 & 0xff;
    bVar4 = (byte)((uint)(piVar2 + -0x10a6dd) >> 3) & 0x1f;
    puVar1 = (uint *)(&DAT_00429af4 + uVar5 * 4);
    *puVar1 = *puVar1 & (-2 << bVar4 | 0xfffffffeU >> 0x20 - bVar4);
    if (*puVar1 == 0) {
      bVar4 = (byte)uVar5 & 0x1f;
      _DAT_00429af0 = _DAT_00429af0 & (-2 << bVar4 | 0xfffffffeU >> 0x20 - bVar4);
      return;
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00402bc8(undefined4 *param_1,int param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = param_2 - 0xb30U >> 8;
  iVar3 = (uVar2 - 0x3ff & -(uint)(uVar2 < 0x3ff)) + 0x3ff;
  puVar1 = (undefined4 *)(&DAT_00429b78)[iVar3 * 2];
  *param_1 = &DAT_00429b74 + iVar3 * 2;
  param_1[1] = puVar1;
  *puVar1 = param_1;
  (&DAT_00429b78)[iVar3 * 2] = param_1;
  if (puVar1 != &DAT_00429b74 + iVar3 * 2) {
    return;
  }
  uVar2 = (uint)(iVar3 * 8) >> 8 & 0xff;
  *(uint *)(&DAT_00429af4 + uVar2 * 4) =
       *(uint *)(&DAT_00429af4 + uVar2 * 4) | 1 << ((byte)iVar3 & 0x1f);
  _DAT_00429af0 = _DAT_00429af0 | 1 << ((byte)uVar2 & 0x1f);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00402c28(void)

{
  undefined4 *puVar1;
  int **ppiVar2;
  undefined4 *puVar3;
  uint uVar4;
  int iVar5;
  
  ppiVar2 = DAT_00429ae8;
  if (DAT_00429aec == 0) {
    return;
  }
  if ((*(byte *)(DAT_00429ae8 + -1) & 1) == 0) {
    DAT_00429ae8[-1] = (int *)((uint)DAT_00429ae8[-1] | 8);
    puVar3 = (undefined4 *)((int)ppiVar2 - DAT_00429aec);
    uVar4 = DAT_00429aec;
  }
  else {
    uVar4 = (uint)DAT_00429ae8[-1] & 0xfffffff0;
    if (0xb2f < uVar4) {
      FUN_00402b88(DAT_00429ae8);
      uVar4 = (uint)DAT_00429ae8[-1] & 0xfffffff0;
    }
    puVar3 = (undefined4 *)((int)DAT_00429ae8 - DAT_00429aec);
    uVar4 = uVar4 + DAT_00429aec;
  }
  puVar3[-1] = uVar4 + 3;
  *(uint *)((uVar4 - 8) + (int)puVar3) = uVar4;
  if (uVar4 < 0xb30) {
    return;
  }
  uVar4 = uVar4 - 0xb30 >> 8;
  iVar5 = (uVar4 - 0x3ff & -(uint)(uVar4 < 0x3ff)) + 0x3ff;
  puVar1 = (undefined4 *)(&DAT_00429b78)[iVar5 * 2];
  *puVar3 = &DAT_00429b74 + iVar5 * 2;
  puVar3[1] = puVar1;
  *puVar1 = puVar3;
  (&DAT_00429b78)[iVar5 * 2] = puVar3;
  if (puVar1 != &DAT_00429b74 + iVar5 * 2) {
    return;
  }
  uVar4 = (uint)(iVar5 * 8) >> 8 & 0xff;
  *(uint *)(&DAT_00429af4 + uVar4 * 4) =
       *(uint *)(&DAT_00429af4 + uVar4 * 4) | 1 << ((byte)iVar5 & 0x1f);
  _DAT_00429af0 = _DAT_00429af0 | 1 << ((byte)uVar4 & 0x1f);
  return;
}



int FUN_00402c94(uint param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  FUN_00402c28();
  puVar3 = (undefined4 *)VirtualAlloc((LPVOID)0x0,0x13fff0,0x1000,4);
  puVar1 = DAT_00429ad8;
  if (puVar3 != (undefined4 *)0x0) {
    *puVar3 = &DAT_00429ad4;
    puVar2 = puVar3;
    puVar3[1] = DAT_00429ad8;
    DAT_00429ad8 = puVar2;
    *puVar1 = puVar3;
    puVar3[0x4fffb] = 2;
    DAT_00429aec = 0x13ffe0 - param_1;
    DAT_00429ae8 = (int)puVar3 + (0x13fff0 - param_1);
    iVar4 = DAT_00429ae8;
    *(uint *)(DAT_00429ae8 + -4) = param_1 | 2;
    return iVar4;
  }
  DAT_00429aec = 0;
  return 0;
}



void FUN_00402d10(void)

{
  bool bVar1;
  
  if (DAT_00429055 != '\0') {
    while( true ) {
      LOCK();
      bVar1 = DAT_0042bb74 == 0;
      DAT_0042bb74 = DAT_0042bb74 ^ bVar1 * (DAT_0042bb74 ^ 1);
      UNLOCK();
      if ((byte)(!bVar1 * DAT_0042bb74) == '\0') break;
      if (DAT_00429985 == '\0') {
        Sleep(0);
        LOCK();
        bVar1 = DAT_0042bb74 == 0;
        DAT_0042bb74 = DAT_0042bb74 ^ bVar1 * (DAT_0042bb74 ^ 1);
        UNLOCK();
        if ((byte)(!bVar1 * DAT_0042bb74) == '\0') {
          return;
        }
        Sleep(10);
      }
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte ** FUN_00402fb0(byte *param_1)

{
  int *piVar1;
  byte *pbVar2;
  uint *puVar3;
  ushort uVar4;
  byte *pbVar5;
  undefined4 *puVar6;
  byte bVar7;
  byte **ppbVar8;
  byte **ppbVar9;
  byte **ppbVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  byte *pbVar16;
  uint uVar17;
  uint uVar18;
  bool bVar19;
  
  if ((byte *)0xa2c < param_1) {
    if ((byte *)0x40a2c < param_1) {
      if ((int)param_1 < 0) {
        return (byte **)0x0;
      }
      ppbVar10 = (byte **)VirtualAlloc((LPVOID)0x0,(uint)(param_1 + 0x10013) & 0xffff0000,0x101000,4
                                      );
      if (ppbVar10 != (byte **)0x0) {
        ppbVar10[2] = param_1;
        ppbVar10[3] = (byte *)((uint)(param_1 + 0x10013) & 0xffff0000 | 4);
        FUN_00402d10();
        ppbVar8 = DAT_0042bb7c;
        *ppbVar10 = (byte *)&DAT_0042bb78;
        ppbVar9 = ppbVar10;
        ppbVar10[1] = (byte *)DAT_0042bb7c;
        DAT_0042bb7c = ppbVar9;
        *ppbVar8 = (byte *)ppbVar10;
        DAT_0042bb74 = 0;
        ppbVar10 = ppbVar10 + 4;
      }
      return ppbVar10;
    }
    uVar17 = (uint)(param_1 + 0xd3) & 0xffffff00;
    uVar18 = uVar17 + 0x30;
    if (DAT_00429055 != '\0') {
      while( true ) {
        LOCK();
        bVar19 = DAT_00429ae4 == 0;
        DAT_00429ae4 = DAT_00429ae4 ^ bVar19 * (DAT_00429ae4 ^ 1);
        UNLOCK();
        if (bVar19) break;
        if (DAT_00429985 == '\0') {
          Sleep(0);
          LOCK();
          bVar19 = DAT_00429ae4 == 0;
          DAT_00429ae4 = DAT_00429ae4 ^ bVar19 * (DAT_00429ae4 ^ 1);
          UNLOCK();
          if (bVar19) break;
          Sleep(10);
        }
      }
    }
    uVar15 = uVar17 - 0xb00;
    uVar14 = uVar15 >> 0xd;
    uVar11 = -1 << ((byte)(uVar15 >> 8) & 0x1f) & *(uint *)(&DAT_00429af4 + uVar14 * 4);
    if (uVar11 == 0) {
      uVar15 = -2 << ((byte)uVar14 & 0x1f) & _DAT_00429af0;
      if (uVar15 == 0) {
        if (DAT_00429aec < uVar18) {
          ppbVar10 = (byte **)FUN_00402c94(uVar18);
        }
        else {
          ppbVar10 = (byte **)((int)DAT_00429ae8 - uVar18);
          DAT_00429ae8 = ppbVar10;
          DAT_00429aec = DAT_00429aec - uVar18;
          ppbVar10[-1] = (byte *)(uVar18 | 2);
        }
        DAT_00429ae4 = 0;
        return ppbVar10;
      }
      uVar14 = 0;
      if (uVar15 != 0) {
        for (; (uVar15 >> uVar14 & 1) == 0; uVar14 = uVar14 + 1) {
        }
      }
      uVar12 = 0;
      if (*(uint *)(&DAT_00429af4 + uVar14 * 4) != 0) {
        for (; (*(uint *)(&DAT_00429af4 + uVar14 * 4) >> uVar12 & 1) == 0; uVar12 = uVar12 + 1) {
        }
      }
      uVar12 = uVar12 | uVar14 << 5;
    }
    else {
      uVar12 = 0;
      if (uVar11 != 0) {
        for (; (uVar11 >> uVar12 & 1) == 0; uVar12 = uVar12 + 1) {
        }
      }
      uVar12 = uVar15 >> 8 & 0xffffffe0 | uVar12;
    }
    ppbVar10 = (byte **)(&DAT_00429b78)[uVar12 * 2];
    puVar6 = (undefined4 *)ppbVar10[1];
    (&DAT_00429b78)[uVar12 * 2] = puVar6;
    *puVar6 = &DAT_00429b74 + uVar12 * 2;
    if (&DAT_00429b74 + uVar12 * 2 == puVar6) {
      bVar7 = (byte)uVar12 & 0x1f;
      puVar3 = (uint *)(&DAT_00429af4 + uVar14 * 4);
      *puVar3 = *puVar3 & (-2 << bVar7 | 0xfffffffeU >> 0x20 - bVar7);
      if (*puVar3 == 0) {
        (&DAT_00429af0)[(int)uVar14 >> 3] =
             (&DAT_00429af0)[(int)uVar14 >> 3] & ~('\x01' << (uVar14 & 7));
      }
    }
    uVar15 = ((uint)ppbVar10[-1] & 0xfffffff0) - uVar18;
    if (uVar15 == 0) {
      pbVar2 = (byte *)((((uint)ppbVar10[-1] & 0xfffffff0) - 4) + (int)ppbVar10);
      *pbVar2 = *pbVar2 & 0xf7;
    }
    else {
      puVar6 = (undefined4 *)(uVar18 + (int)ppbVar10);
      puVar6[-1] = uVar15 + 3;
      *(uint *)((uVar15 - 8) + (int)puVar6) = uVar15;
      if (0xb2f < uVar15) {
        FUN_00402bc8(puVar6,uVar15);
      }
    }
    ppbVar10[-1] = (byte *)(uVar17 + 0x32);
    DAT_00429ae4 = 0;
    return ppbVar10;
  }
  iVar13 = (uint)(byte)(&DAT_0042998c)[(uint)(param_1 + 3) >> 3] * 8;
  pbVar2 = &DAT_0042706c + iVar13;
  pbVar16 = pbVar2;
  if (DAT_00429055 != '\0') {
    while( true ) {
      LOCK();
      bVar7 = *pbVar2;
      *pbVar2 = *pbVar2 ^ (bVar7 == 0) * (*pbVar2 ^ 1);
      UNLOCK();
      pbVar16 = pbVar2;
      if (bVar7 == 0) break;
      pbVar16 = &DAT_0042708c + iVar13;
      LOCK();
      bVar7 = *pbVar16;
      *pbVar16 = *pbVar16 ^ (bVar7 == 0) * (*pbVar16 ^ 1);
      UNLOCK();
      if (bVar7 == 0) break;
      pbVar16 = &DAT_004270ac + iVar13;
      LOCK();
      bVar7 = *pbVar16;
      *pbVar16 = *pbVar16 ^ (bVar7 == 0) * (*pbVar16 ^ 1);
      UNLOCK();
      if (bVar7 == 0) break;
      if (DAT_00429985 == '\0') {
        Sleep(0);
        LOCK();
        bVar7 = *pbVar2;
        *pbVar2 = *pbVar2 ^ (bVar7 == 0) * (*pbVar2 ^ 1);
        UNLOCK();
        pbVar16 = pbVar2;
        if (bVar7 == 0) break;
        Sleep(10);
      }
    }
  }
  pbVar2 = *(byte **)(pbVar16 + 8);
  ppbVar10 = *(byte ***)(pbVar2 + 0x10);
  if (pbVar2 != pbVar16) {
    *(int *)(pbVar2 + 0x14) = *(int *)(pbVar2 + 0x14) + 1;
    pbVar5 = ppbVar10[-1];
    *(uint *)(pbVar2 + 0x10) = (uint)pbVar5 & 0xfffffff8;
    ppbVar10[-1] = pbVar2;
    if (((uint)pbVar5 & 0xfffffff8) != 0) {
      *pbVar16 = 0;
      return ppbVar10;
    }
    iVar13 = *(int *)(pbVar2 + 8);
    *(byte **)(iVar13 + 0xc) = pbVar16;
    *(int *)(pbVar16 + 8) = iVar13;
    *pbVar16 = 0;
    return ppbVar10;
  }
  pbVar2 = *(byte **)(pbVar16 + 0x18);
  uVar4 = *(ushort *)(pbVar16 + 2);
  if (ppbVar10 < *(byte ***)(pbVar16 + 0x14) || ppbVar10 == *(byte ***)(pbVar16 + 0x14)) {
    piVar1 = (int *)(pbVar2 + 0x14);
    *piVar1 = *piVar1 + 1;
    *(uint *)(pbVar16 + 0x10) = (uint)uVar4 + (int)ppbVar10;
    *pbVar16 = 0;
    ppbVar10[-1] = pbVar2;
    return ppbVar10;
  }
  if (DAT_00429055 != '\0') {
    while( true ) {
      LOCK();
      bVar19 = DAT_00429ae4 == 0;
      DAT_00429ae4 = DAT_00429ae4 ^ bVar19 * (DAT_00429ae4 ^ 1);
      UNLOCK();
      if (bVar19) break;
      if (DAT_00429985 == '\0') {
        Sleep(0);
        LOCK();
        bVar19 = DAT_00429ae4 == 0;
        DAT_00429ae4 = DAT_00429ae4 ^ bVar19 * (DAT_00429ae4 ^ 1);
        UNLOCK();
        if (bVar19) break;
        Sleep(10);
      }
    }
  }
  uVar17 = (int)(char)pbVar16[1] & _DAT_00429af0;
  if (uVar17 == 0) {
    if (DAT_00429aec < *(ushort *)(pbVar16 + 4)) {
      uVar17 = (uint)*(ushort *)(pbVar16 + 6);
      ppbVar10 = (byte **)FUN_00402c94(uVar17);
      if (ppbVar10 == (byte **)0x0) {
        DAT_00429ae4 = 0;
        *pbVar16 = 0;
        return (byte **)0x0;
      }
    }
    else {
      uVar17 = DAT_00429aec;
      if (*(ushort *)(pbVar16 + 6) + 0xb30 <= DAT_00429aec) {
        uVar17 = (uint)*(ushort *)(pbVar16 + 6);
      }
      ppbVar10 = (byte **)((int)DAT_00429ae8 - uVar17);
      DAT_00429aec = DAT_00429aec - uVar17;
      DAT_00429ae8 = ppbVar10;
    }
  }
  else {
    uVar18 = 0;
    if (uVar17 != 0) {
      for (; (uVar17 >> uVar18 & 1) == 0; uVar18 = uVar18 + 1) {
      }
    }
    iVar13 = 0;
    if (*(uint *)(&DAT_00429af4 + uVar18 * 4) != 0) {
      for (; (*(uint *)(&DAT_00429af4 + uVar18 * 4) >> iVar13 & 1) == 0; iVar13 = iVar13 + 1) {
      }
    }
    iVar13 = iVar13 + uVar18 * 0x20;
    ppbVar10 = (byte **)(&DAT_00429b78)[iVar13 * 2];
    puVar6 = (undefined4 *)ppbVar10[1];
    (&DAT_00429b78)[iVar13 * 2] = puVar6;
    *puVar6 = &DAT_00429b74 + iVar13 * 2;
    if (&DAT_00429b74 + iVar13 * 2 == puVar6) {
      bVar7 = (byte)iVar13 & 0x1f;
      puVar3 = (uint *)(&DAT_00429af4 + uVar18 * 4);
      *puVar3 = *puVar3 & (-2 << bVar7 | 0xfffffffeU >> 0x20 - bVar7);
      if (*puVar3 == 0) {
        (&DAT_00429af0)[(int)uVar18 >> 3] =
             (&DAT_00429af0)[(int)uVar18 >> 3] & ~('\x01' << (uVar18 & 7));
      }
    }
    uVar17 = (uint)ppbVar10[-1] & 0xfffffff0;
    if (uVar17 < 0x10a60) {
      pbVar2 = (byte *)((uVar17 - 4) + (int)ppbVar10);
      *pbVar2 = *pbVar2 & 0xf7;
    }
    else {
      uVar18 = (uint)*(ushort *)(pbVar16 + 6);
      iVar13 = uVar17 - uVar18;
      puVar6 = (undefined4 *)(uVar18 + (int)ppbVar10);
      puVar6[-1] = iVar13 + 3;
      *(int *)(iVar13 + -8 + (int)puVar6) = iVar13;
      FUN_00402bc8(puVar6,iVar13);
      uVar17 = uVar18;
    }
  }
  ppbVar10[-1] = (byte *)(uVar17 + 6);
  DAT_00429ae4 = 0;
  *ppbVar10 = pbVar16;
  ppbVar10[4] = (byte *)0x0;
  ppbVar10[5] = (byte *)0x1;
  *(byte ***)(pbVar16 + 0x18) = ppbVar10;
  *(uint *)(pbVar16 + 0x10) = (uint)*(ushort *)(pbVar16 + 2) + (int)(ppbVar10 + 8);
  *(uint *)(pbVar16 + 0x14) = (int)ppbVar10 + (uVar17 - *(ushort *)(pbVar16 + 2));
  *pbVar16 = 0;
  ppbVar10[7] = (byte *)ppbVar10;
  return ppbVar10 + 8;
}



// WARNING: Type propagation algorithm not settling

int FUN_00403334(int **param_1)

{
  byte bVar1;
  int *piVar2;
  int *piVar3;
  int *piVar4;
  BOOL BVar5;
  uint uVar6;
  int **ppiVar7;
  byte *pbVar8;
  int **ppiVar9;
  int iVar10;
  bool bVar11;
  uint local_20;
  DWORD DStack_18;
  
  ppiVar7 = (int **)param_1[-1];
  if (((uint)ppiVar7 & 7) != 0) {
    if (((uint)ppiVar7 & 5) != 0) {
      if (((uint)ppiVar7 & 3) != 0) {
        return -1;
      }
      ppiVar9 = param_1 + -4;
      FUN_00402d10();
      piVar2 = *ppiVar9;
      ppiVar7 = (int **)param_1[-3];
      if (((uint)param_1[-1] & 8) == 0) {
        BVar5 = VirtualFree(ppiVar9,0,0x8000);
        if (BVar5 == 0) {
          iVar10 = -1;
        }
        else {
          iVar10 = 0;
        }
      }
      else {
        uVar6 = (uint)param_1[-1] & 0xfffffff0;
        iVar10 = 0;
        while( true ) {
          VirtualQuery(ppiVar9,(PMEMORY_BASIC_INFORMATION)&stack0xffffffd4,0x1c);
          BVar5 = VirtualFree(ppiVar9,0,0x8000);
          if (BVar5 == 0) break;
          if (uVar6 <= local_20) goto LAB_00402e3b;
          uVar6 = uVar6 - local_20;
          ppiVar9 = (int **)((int)ppiVar9 + local_20);
        }
        iVar10 = -1;
      }
LAB_00402e3b:
      if (iVar10 == 0) {
        *ppiVar7 = piVar2;
        piVar2[1] = (int)ppiVar7;
      }
      DAT_0042bb74 = 0;
      return iVar10;
    }
    goto LAB_00403435;
  }
  piVar2 = *ppiVar7;
  if (DAT_00429055 != '\0') {
    while( true ) {
      LOCK();
      bVar1 = *(byte *)piVar2;
      *(byte *)piVar2 = *(byte *)piVar2 ^ (bVar1 == 0) * (*(byte *)piVar2 ^ 1);
      UNLOCK();
      if (bVar1 == 0) break;
      if (DAT_00429985 == '\0') {
        Sleep(0);
        LOCK();
        bVar1 = *(byte *)piVar2;
        *(byte *)piVar2 = *(byte *)piVar2 ^ (bVar1 == 0) * (*(byte *)piVar2 ^ 1);
        UNLOCK();
        if (bVar1 == 0) break;
        Sleep(10);
      }
    }
  }
  ppiVar9 = ppiVar7 + 5;
  *ppiVar9 = (int *)((int)*ppiVar9 + -1);
  piVar4 = ppiVar7[4];
  if (*ppiVar9 != (int *)0x0) {
    ppiVar7[4] = (int *)param_1;
    param_1[-1] = (int *)((int)piVar4 + 1);
    if (piVar4 != (int *)0x0) {
      *(byte *)piVar2 = 0;
      return 0;
    }
    piVar4 = (int *)piVar2[2];
    ppiVar7[3] = piVar2;
    ppiVar7[2] = piVar4;
    piVar4[3] = (int)ppiVar7;
    piVar2[2] = (int)ppiVar7;
    *(byte *)piVar2 = 0;
    return 0;
  }
  if (piVar4 == (int *)0x0) {
LAB_0040339b:
    piVar2[5] = (int)piVar4;
  }
  else {
    piVar4 = ppiVar7[3];
    piVar3 = ppiVar7[2];
    piVar4[2] = (int)piVar3;
    piVar3[3] = (int)piVar4;
    piVar4 = (int *)0x0;
    if ((int **)piVar2[6] == ppiVar7) goto LAB_0040339b;
  }
  *(byte *)piVar2 = (byte)piVar4;
  param_1 = ppiVar7;
  ppiVar7 = (int **)ppiVar7[-1];
LAB_00403435:
  pbVar8 = (byte *)((uint)ppiVar7 & 0xfffffff0);
  if (DAT_00429055 != '\0') {
    while( true ) {
      LOCK();
      bVar11 = DAT_00429ae4 == 0;
      DAT_00429ae4 = DAT_00429ae4 ^ bVar11 * (DAT_00429ae4 ^ 1);
      UNLOCK();
      if (bVar11) break;
      if (DAT_00429985 == '\0') {
        Sleep(0);
        LOCK();
        bVar11 = DAT_00429ae4 == 0;
        DAT_00429ae4 = DAT_00429ae4 ^ bVar11 * (DAT_00429ae4 ^ 1);
        UNLOCK();
        if (bVar11) break;
        Sleep(10);
      }
    }
  }
  if ((*(uint *)(pbVar8 + -4 + (int)param_1) & 1) == 0) {
    *(uint *)(pbVar8 + -4 + (int)param_1) = *(uint *)(pbVar8 + -4 + (int)param_1) | 8;
  }
  else {
    ppiVar7 = (int **)(pbVar8 + (int)param_1);
    uVar6 = *(uint *)(pbVar8 + -4 + (int)param_1) & 0xfffffff0;
    pbVar8 = pbVar8 + uVar6;
    if (0xb2f < uVar6) {
      FUN_00402b88(ppiVar7);
    }
  }
  if ((*(byte *)(param_1 + -1) & 8) != 0) {
    piVar2 = param_1[-2];
    param_1 = (int **)((int)param_1 - (int)piVar2);
    pbVar8 = pbVar8 + (int)piVar2;
    if ((int *)0xb2f < piVar2) {
      FUN_00402b88(param_1);
    }
  }
  if (pbVar8 != (byte *)0x13ffe0) {
    param_1[-1] = (int *)(pbVar8 + 3);
    *(byte **)(pbVar8 + -8 + (int)param_1) = pbVar8;
    FUN_00402bc8(param_1,(int)pbVar8);
    DAT_00429ae4 = 0;
    return 0;
  }
  if (DAT_00429aec == 0x13ffe0) {
    piVar2 = param_1[-4];
    ppiVar7 = (int **)param_1[-3];
    piVar2[1] = (int)ppiVar7;
    *ppiVar7 = piVar2;
    DAT_00429ae4 = 0;
    DStack_18 = 0x4034e1;
    BVar5 = VirtualFree(param_1 + -4,0,0x8000);
    return -(uint)(BVar5 == 0);
  }
  FUN_00402c28();
  param_1[0x4fff7] = (int *)0x2;
  DAT_00429aec = 0x13ffe0;
  DAT_00429ae8 = param_1 + 0x4fff8;
  DAT_00429ae4 = 0;
  return 0;
}



int ** FUN_0040352c(int **param_1,int *param_2)

{
  int iVar1;
  LPVOID pvVar2;
  int **ppiVar3;
  byte *pbVar4;
  int *piVar5;
  uint uVar6;
  int *piVar7;
  int *piVar8;
  LPCVOID lpAddress;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  int **ppiVar12;
  bool bVar13;
  uint local_20;
  DWORD in_stack_ffffffe4;
  
  piVar5 = param_1[-1];
  if (((uint)piVar5 & 7) == 0) {
    iVar1 = *piVar5;
    piVar5 = (int *)(*(ushort *)(iVar1 + 2) - 4);
    if (piVar5 < param_2) {
      piVar5 = (int *)(*(ushort *)(iVar1 + 2) + 0x1c + (int)piVar5);
      ppiVar3 = (int **)FUN_00402fb0((byte *)(((piVar5 < param_2) - 1 & (int)piVar5 - (int)param_2)
                                             + (int)param_2));
      if (ppiVar3 != (int **)0x0) {
        if ((int *)0x40a2c < param_2) {
          ppiVar3[-2] = param_2;
        }
        (**(code **)(iVar1 + 0x1c))(param_1,ppiVar3,*(ushort *)(iVar1 + 2) - 4);
        FUN_00403334(param_1);
      }
      return ppiVar3;
    }
    if (piVar5 <= (int *)((int)param_2 * 4 + 0x40U)) {
      return param_1;
    }
    ppiVar3 = (int **)FUN_00402fb0((byte *)param_2);
    if (ppiVar3 != (int **)0x0) {
      FUN_00402b6c((int)param_1,(int)ppiVar3,(int)param_2);
      FUN_00403334(param_1);
    }
    return ppiVar3;
  }
  if (((uint)piVar5 & 5) != 0) {
    if (((uint)piVar5 & 3) != 0) {
      return (int **)0x0;
    }
    piVar5 = (int *)(((uint)param_1[-1] & 0xfffffff0) - 0x14);
    if (piVar5 < param_2) {
      piVar8 = (int *)(((uint)piVar5 >> 2) + (int)piVar5);
      piVar7 = param_2;
      if (param_2 < piVar8) {
        piVar7 = piVar8;
      }
      lpAddress = (LPCVOID)((int)param_1 + (((uint)param_1[-1] & 0xfffffff0) - 0x10));
      VirtualQuery(lpAddress,(PMEMORY_BASIC_INFORMATION)&stack0xffffffd4,0x1c);
      if ((in_stack_ffffffe4 == 0x10000) &&
         (local_20 = local_20 & 0xffff0000, (uint)((int)param_2 - (int)piVar5) < local_20)) {
        uVar6 = (int)piVar7 + (0xffff - (int)piVar5) & 0xffff0000;
        if (local_20 < uVar6) {
          uVar6 = local_20;
        }
        pvVar2 = VirtualAlloc(lpAddress,uVar6,0x2000,4);
        if ((pvVar2 != (LPVOID)0x0) &&
           (pvVar2 = VirtualAlloc(lpAddress,uVar6,0x1000,4), pvVar2 != (LPVOID)0x0)) {
          param_1[-2] = param_2;
          param_1[-1] = (int *)(uVar6 + (int)param_1[-1] | 8);
          return param_1;
        }
      }
      ppiVar3 = (int **)FUN_00402fb0((byte *)piVar7);
      if (ppiVar3 != (int **)0x0) {
        if ((int *)0x40a2c < piVar7) {
          ppiVar3[-2] = param_2;
        }
        FUN_00402b3c((int)param_1,(int)ppiVar3,(int)param_1[-2]);
        FUN_00403334(param_1);
      }
    }
    else if (param_2 < (int *)((uint)piVar5 >> 1)) {
      ppiVar3 = (int **)FUN_00402fb0((byte *)param_2);
      if (ppiVar3 != (int **)0x0) {
        if ((int *)0x40a2c < param_2) {
          param_1[-2] = param_2;
        }
        FUN_00402b6c((int)param_1,(int)ppiVar3,(int)param_2);
        FUN_00403334(param_1);
      }
    }
    else {
      param_1[-2] = param_2;
      ppiVar3 = param_1;
    }
    return ppiVar3;
  }
  uVar6 = (uint)piVar5 & 0xfffffff0;
  ppiVar3 = (int **)(uVar6 + (int)param_1);
  piVar7 = (int *)(uVar6 - 4);
  uVar9 = (uint)piVar5 & 0xf;
  if (param_2 <= piVar7) {
    if (piVar7 <= (int *)((int)param_2 * 2)) {
      return param_1;
    }
    if (param_2 < (int *)0xb2c) {
      if (param_2 < (int *)0x2cc) {
        ppiVar3 = (int **)FUN_00402fb0((byte *)param_2);
        if (ppiVar3 != (int **)0x0) {
          FUN_00402b6c((int)param_1,(int)ppiVar3,(int)param_2);
          FUN_00403334(param_1);
        }
        return ppiVar3;
      }
      param_2 = (int *)0xb2c;
      if (piVar7 < (int *)0xb2d) {
        return param_1;
      }
    }
    uVar10 = (int)param_2 + 0xd3U & 0xffffff00;
    uVar11 = uVar10 + 0x30;
    piVar5 = (int *)(uVar6 - uVar11);
    if (DAT_00429055 != '\0') {
      while( true ) {
        LOCK();
        bVar13 = DAT_00429ae4 == 0;
        DAT_00429ae4 = DAT_00429ae4 ^ bVar13 * (DAT_00429ae4 ^ 1);
        UNLOCK();
        if (bVar13) break;
        if (DAT_00429985 == '\0') {
          Sleep(0);
          LOCK();
          bVar13 = DAT_00429ae4 == 0;
          DAT_00429ae4 = DAT_00429ae4 ^ bVar13 * (DAT_00429ae4 ^ 1);
          UNLOCK();
          if (bVar13) break;
          Sleep(10);
        }
      }
      uVar9 = (uint)param_1[-1] & 0xf;
    }
    param_1[-1] = (int *)(uVar9 | uVar11);
    piVar7 = ppiVar3[-1];
    if (((uint)piVar7 & 1) == 0) {
      ppiVar3[-1] = (int *)((uint)piVar7 | 8);
      ppiVar12 = ppiVar3;
    }
    else {
      uVar6 = (uint)piVar7 & 0xfffffff0;
      piVar5 = (int *)((int)piVar5 + uVar6);
      ppiVar12 = (int **)((int)ppiVar3 + uVar6);
      if (0xb2f < uVar6) {
        FUN_00402b88(ppiVar3);
      }
    }
    ppiVar12[-2] = piVar5;
    *(int *)((int)param_1 + uVar10 + 0x2c) = (int)piVar5 + 3;
    if ((int *)0xb2f < piVar5) {
      FUN_00402bc8((undefined4 *)((int)param_1 + uVar11),(int)piVar5);
    }
    DAT_00429ae4 = 0;
    return param_1;
  }
  if (((uint)ppiVar3[-1] & 1) != 0) {
    uVar6 = (uint)ppiVar3[-1] & 0xfffffff0;
    piVar5 = (int *)((int)piVar7 + uVar6);
    if (param_2 <= piVar5) {
      if (DAT_00429055 == '\0') {
LAB_00403771:
        if (0xb2f < uVar6) {
          FUN_00402b88(ppiVar3);
        }
        piVar7 = (int *)(((uint)piVar7 >> 2) + (int)piVar7);
        uVar6 = (uint)((int)param_2 + ((int)piVar7 - (int)param_2 & (piVar7 < param_2) - 1) + 0xd3)
                & 0xffffff00;
        piVar7 = (int *)(uVar6 + 0x30);
        uVar10 = (int)(piVar5 + 1) - (int)piVar7;
        if (piVar5 + 1 < piVar7 || uVar10 == 0) {
          *(uint *)((int)param_1 + (int)piVar5) = *(uint *)((int)param_1 + (int)piVar5) & 0xfffffff7
          ;
          piVar7 = piVar5 + 1;
        }
        else {
          *(uint *)((int)(param_1 + -1) + (int)piVar5) = uVar10;
          *(uint *)(uVar6 + 0x2c + (int)param_1) = uVar10 + 3;
          if (0xb2f < uVar10) {
            FUN_00402bc8((undefined4 *)((int)piVar7 + (int)param_1),uVar10);
          }
        }
        param_1[-1] = (int *)((uint)piVar7 | uVar9);
        DAT_00429ae4 = 0;
        return param_1;
      }
      while( true ) {
        LOCK();
        bVar13 = DAT_00429ae4 == 0;
        DAT_00429ae4 = DAT_00429ae4 ^ bVar13 * (DAT_00429ae4 ^ 1);
        UNLOCK();
        if (bVar13) break;
        if (DAT_00429985 == '\0') {
          local_20 = 0x403739;
          Sleep(0);
          LOCK();
          bVar13 = DAT_00429ae4 == 0;
          DAT_00429ae4 = DAT_00429ae4 ^ bVar13 * (DAT_00429ae4 ^ 1);
          UNLOCK();
          if (bVar13) break;
          local_20 = 0x403753;
          Sleep(10);
        }
      }
      uVar9 = (uint)param_1[-1] & 0xf;
      if (((uint)ppiVar3[-1] & 1) != 0) {
        uVar6 = (uint)ppiVar3[-1] & 0xfffffff0;
        piVar5 = (int *)((int)piVar7 + uVar6);
        if (param_2 <= piVar5) goto LAB_00403771;
      }
      DAT_00429ae4 = 0;
    }
  }
  piVar5 = (int *)(((uint)piVar7 >> 2) + (int)piVar7);
  pbVar4 = (byte *)(((int)piVar5 - (int)param_2 & (piVar5 < param_2) - 1) + (int)param_2);
  ppiVar3 = (int **)FUN_00402fb0(pbVar4);
  if (ppiVar3 == (int **)0x0) {
    return (int **)0x0;
  }
  if ((byte *)0x40a2c < pbVar4) {
    ppiVar3[-2] = param_2;
  }
  FUN_00402b3c((int)param_1,(int)ppiVar3,(int)piVar7);
  FUN_00403334(param_1);
  return ppiVar3;
}



void FUN_00403844(byte *param_1)

{
  uint *puVar1;
  byte **ppbVar2;
  uint uVar3;
  int iVar4;
  
  ppbVar2 = FUN_00402fb0(param_1);
  puVar1 = (uint *)(((uint)(param_1 + -1) & 0xfffffffc) + (int)ppbVar2);
  uVar3 = (uint)(param_1 + -1) & 0xfffffffc | -(uint)(ppbVar2 == (byte **)0x0);
  if (uVar3 < 0x40a2c) {
    iVar4 = -uVar3;
    do {
      *(double *)(iVar4 + (int)puVar1) = (double)(float10)0;
      iVar4 = iVar4 + 8;
    } while (iVar4 < 0);
    *puVar1 = -(uint)(ppbVar2 == (byte **)0x0);
    ffree((float10)0);
  }
  return;
}



void FUN_00403878(LPCSTR param_1,LPCSTR param_2,DWORD param_3)

{
  DWORD DVar1;
  HANDLE pvVar2;
  undefined *lpBuffer;
  DWORD *pDVar3;
  LPOVERLAPPED p_Var4;
  DWORD local_c;
  
  pDVar3 = &local_c;
  local_c = param_3;
  if (DAT_00429054 == '\0') {
    MessageBoxA((HWND)0x0,param_1,param_2,0x2010);
  }
  else {
    p_Var4 = (LPOVERLAPPED)0x0;
    DVar1 = FUN_00406eec((int)param_2);
    pvVar2 = GetStdHandle(0xfffffff4);
    WriteFile(pvVar2,param_2,DVar1,pDVar3,p_Var4);
    pDVar3 = &local_c;
    p_Var4 = (LPOVERLAPPED)0x0;
    DVar1 = FUN_00406eec((int)PTR_DAT_00427064);
    lpBuffer = PTR_DAT_00427064;
    pvVar2 = GetStdHandle(0xfffffff4);
    WriteFile(pvVar2,lpBuffer,DVar1,pDVar3,p_Var4);
    pDVar3 = &local_c;
    p_Var4 = (LPOVERLAPPED)0x0;
    DVar1 = FUN_00406eec((int)param_1);
    pvVar2 = GetStdHandle(0xfffffff4);
    WriteFile(pvVar2,param_1,DVar1,pDVar3,p_Var4);
  }
  return;
}



int FUN_004038fc(int param_1)

{
  int iVar1;
  
  iVar1 = (*(uint *)(param_1 + -4) & 0xfffffff0) + param_1;
  if ((*(uint *)(iVar1 + -4) & 0xfffffff0) == 0) {
    iVar1 = 0;
  }
  return iVar1;
}



uint FUN_00403920(uint param_1)

{
  uint uVar1;
  
  if (((DAT_00429aec != 0) && (param_1 <= DAT_00429ae8)) && (DAT_00429ae8 <= param_1 + 0x13fff0)) {
    uVar1 = DAT_00429ae8;
    if (DAT_00429aec == 0x13ffe0) {
      uVar1 = 0;
    }
    return uVar1;
  }
  return param_1 + 0x10;
}



void FUN_00403960(int *param_1,int **param_2,int *param_3)

{
  int iVar1;
  
  *param_2 = param_1 + 8;
  iVar1 = *param_1;
  if ((param_1 == *(int **)(iVar1 + 0x18)) &&
     (*(uint *)(iVar1 + 0x10) < *(uint *)(iVar1 + 0x14) ||
      *(uint *)(iVar1 + 0x10) == *(uint *)(iVar1 + 0x14))) {
    *param_3 = *(int *)(iVar1 + 0x10) + -1;
    return;
  }
  *param_3 = (int)param_1 + ((param_1[-1] & 0xfffffff0U) - (uint)*(ushort *)(iVar1 + 2));
  return;
}



int FUN_0040399c(uint param_1,longlong *param_2)

{
  uint uVar1;
  uint uVar2;
  char acStack_13 [3];
  
  uVar2 = 0;
  do {
    uVar1 = param_1 / 10;
    uVar2 = uVar2 + 1;
    (&stack0xfffffff0)[-uVar2] = (char)param_1 + (char)uVar1 * -10 + '0';
    param_1 = uVar1;
  } while (uVar1 != 0);
  FUN_0040465c((longlong *)(&stack0xfffffff0 + -uVar2),param_2,uVar2);
  return uVar2 + (int)param_2;
}



int FUN_004039ec(longlong *param_1,longlong *param_2,uint param_3)

{
  FUN_0040465c(param_1,param_2,param_3);
  return (int)param_2 + param_3;
}



void FUN_00403a04(int param_1,longlong *param_2)

{
  uint uVar1;
  
  if (param_1 != 0) {
    FUN_004039ec((longlong *)(*(byte **)(param_1 + -0x38) + 1),param_2,
                 (uint)**(byte **)(param_1 + -0x38));
    return;
  }
  uVar1 = FUN_00406eec((int)PTR_s_Unknown_00427058);
  FUN_004039ec((longlong *)PTR_s_Unknown_00427058,param_2,uVar1);
  return;
}



undefined4 FUN_00403a38(LPCVOID param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  if (((LPCVOID)0xffff < param_1) && (((uint)param_1 & 3) == 0)) {
    if ((param_1 < *(LPCVOID *)(param_4 + -0x1c)) ||
       ((uint)((int)*(LPCVOID *)(param_4 + -0x1c) + *(int *)(param_4 + -0x10)) < (int)param_1 + 4U))
    {
      *(undefined4 *)(param_4 + -0x10) = 0;
      VirtualQuery(param_1,(PMEMORY_BASIC_INFORMATION)(param_4 + -0x1c),0x1c);
    }
    if ((((3 < *(uint *)(param_4 + -0x10)) && (*(int *)(param_4 + -0xc) == 0x1000)) &&
        ((*(byte *)(param_4 + -8) & 0xf6) != 0)) && ((*(byte *)(param_4 + -7) & 1) == 0)) {
      return CONCAT31((int3)((uint)param_4 >> 8),1);
    }
  }
  return 0;
}



undefined4 FUN_00403ab0(int param_1,int param_2,undefined4 param_3,int param_4)

{
  int *piVar1;
  undefined4 uVar2;
  int *piVar3;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  int iVar4;
  int iVar5;
  
  if (((999 < param_2) ||
      (iVar4 = param_4, uVar2 = FUN_00403a38((LPCVOID)(param_1 + -0x58),param_2,param_3,param_4),
      (char)uVar2 == '\0')) ||
     (iVar5 = param_4, uVar2 = FUN_00403a38((LPCVOID)(param_1 + -0x30),extraout_EDX,iVar4,param_4),
     (char)uVar2 == '\0')) {
    return 0;
  }
  piVar1 = *(int **)(param_1 + -0x30);
  piVar3 = (int *)(param_1 + -0x58);
  if ((param_1 == *piVar3) &&
     ((piVar1 == (int *)0x0 ||
      ((iVar4 = param_4, uVar2 = FUN_00403a38(piVar1,extraout_EDX_00,iVar5,param_4),
       (char)uVar2 != '\0' &&
       (piVar3 = (int *)FUN_00403ab0(*piVar1,param_2 + 1,iVar4,param_4), (char)piVar3 != '\0'))))))
  {
    return CONCAT31((int3)((uint)piVar3 >> 8),1);
  }
  return 0;
}



int FUN_00403b30(int *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *param_1;
  uVar1 = FUN_00403ab0(iVar2,0,param_3,(int)&stack0xfffffffc);
  if ((char)uVar1 == '\0') {
    iVar2 = 0;
  }
  return iVar2;
}



bool FUN_00403b58(void)

{
  bool bVar1;
  
  if (DAT_00429055 != '\0') {
    while( true ) {
      LOCK();
      bVar1 = DAT_0042bb8c == 0;
      DAT_0042bb8c = DAT_0042bb8c ^ bVar1 * (DAT_0042bb8c ^ 1);
      UNLOCK();
      if ((byte)(!bVar1 * DAT_0042bb8c) == '\0') break;
      if (DAT_00429985 == '\0') {
        Sleep(0);
        LOCK();
        bVar1 = DAT_0042bb8c == 0;
        DAT_0042bb8c = DAT_0042bb8c ^ bVar1 * (DAT_0042bb8c ^ 1);
        UNLOCK();
        if ((byte)(!bVar1 * DAT_0042bb8c) == '\0') break;
        Sleep(10);
      }
    }
  }
  if (DAT_0042bb88 == (LPVOID)0x0) {
    DAT_0042bb88 = VirtualAlloc((LPVOID)0x0,0x10000,0x1000,4);
  }
  return DAT_0042bb88 != (LPVOID)0x0;
}



undefined4 FUN_00403bcc(int param_1)

{
  int *piVar1;
  bool bVar2;
  undefined4 uVar3;
  
  bVar2 = FUN_00403b58();
  if ((bVar2) && (*DAT_0042bb88 < 0x3ffe)) {
    DAT_0042bb88[*DAT_0042bb88 + 1] = param_1;
    piVar1 = DAT_0042bb88;
    *DAT_0042bb88 = *DAT_0042bb88 + 1;
    uVar3 = CONCAT31((int3)((uint)piVar1 >> 8),1);
  }
  else {
    uVar3 = 0;
  }
  DAT_0042bb8c = 0;
  return uVar3;
}



undefined4 FUN_00403c0c(int param_1)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  
  uVar4 = 0;
  if (DAT_0042bb88 != (int *)0x0) {
    bVar1 = FUN_00403b58();
    if (bVar1) {
      iVar3 = *DAT_0042bb88;
      if (-1 < iVar3 + -1) {
        iVar2 = 0;
        do {
          if (param_1 == DAT_0042bb88[iVar2 + 1]) {
            DAT_0042bb88[iVar2 + 1] = DAT_0042bb88[*DAT_0042bb88];
            *DAT_0042bb88 = *DAT_0042bb88 + -1;
            uVar4 = 1;
            break;
          }
          iVar2 = iVar2 + 1;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
      DAT_0042bb8c = 0;
    }
  }
  return uVar4;
}



void FUN_00403c64(int *param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  int iVar5;
  int local_2c;
  int *local_28;
  int *local_24;
  char local_1d;
  int *local_1c;
  int *local_18;
  uint local_14;
  int local_10;
  int *local_8;
  
  iVar2 = param_4 + -0x1b800 + (*param_1 - 0x42706cU >> 5) * 0x800;
  local_8 = param_1;
  FUN_00403960(param_1,&local_24,(int *)&local_28);
  do {
    if (local_28 < local_24) {
      return;
    }
    if (((*(byte *)(local_24 + -1) & 1) == 0) &&
       (uVar3 = FUN_00403c0c((int)local_24), (char)uVar3 == '\0')) {
      *(undefined *)(param_4 + -0x1b801) = 0;
      iVar5 = 0;
      iVar4 = FUN_00403b30(local_24,extraout_EDX,extraout_ECX);
      if (iVar4 == 0) {
        if (local_24[1] < 0x100) {
          local_10 = local_24[2];
          local_14 = (uint)*(ushort *)((int)local_24 + 2);
          if ((((local_14 == 1) || (local_14 == 2)) && (0 < local_10)) &&
             (local_10 < (int)(*(ushort *)(*local_8 + 2) - 0x10) / (int)local_14)) {
            local_1d = '\x01';
            local_2c = local_10;
            if (local_14 == 1) {
              local_18 = local_24 + 3;
              if (0 < local_10) {
                do {
                  if ((local_1d == '\0') || (*(byte *)local_18 < 0x20)) {
                    local_1d = '\0';
                  }
                  else {
                    local_1d = '\x01';
                  }
                  local_18 = (int *)((int)local_18 + 1);
                  local_2c = local_2c + -1;
                } while (local_2c != 0);
              }
              if ((local_1d != '\0') && (*(byte *)local_18 == 0)) {
                iVar5 = 1;
              }
            }
            else {
              local_1c = local_24 + 3;
              if (0 < local_10) {
                do {
                  if ((local_1d == '\0') || (*(ushort *)local_1c < 0x20)) {
                    local_1d = '\0';
                  }
                  else {
                    local_1d = '\x01';
                  }
                  local_1c = (int *)((int)local_1c + 2);
                  local_2c = local_2c + -1;
                } while (local_2c != 0);
              }
              if ((local_1d != '\0') && (*(ushort *)local_1c == 0)) {
                iVar5 = 2;
              }
            }
          }
        }
      }
      else {
        iVar5 = 3;
        do {
          if ((iVar4 == *(int *)(iVar2 + iVar5 * 8)) || (*(int *)(iVar2 + iVar5 * 8) == 0)) break;
          iVar5 = iVar5 + 1;
        } while (iVar5 < 0x100);
        if (iVar5 < 0x100) {
          *(int *)(iVar2 + iVar5 * 8) = iVar4;
        }
        else {
          iVar5 = 0;
        }
      }
      piVar1 = (int *)(iVar2 + 4 + iVar5 * 8);
      *piVar1 = *piVar1 + 1;
    }
    local_24 = (int *)((int)local_24 + (uint)*(ushort *)(*local_8 + 2));
  } while( true );
}



void FUN_00403e20(void)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  uint uVar5;
  longlong *plVar6;
  undefined *puVar7;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  DWORD extraout_ECX_01;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 *puVar8;
  double *pdVar9;
  undefined4 *puVar10;
  int iVar11;
  double adStackY_27828 [3839];
  longlong alStackY_20029 [256];
  double adStackY_1f828 [2048];
  double *pdStackY_1b828;
  ushort *puStackY_1b824;
  uint uStackY_1b820;
  uint uStackY_1b81c;
  int iStackY_1b818;
  int iStackY_1b814;
  char cStackY_1b80e;
  char cStackY_1b80d;
  int iStackY_1b80c;
  char cStackY_1b805;
  double adStackY_1b804 [255];
  double adStackY_1b008 [13050];
  
  iVar2 = 0x27;
  do {
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  FUN_004048f8(adStackY_27828,0x8000,0);
  FUN_004048f8(adStackY_1b804,0x1b800,0);
  FUN_004048f8(adStackY_1f828,0x4000,0);
  iStackY_1b80c = 0;
  cStackY_1b805 = '\x01';
  for (puVar10 = DAT_00429ad8; puVar8 = DAT_0042bb7c, puVar10 != &DAT_00429ad4;
      puVar10 = (undefined4 *)puVar10[1]) {
    piVar3 = (int *)FUN_00403920((uint)puVar10);
    uVar4 = extraout_ECX;
    uVar1 = extraout_EDX;
    while (piVar3 != (int *)0x0) {
      uVar5 = piVar3[-1];
      if ((uVar5 & 1) == 0) {
        if ((uVar5 & 4) == 0) {
          if (iStackY_1b80c < 0x1000) {
            iStackY_1b818 = (uVar5 & 0xfffffff0) - 4;
            uVar4 = FUN_00403c0c((int)piVar3);
            if ((char)uVar4 == '\0') {
              cStackY_1b805 = '\0';
              *(int *)((int)adStackY_1f828 + iStackY_1b80c * 4) = iStackY_1b818;
              iStackY_1b80c = iStackY_1b80c + 1;
            }
          }
        }
        else {
          FUN_00403c64(piVar3,uVar1,uVar4,(int)&stack0xfffffffc);
        }
      }
      piVar3 = (int *)FUN_004038fc((int)piVar3);
      uVar4 = extraout_ECX_00;
      uVar1 = extraout_EDX_00;
    }
  }
  while ((puVar8 != &DAT_0042bb78 && (iStackY_1b80c < 0x1000))) {
    uVar4 = FUN_00403c0c((int)(puVar8 + 4));
    if ((char)uVar4 == '\0') {
      cStackY_1b805 = '\0';
      *(uint *)((int)adStackY_1f828 + iStackY_1b80c * 4) = (puVar8[3] & 0xfffffff0) - 0x14;
      iStackY_1b80c = iStackY_1b80c + 1;
    }
    puVar8 = (undefined4 *)puVar8[1];
  }
  if (cStackY_1b805 == '\0') {
    cStackY_1b80d = '\0';
    uStackY_1b81c = 0;
    uVar5 = FUN_00406eec((int)PTR_s_An_unexpected_memory_leak_has_oc_00427048);
    plVar6 = (longlong *)
             FUN_004039ec((longlong *)PTR_s_An_unexpected_memory_leak_has_oc_00427048,
                          (longlong *)adStackY_27828,uVar5);
    iStackY_1b814 = 0x37;
    puStackY_1b824 = &DAT_0042706e;
    pdStackY_1b828 = adStackY_1b008;
    do {
      uStackY_1b820 = *puStackY_1b824 - 4;
      cStackY_1b80e = '\0';
      iVar2 = 0xff;
      pdVar9 = pdStackY_1b828;
      do {
        if (alStackY_20029 < plVar6) break;
        if (*(uint *)pdVar9 != 0) {
          if (cStackY_1b80d == '\0') {
            uVar5 = FUN_00406eec((int)PTR_s_The_unexpected_small_block_leaks_0042704c);
            plVar6 = (longlong *)
                     FUN_004039ec((longlong *)PTR_s_The_unexpected_small_block_leaks_0042704c,plVar6
                                  ,uVar5);
            cStackY_1b80d = '\x01';
          }
          if (cStackY_1b80e == '\0') {
            *(undefined *)plVar6 = 0xd;
            *(undefined *)((int)plVar6 + 1) = 10;
            puVar7 = (undefined *)FUN_0040399c(uStackY_1b81c + 1,(longlong *)((int)plVar6 + 2));
            *puVar7 = 0x20;
            puVar7[1] = 0x2d;
            puVar7[2] = 0x20;
            plVar6 = (longlong *)FUN_0040399c(uStackY_1b820,(longlong *)(puVar7 + 3));
            uVar5 = FUN_00406eec((int)PTR_s__bytes__00427054);
            plVar6 = (longlong *)FUN_004039ec((longlong *)PTR_s__bytes__00427054,plVar6,uVar5);
            cStackY_1b80e = '\x01';
          }
          else {
            *(undefined *)plVar6 = 0x2c;
            *(undefined *)((int)plVar6 + 1) = 0x20;
            plVar6 = (longlong *)((int)plVar6 + 2);
          }
          if (iVar2 == 0) {
            uVar5 = FUN_00406eec((int)PTR_s_Unknown_00427058);
            puVar7 = (undefined *)FUN_004039ec((longlong *)PTR_s_Unknown_00427058,plVar6,uVar5);
          }
          else if (iVar2 == 1) {
            uVar5 = FUN_00406eec((int)PTR_s_AnsiString_0042705c);
            puVar7 = (undefined *)FUN_004039ec((longlong *)PTR_s_AnsiString_0042705c,plVar6,uVar5);
          }
          else if (iVar2 == 2) {
            uVar5 = FUN_00406eec((int)PTR_s_UnicodeString_00427060);
            puVar7 = (undefined *)
                     FUN_004039ec((longlong *)PTR_s_UnicodeString_00427060,plVar6,uVar5);
          }
          else {
            puVar7 = (undefined *)FUN_00403a04(*(uint *)((int)pdVar9 + -4),plVar6);
          }
          *puVar7 = 0x20;
          puVar7[1] = 0x78;
          puVar7[2] = 0x20;
          plVar6 = (longlong *)FUN_0040399c(*(uint *)pdVar9,(longlong *)(puVar7 + 3));
        }
        iVar2 = iVar2 + -1;
        pdVar9 = pdVar9 + -1;
      } while (iVar2 != -1);
      if (((cStackY_1b80e != '\0') || (DAT_00429ad2 == '\0')) || ((uStackY_1b820 + 4 & 0xf) == 0)) {
        uStackY_1b81c = uStackY_1b820;
      }
      pdStackY_1b828 = pdStackY_1b828 + 0x100;
      puStackY_1b824 = puStackY_1b824 + 0x10;
      iStackY_1b814 = iStackY_1b814 + -1;
    } while (iStackY_1b814 != 0);
    if (0 < iStackY_1b80c) {
      if (cStackY_1b80d != '\0') {
        *(undefined *)plVar6 = 0xd;
        *(undefined *)((int)plVar6 + 1) = 10;
        *(undefined *)((int)plVar6 + 2) = 0xd;
        *(undefined *)((int)plVar6 + 3) = 10;
        plVar6 = (longlong *)((int)plVar6 + 4);
      }
      uVar5 = FUN_00406eec((int)PTR_s_The_sizes_of_unexpected_leaked_m_00427050);
      plVar6 = (longlong *)
               FUN_004039ec((longlong *)PTR_s_The_sizes_of_unexpected_leaked_m_00427050,plVar6,uVar5
                           );
      iVar11 = 0;
      pdStackY_1b828 = adStackY_1f828;
      iVar2 = iStackY_1b80c;
      do {
        if (iVar11 != 0) {
          *(undefined *)plVar6 = 0x2c;
          *(undefined *)((int)plVar6 + 1) = 0x20;
          plVar6 = (longlong *)((int)plVar6 + 2);
        }
        plVar6 = (longlong *)FUN_0040399c(*(uint *)pdStackY_1b828,plVar6);
        if (alStackY_20029 < plVar6) break;
        iVar11 = iVar11 + 1;
        pdStackY_1b828 = (double *)((int)pdStackY_1b828 + 4);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    uVar5 = FUN_00406eec((int)PTR_DAT_00427064);
    FUN_004039ec((longlong *)PTR_DAT_00427064,plVar6,uVar5);
    FUN_00403878((LPCSTR)adStackY_27828,PTR_s_Unexpected_Memory_Leak_00427068,extraout_ECX_01);
  }
  return;
}



void FUN_0040422c(void)

{
  uint uVar1;
  ushort *puVar2;
  int iVar3;
  uint uVar4;
  
  iVar3 = 0;
  puVar2 = &DAT_0042706e;
  uVar1 = 0;
  do {
    if ((DAT_00429ad2 == '\0') || (uVar4 = uVar1, (*(byte *)puVar2 & 0xf) == 0)) {
      uVar4 = (uint)(*puVar2 >> 3);
      for (; uVar1 < uVar4; uVar1 = uVar1 + 1) {
        (&DAT_0042998c)[uVar1] = (char)iVar3 * '\x04';
      }
    }
    iVar3 = iVar3 + 1;
    puVar2 = puVar2 + 0x10;
    uVar1 = uVar4;
  } while (iVar3 != 0x37);
  return;
}



void FUN_00404270(void)

{
  ushort uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined **ppuVar4;
  int iVar5;
  
  iVar5 = 0x37;
  ppuVar4 = &PTR_LAB_00427088;
  do {
    if ((code *)*ppuVar4 == (code *)0x0) {
      *ppuVar4 = FUN_00402b3c;
    }
    ((code **)ppuVar4)[-4] = (code *)((code **)ppuVar4 + -7);
    ((code **)ppuVar4)[-5] = (code *)((code **)ppuVar4 + -7);
    ((code **)ppuVar4)[-2] = (code *)0x0;
    ((code **)ppuVar4)[-3] = (code *)0x1;
    uVar2 = ((uint)*(ushort *)((int)ppuVar4 + -0x1a) * 0xc + 0xef & 0xffffff00) + 0x30;
    if (uVar2 < 0xb30) {
      uVar2 = 0xb30;
    }
    uVar2 = uVar2 + 0x4d0 >> 0xd;
    if (7 < uVar2) {
      uVar2 = 7;
    }
    *(char *)((int)ppuVar4 + -0x1b) = (char)(0xff << ((byte)uVar2 & 0x1f));
    *(short *)((code **)ppuVar4 + -6) = (short)(uVar2 << 0xd) + 0xb30;
    uVar1 = *(ushort *)((int)ppuVar4 + -0x1a);
    uVar2 = ((uint)uVar1 * 0x30 + 0xef & 0xffffff00) + 0x30;
    if (uVar2 < 0x7330) {
      uVar2 = 0x7330;
    }
    if (0xff30 < uVar2) {
      uVar2 = 0xff30;
    }
    *(ushort *)((int)ppuVar4 + -0x16) =
         (uVar1 * (short)((ulonglong)(uVar2 - 0x20) / (ulonglong)uVar1) + 0xef & 0xff00) + 0x30;
    ppuVar4 = (code **)ppuVar4 + 8;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  FUN_0040422c();
  DAT_00429ad4 = &DAT_00429ad4;
  DAT_00429ad8 = &DAT_00429ad4;
  iVar5 = 0x400;
  puVar3 = &DAT_00429b74;
  do {
    *puVar3 = puVar3;
    puVar3[1] = puVar3;
    puVar3 = puVar3 + 2;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  DAT_0042bb78 = &DAT_0042bb78;
  DAT_0042bb7c = &DAT_0042bb78;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040439c(void)

{
  undefined4 *puVar1;
  undefined *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  puVar3 = DAT_00429ad8;
  while ((undefined4 **)puVar3 != &DAT_00429ad4) {
    puVar1 = (undefined4 *)puVar3[1];
    VirtualFree(puVar3,0,0x8000);
    puVar3 = puVar1;
  }
  iVar4 = 0x37;
  puVar2 = &DAT_0042706c;
  do {
    *(undefined **)(puVar2 + 0xc) = puVar2;
    *(undefined **)(puVar2 + 8) = puVar2;
    *(undefined4 *)(puVar2 + 0x10) = 1;
    *(undefined4 *)(puVar2 + 0x14) = 0;
    puVar2 = puVar2 + 0x20;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  DAT_00429ad4 = &DAT_00429ad4;
  DAT_00429ad8 = &DAT_00429ad4;
  iVar4 = 0x400;
  puVar3 = &DAT_00429b74;
  do {
    *puVar3 = puVar3;
    puVar3[1] = puVar3;
    puVar3 = puVar3 + 2;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  _DAT_00429af0 = 0;
  FUN_004048f8((double *)&DAT_00429af4,0x80,0);
  DAT_00429aec = 0;
  puVar3 = DAT_0042bb7c;
  while ((undefined4 **)puVar3 != &DAT_0042bb78) {
    puVar1 = (undefined4 *)puVar3[1];
    VirtualFree(puVar3,0,0x8000);
    puVar3 = puVar1;
  }
  DAT_0042bb78 = &DAT_0042bb78;
  DAT_0042bb7c = &DAT_0042bb78;
  return;
}



void FUN_0040444c(void)

{
  if (DAT_0042bb90 != (HANDLE)0x0) {
    CloseHandle(DAT_0042bb90);
    DAT_0042bb90 = (HANDLE)0x0;
  }
  if (DAT_00429984 != '\0') {
    FUN_00403e20();
  }
  if (DAT_0042bb88 != (LPVOID)0x0) {
    VirtualFree(DAT_0042bb88,0,0x8000);
    DAT_0042bb88 = (LPVOID)0x0;
  }
  FUN_0040439c();
  return;
}



void FUN_004044a0(int param_1)

{
  int iVar1;
  
  if (param_1 != 0) {
    iVar1 = (*(code *)PTR_FUN_00427758)();
    if (iVar1 == 0) {
      FUN_004045f4(1);
      return;
    }
  }
  return;
}



int FUN_004044b8(int param_1)

{
  int iVar1;
  
  if (param_1 < 1) {
    return 0;
  }
  iVar1 = (*(code *)PTR_FUN_0042774c)();
  if (iVar1 != 0) {
    return iVar1;
  }
  iVar1 = FUN_004045f4(1);
  return iVar1;
}



void FUN_004044d4(int param_1)

{
  int iVar1;
  
  if (param_1 != 0) {
    iVar1 = (*(code *)PTR_FUN_00427750)();
    if (iVar1 != 0) {
      FUN_004045f4(2);
      return;
    }
  }
  return;
}



void FUN_004044ec(int *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *param_1;
  if (iVar1 != 0) {
    if (param_2 == 0) {
      *param_1 = 0;
      iVar1 = (*(code *)PTR_FUN_00427750)(iVar1);
      if (iVar1 == 0) {
        return;
      }
      FUN_004045f4(2);
      return;
    }
    iVar1 = (*(code *)PTR_FUN_00427754)(iVar1);
    if (iVar1 != 0) {
      *param_1 = iVar1;
      return;
    }
LAB_0040451d:
    FUN_004045f4(1);
    return;
  }
  if (param_2 != 0) {
    iVar1 = (*(code *)PTR_FUN_0042774c)(param_2);
    if (iVar1 == 0) goto LAB_0040451d;
    *param_1 = iVar1;
  }
  return;
}



undefined4 FUN_0040453c(void)

{
  int *piVar1;
  
  piVar1 = (int *)FUN_0040ae54();
  if (*piVar1 != 0) {
    piVar1 = (int *)FUN_0040ae54();
    return *(undefined4 *)(*piVar1 + 8);
  }
  return 0;
}



undefined4 FUN_0040455c(void)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  
  piVar2 = (int *)FUN_0040ae54();
  iVar1 = *piVar2;
  if (iVar1 == 0) {
    uVar3 = 0;
  }
  else {
    uVar3 = *(undefined4 *)(iVar1 + 8);
    *(undefined4 *)(iVar1 + 8) = 0;
    if (DAT_00429028 != (code *)0x0) {
      (*DAT_00429028)(uVar3);
    }
  }
  return uVar3;
}



undefined4 FUN_00404590(void)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0040ae54();
  return *puVar1;
}



void FUN_0040459c(undefined4 param_1,undefined4 param_2)

{
  DAT_00427004 = param_2;
  FUN_00406a30(param_1);
  return;
}



void FUN_004045a8(uint param_1,undefined4 param_2)

{
  LPVOID pvVar1;
  uint uVar2;
  
  uVar2 = param_1 & 0xffffff7f;
  if (DAT_00429010 != (code *)0x0) {
    (*DAT_00429010)(uVar2,param_2);
  }
  if ((byte)uVar2 == 0) {
    pvVar1 = FUN_0040ae54();
    uVar2 = *(uint *)((int)pvVar1 + 4);
  }
  else if ((byte)uVar2 < 0x1d) {
    uVar2 = (uint)(byte)(&DAT_00427764)[param_1 & 0x7f];
  }
  FUN_0040459c(uVar2 & 0xff,param_2);
  return;
}



void FUN_004045f4(byte param_1)

{
  undefined4 in_stack_00000000;
  
  FUN_004045a8((uint)param_1,in_stack_00000000);
  return;
}



void FUN_0040460c(void)

{
  LPVOID pvVar1;
  
  pvVar1 = FUN_0040ae54();
  if (*(int *)((int)pvVar1 + 4) == 0) {
    return;
  }
  FUN_004045f4(0);
  return;
}



void FUN_0040462c(undefined4 param_1)

{
  LPVOID pvVar1;
  
  pvVar1 = FUN_0040ae54();
  *(undefined4 *)((int)pvVar1 + 4) = param_1;
  return;
}



undefined4 FUN_0040463c(void)

{
  undefined4 uVar1;
  LPVOID pvVar2;
  
  pvVar2 = FUN_0040ae54();
  uVar1 = *(undefined4 *)((int)pvVar2 + 4);
  pvVar2 = FUN_0040ae54();
  *(undefined4 *)((int)pvVar2 + 4) = 0;
  return uVar1;
}



void FUN_0040465c(longlong *param_1,longlong *param_2,uint param_3)

{
  longlong *plVar1;
  longlong lVar2;
  longlong lVar3;
  longlong lVar4;
  undefined uVar5;
  undefined2 uVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  longlong *plVar11;
  bool bVar12;
  
  if (param_1 != param_2) {
    if (0x20 < param_3) {
      if (0x20 < (int)param_3) {
        if ((param_2 < param_1) ||
           (plVar11 = (longlong *)((int)param_2 - param_3),
           param_2 = (longlong *)(param_3 + (int)plVar11), param_1 <= plVar11)) {
          lVar2 = *param_1;
          plVar11 = (longlong *)((param_3 - 8) + (int)param_1);
          plVar1 = (longlong *)((int)param_2 + (param_3 - 8));
          lVar3 = *plVar11;
          iVar8 = (((uint)param_2 & 0xfffffff8) + 8) - (int)plVar1;
          do {
            *(longlong *)(iVar8 + (int)plVar1) =
                 (longlong)ROUND((float10)*(longlong *)(iVar8 + (int)plVar11));
            bVar12 = SCARRY4(iVar8,8);
            iVar8 = iVar8 + 8;
          } while (bVar12 != iVar8 < 0);
          *plVar1 = (longlong)ROUND((float10)lVar3);
          *param_2 = (longlong)ROUND((float10)lVar2);
          return;
        }
        iVar9 = param_3 - 8;
        lVar2 = *(longlong *)(iVar9 + (int)param_1);
        lVar3 = *param_1;
        iVar8 = (iVar9 + (int)param_2 & 0xfffffff8U) - (int)param_2;
        do {
          *(longlong *)(iVar8 + (int)param_2) =
               (longlong)ROUND((float10)*(longlong *)(iVar8 + (int)param_1));
          iVar10 = iVar8 + -8;
          bVar12 = 7 < iVar8;
          iVar8 = iVar10;
        } while (iVar10 != 0 && bVar12);
        *param_2 = (longlong)ROUND((float10)lVar3);
        *(longlong *)(iVar9 + (int)param_2) = (longlong)ROUND((float10)lVar2);
      }
      return;
    }
    iVar8 = param_3 - 8;
    if (iVar8 == 0 || (int)param_3 < 8) {
                    // WARNING (jumptable): Sanity check requires truncation of jumptable
                    // WARNING: Could not find normalized switch variable to match jumptable
      switch(param_3) {
      case 1:
        *(undefined *)param_2 = *(undefined *)param_1;
        return;
      case 2:
        *(undefined2 *)param_2 = *(undefined2 *)param_1;
        return;
      case 3:
        uVar5 = *(undefined *)((int)param_1 + 2);
        *(undefined2 *)param_2 = *(undefined2 *)param_1;
        *(undefined *)((int)param_2 + 2) = uVar5;
        return;
      case 4:
        *(undefined4 *)param_2 = *(undefined4 *)param_1;
        return;
      case 5:
        uVar5 = *(undefined *)((int)param_1 + 4);
        *(undefined4 *)param_2 = *(undefined4 *)param_1;
        *(undefined *)((int)param_2 + 4) = uVar5;
        return;
      case 6:
        uVar6 = *(undefined2 *)((int)param_1 + 4);
        *(undefined4 *)param_2 = *(undefined4 *)param_1;
        *(undefined2 *)((int)param_2 + 4) = uVar6;
        return;
      case 7:
        uVar7 = *(undefined4 *)((int)param_1 + 3);
        *(undefined4 *)param_2 = *(undefined4 *)param_1;
        *(undefined4 *)((int)param_2 + 3) = uVar7;
        return;
      case 8:
        *param_2 = (longlong)ROUND((float10)*param_1);
        return;
      }
    }
    else {
      lVar2 = *(longlong *)(iVar8 + (int)param_1);
      lVar3 = *param_1;
      if (8 < iVar8) {
        lVar4 = param_1[1];
        if (0x10 < iVar8) {
          param_2[2] = (longlong)ROUND((float10)param_1[2]);
        }
        param_2[1] = (longlong)ROUND((float10)lVar4);
      }
      *param_2 = (longlong)ROUND((float10)lVar3);
      *(longlong *)(iVar8 + (int)param_2) = (longlong)ROUND((float10)lVar2);
    }
  }
  return;
}



void FUN_0040475c(undefined param_1,undefined param_2,undefined param_3,uint param_4,uint param_5)

{
  DAT_00427008 = param_4 ^ param_5;
  return;
}



void FUN_00404778(void)

{
  BOOL BVar1;
  LARGE_INTEGER local_8;
  
  BVar1 = QueryPerformanceCounter(&local_8);
  if (BVar1 == 0) {
    local_8.s.LowPart = GetTickCount();
    local_8.s.HighPart = 0;
  }
  FUN_004047c8(0x7fffffff);
  (*(code *)PTR_FUN_0042702c)();
  return;
}



void FUN_004047b4(void)

{
  DAT_00427008 = DAT_00427008 * 0x8088405 + 1;
  return;
}



undefined4 FUN_004047c8(uint param_1)

{
  uint uVar1;
  
  uVar1 = (*(code *)PTR_FUN_00427028)();
  return (int)((ulonglong)uVar1 * (ulonglong)param_1 >> 0x20);
}



void FUN_004047d8(undefined2 param_1)

{
  DAT_0042701c = param_1;
  return;
}



undefined2 FUN_004047e8(void)

{
  undefined2 in_FPUControlWord;
  
  return in_FPUControlWord;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004047f0(void)

{
  undefined4 uVar1;
  undefined4 in_MXCSR;
  
  uVar1 = 0;
  if (_DAT_00429058 != 0) {
    uVar1 = in_MXCSR;
  }
  return uVar1;
}



undefined4 FUN_00404804(void)

{
  float10 in_ST0;
  undefined4 local_8;
  
  local_8 = (undefined4)(longlong)ROUND(in_ST0);
  return local_8;
}



int FUN_0040484c(undefined *param_1,undefined *param_2)

{
  ushort uVar1;
  int iVar2;
  
  if ((ushort)(*(short *)(param_1 + 4) + 0x284fU) == 0) {
    iVar2 = 0;
  }
  else {
    iVar2 = (ushort)(*(short *)(param_1 + 4) + 0x284fU) - 1;
    uVar1 = (ushort)iVar2;
    if (uVar1 < 2) {
      iVar2 = (*(code *)param_2)(param_1,param_2,CONCAT22((short)((uint)iVar2 >> 0x10),uVar1 - 2));
    }
    else if ((param_1 == &DAT_0042933c) || (param_1 == &DAT_00429618)) {
      iVar2 = 0;
    }
    else {
      iVar2 = 0x67;
    }
  }
  if (iVar2 != 0) {
    FUN_0040462c(iVar2);
  }
  return iVar2;
}



void FUN_00404894(undefined *param_1)

{
  FUN_0040484c(param_1,*(undefined **)(param_1 + 0x1c));
  return;
}



int FUN_004048a0(undefined *param_1)

{
  ushort uVar1;
  int iVar2;
  
  iVar2 = 0;
  uVar1 = *(ushort *)(param_1 + 4);
  if ((uVar1 < 0xd7b1) || (0xd7b3 < uVar1)) {
    if (param_1 != &DAT_00429060) {
      FUN_0040462c(0x67);
    }
  }
  else {
    if ((uVar1 & 0xd7b2) == 0xd7b2) {
      iVar2 = (**(code **)(param_1 + 0x1c))(param_1);
    }
    if (iVar2 == 0) {
      iVar2 = (**(code **)(param_1 + 0x24))(param_1);
    }
    if (iVar2 != 0) {
      FUN_0040462c(iVar2);
    }
  }
  return iVar2;
}



void FUN_004048f8(double *param_1,int param_2,undefined param_3)

{
  double dVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  bool bVar5;
  
  uVar2 = CONCAT11(param_3,param_3);
  if (0x1f < param_2) {
    *(undefined2 *)param_1 = uVar2;
    *(undefined2 *)((int)param_1 + 2) = uVar2;
    *(undefined2 *)((int)param_1 + 4) = uVar2;
    *(undefined2 *)((int)param_1 + 6) = uVar2;
    dVar1 = *param_1;
    *(double *)(param_2 + -0x10 + (int)param_1) = dVar1;
    *(double *)(param_2 + -8 + (int)param_1) = dVar1;
    iVar3 = ((uint)param_1 & 7) - 8;
    iVar4 = param_2 + -0x10 + iVar3;
    iVar3 = iVar4 - iVar3;
    iVar4 = -iVar4;
    do {
      *(double *)((int)param_1 + iVar4 + iVar3) = dVar1;
      *(double *)((int)param_1 + iVar4 + 8 + iVar3) = dVar1;
      bVar5 = SCARRY4(iVar4,0x10);
      iVar4 = iVar4 + 0x10;
    } while (bVar5 != iVar4 < 0);
    ffree((float10)dVar1);
    return;
  }
  *(undefined *)(param_2 + -1 + (int)param_1) = param_3;
  switch(param_2) {
  default:
    return;
  case 0x1e:
  case 0x1f:
    *(undefined2 *)((int)param_1 + 0x1c) = uVar2;
  case 0x1c:
  case 0x1d:
    *(undefined2 *)((int)param_1 + 0x1a) = uVar2;
  case 0x1a:
  case 0x1b:
    *(undefined2 *)(param_1 + 3) = uVar2;
  case 0x18:
  case 0x19:
    *(undefined2 *)((int)param_1 + 0x16) = uVar2;
  case 0x16:
  case 0x17:
    *(undefined2 *)((int)param_1 + 0x14) = uVar2;
  case 0x14:
  case 0x15:
    *(undefined2 *)((int)param_1 + 0x12) = uVar2;
  case 0x12:
  case 0x13:
    *(undefined2 *)(param_1 + 2) = uVar2;
  case 0x10:
  case 0x11:
    *(undefined2 *)((int)param_1 + 0xe) = uVar2;
  case 0xe:
  case 0xf:
    *(undefined2 *)((int)param_1 + 0xc) = uVar2;
  case 0xc:
  case 0xd:
    *(undefined2 *)((int)param_1 + 10) = uVar2;
  case 10:
  case 0xb:
    *(undefined2 *)(param_1 + 1) = uVar2;
  case 8:
  case 9:
    *(undefined2 *)((int)param_1 + 6) = uVar2;
  case 6:
  case 7:
    *(undefined2 *)((int)param_1 + 4) = uVar2;
  case 4:
  case 5:
    *(undefined2 *)((int)param_1 + 2) = uVar2;
  case 2:
  case 3:
    *(undefined2 *)param_1 = uVar2;
    return;
  }
}



ushort * FUN_00404994(ushort *param_1,uint *param_2)

{
  ushort *puVar1;
  ushort *puVar2;
  ushort uVar3;
  ushort uVar4;
  ushort *puVar5;
  uint uVar6;
  bool bVar7;
  
  puVar1 = param_1;
  puVar5 = param_1;
  if (param_1 == (ushort *)0x0) {
LAB_00404a25:
    puVar5 = puVar5 + 1;
  }
  else {
    puVar1 = (ushort *)0x0;
    do {
      puVar2 = puVar5;
      uVar3 = *puVar2;
      puVar5 = puVar2 + 1;
    } while (uVar3 == 0x20);
    bVar7 = false;
    if (uVar3 == 0x2d) {
      bVar7 = true;
LAB_00404a37:
      uVar3 = *puVar5;
      puVar5 = puVar2 + 2;
    }
    else if (uVar3 == 0x2b) goto LAB_00404a37;
    if (((uVar3 == 0x24) || (uVar3 == 0x78)) || (uVar3 == 0x58)) {
LAB_00404a3f:
      uVar3 = *puVar5;
      puVar5 = puVar5 + 1;
      puVar2 = puVar1;
      if (uVar3 != 0) {
        do {
          if (0x60 < uVar3) {
            uVar3 = uVar3 - 0x20;
          }
          uVar4 = uVar3 - 0x30;
          puVar1 = puVar2;
          if (9 < uVar4) {
            if (5 < (ushort)(uVar3 - 0x41)) goto LAB_00404a30;
            uVar4 = uVar3 - 0x37;
          }
          if ((ushort *)0xfffffff < puVar2) goto LAB_00404a30;
          puVar2 = (ushort *)((int)puVar2 * 0x10 + (uint)uVar4);
          uVar3 = *puVar5;
          puVar5 = puVar5 + 1;
        } while (uVar3 != 0);
        if (bVar7) {
          puVar2 = (ushort *)-(int)puVar2;
        }
LAB_00404a8b:
        uVar6 = 0;
        goto LAB_00404a8e;
      }
      goto LAB_00404a25;
    }
    if (uVar3 != 0x30) {
      if (uVar3 != 0) goto LAB_004049fb;
      goto LAB_00404a30;
    }
    uVar3 = *puVar5;
    puVar5 = puVar5 + 1;
    if ((uVar3 == 0x78) || (uVar3 == 0x58)) goto LAB_00404a3f;
    while (uVar3 != 0) {
LAB_004049fb:
      if ((9 < (ushort)(uVar3 - 0x30)) || ((ushort *)0xccccccc < puVar1)) goto LAB_00404a30;
      puVar1 = (ushort *)((int)puVar1 * 10 + (uint)(ushort)(uVar3 - 0x30));
      uVar3 = *puVar5;
      puVar5 = puVar5 + 1;
    }
    if (bVar7) {
      puVar2 = (ushort *)-(int)puVar1;
      bVar7 = 0 < (int)puVar1;
      if ((puVar2 == (ushort *)0x0 || bVar7) || (puVar1 = puVar2, bVar7)) goto LAB_00404a8b;
    }
    else {
      puVar2 = puVar1;
      if (-1 < (int)puVar1) goto LAB_00404a8b;
    }
  }
LAB_00404a30:
  uVar6 = (int)puVar5 - (int)param_1;
  puVar2 = puVar1;
LAB_00404a8e:
  *param_2 = uVar6 >> 1;
  return puVar2;
}



void thunk_FUN_00404aa0(void)

{
  return;
}



void FUN_00404aa0(void)

{
  return;
}



void FUN_00404b54(int param_1,undefined4 param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  
  if (param_1 == 0) {
    puVar1 = (undefined4 *)cpuid_basic_info(0);
  }
  else if (param_1 == 1) {
    puVar1 = (undefined4 *)cpuid_Version_info(1);
  }
  else if (param_1 == 2) {
    puVar1 = (undefined4 *)cpuid_cache_tlb_info(2);
  }
  else if (param_1 == 3) {
    puVar1 = (undefined4 *)cpuid_serial_info(3);
  }
  else if (param_1 == 4) {
    puVar1 = (undefined4 *)cpuid_Deterministic_Cache_Parameters_info(4);
  }
  else if (param_1 == 5) {
    puVar1 = (undefined4 *)cpuid_MONITOR_MWAIT_Features_info(5);
  }
  else if (param_1 == 6) {
    puVar1 = (undefined4 *)cpuid_Thermal_Power_Management_info(6);
  }
  else if (param_1 == 7) {
    puVar1 = (undefined4 *)cpuid_Extended_Feature_Enumeration_info(7);
  }
  else if (param_1 == 9) {
    puVar1 = (undefined4 *)cpuid_Direct_Cache_Access_info(9);
  }
  else if (param_1 == 10) {
    puVar1 = (undefined4 *)cpuid_Architectural_Performance_Monitoring_info(10);
  }
  else if (param_1 == 0xb) {
    puVar1 = (undefined4 *)cpuid_Extended_Topology_info(0xb);
  }
  else if (param_1 == 0xd) {
    puVar1 = (undefined4 *)cpuid_Processor_Extended_States_info(0xd);
  }
  else if (param_1 == 0xf) {
    puVar1 = (undefined4 *)cpuid_Quality_of_Service_info(0xf);
  }
  else if (param_1 == -0x7ffffffe) {
    puVar1 = (undefined4 *)cpuid_brand_part1_info(0x80000002);
  }
  else if (param_1 == -0x7ffffffd) {
    puVar1 = (undefined4 *)cpuid_brand_part2_info(0x80000003);
  }
  else if (param_1 == -0x7ffffffc) {
    puVar1 = (undefined4 *)cpuid_brand_part3_info(0x80000004);
  }
  else {
    puVar1 = (undefined4 *)cpuid(param_1);
  }
  uVar4 = puVar1[1];
  uVar3 = puVar1[2];
  uVar2 = puVar1[3];
  *param_3 = *puVar1;
  param_3[1] = uVar4;
  param_3[2] = uVar2;
  param_3[3] = uVar3;
  return;
}



void FUN_00404b6c(void)

{
  uint uVar1;
  byte in_CF;
  byte in_PF;
  byte in_AF;
  byte in_ZF;
  byte in_SF;
  byte in_TF;
  byte in_IF;
  byte in_OF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  uint uVar2;
  
  uVar2 = (uint)(in_NT & 1) * 0x4000 | (uint)(in_OF & 1) * 0x800 | (uint)(in_IF & 1) * 0x200 |
          (uint)(in_TF & 1) * 0x100 | (uint)(in_SF & 1) * 0x80 | (uint)(in_ZF & 1) * 0x40 |
          (uint)(in_AF & 1) * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(in_CF & 1) |
          (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 |
          (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  uVar1 = uVar2 ^ 0x200000;
  DAT_004279ba = ((uint)((uVar1 & 0x4000) != 0) * 0x4000 | (uint)((uVar1 & 0x800) != 0) * 0x800 |
                  (uint)((uVar1 & 0x400) != 0) * 0x400 | (uint)((uVar1 & 0x200) != 0) * 0x200 |
                  (uint)((uVar1 & 0x100) != 0) * 0x100 | (uint)((uVar1 & 0x80) != 0) * 0x80 |
                  (uint)((uVar1 & 0x40) != 0) * 0x40 | (uint)((uVar1 & 0x10) != 0) * 0x10 |
                  (uint)((uVar1 & 4) != 0) * 4 | (uint)((uVar1 & 1) != 0) |
                  (uint)((uVar1 & 0x200000) != 0) * 0x200000 |
                 (uint)((uVar1 & 0x40000) != 0) * 0x40000) != uVar2;
  return;
}



void FUN_00404b90(int param_1,undefined4 param_2,undefined4 *param_3)

{
  if (DAT_004279ba == '\0') {
    *param_3 = 0;
    param_3[1] = 0;
    param_3[2] = 0;
    param_3[3] = 0;
  }
  else {
    FUN_00404b54(param_1,param_2,param_3);
  }
  return;
}



byte FUN_00404bc8(void)

{
  byte bVar1;
  
  bVar1 = (DAT_00429914 & 0x2000000) != 0;
  if ((DAT_00429914 & 0x4000000) != 0) {
    bVar1 = bVar1 | 2;
  }
  return bVar1;
}



void FUN_00404be8(void)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  byte bVar4;
  undefined4 auStack_17f8 [1531];
  
  bVar4 = 0;
  FUN_00404b6c();
  iVar2 = 0;
  puVar1 = &DAT_004298f8;
  do {
    FUN_00404b90(iVar2,0,auStack_17f8 + 0x5f7);
    puVar3 = puVar1 + (uint)bVar4 * -2 + 1;
    *puVar1 = auStack_17f8[1527];
    *puVar3 = auStack_17f8[(uint)bVar4 * -2 + 0x5f8];
    puVar3[(uint)bVar4 * -2 + 1] = auStack_17f8[(uint)bVar4 * -2 + (uint)bVar4 * -2 + 0x5f9];
    (puVar3 + (uint)bVar4 * -2 + 1)[(uint)bVar4 * -2 + 1] =
         (auStack_17f8 + (uint)bVar4 * -2 + (uint)bVar4 * -2 + 0x5f9)[(uint)bVar4 * -2 + 1];
    iVar2 = iVar2 + 1;
    puVar1 = puVar1 + 4;
  } while (iVar2 != 8);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00404c24(void)

{
  byte bVar1;
  undefined3 extraout_var;
  uint uVar2;
  
  bVar1 = FUN_00404bc8();
  _DAT_00429058 = CONCAT31(extraout_var,bVar1);
  uVar2 = FUN_004047f0();
  _DAT_00427020 = uVar2 & 0xffc0;
  return;
}



void FUN_00404c40(void)

{
  return;
}



void thunk_FUN_004045f4(byte param_1)

{
  FUN_004045f4(5);
  return;
}



void FUN_00404c5c(int param_1,longlong **param_2)

{
  FUN_0040ab28(*(byte **)(param_1 + -0x38),param_2);
  return;
}



void FUN_00404dc4(int *param_1,char param_2,undefined4 param_3)

{
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_00000000;
  undefined4 in_stack_fffffff0;
  undefined4 in_stack_fffffff4;
  undefined4 in_stack_fffffff8;
  undefined4 in_stack_fffffffc;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00405424((int)param_1,param_2,param_3,in_stack_fffffff0,in_stack_fffffff4,
                                  in_stack_fffffff8,in_stack_fffffffc);
    param_2 = extraout_DL;
  }
  if (param_2 != '\0') {
    FUN_0040547c(param_1);
    *in_FS_OFFSET = in_stack_00000000;
  }
  return;
}



void FUN_00404de4(int *param_1,char param_2)

{
  int *piVar1;
  char extraout_DL;
  
  piVar1 = FUN_004054cc(param_1,param_2);
  if ('\0' < extraout_DL) {
    FUN_00405474(piVar1);
  }
  return;
}



void FUN_00404df4(int *param_1)

{
  if (param_1 != (int *)0x0) {
    (**(code **)(*param_1 + -4))(param_1,1);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00404e7d)
// WARNING: Removing unreachable block (ram,0x00404e45)
// WARNING: Removing unreachable block (ram,0x00404e4b)
// WARNING: Removing unreachable block (ram,0x00404e52)
// WARNING: Removing unreachable block (ram,0x00404e58)
// WARNING: Removing unreachable block (ram,0x00404e5e)

void FUN_00404e10(int param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  int *piVar3;
  
  *param_2 = param_1;
  uVar2 = *(uint *)(param_1 + -0x34);
  uVar1 = uVar2 >> 2;
  piVar3 = param_2 + 1;
  while (uVar1 = uVar1 - 1, uVar1 != 0) {
    *piVar3 = 0;
    piVar3 = piVar3 + 1;
  }
  for (uVar2 = uVar2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
    *(undefined *)piVar3 = 0;
    piVar3 = (int *)((int)piVar3 + 1);
  }
  for (; *(int **)(param_1 + -0x30) != (int *)0x0; param_1 = **(int **)(param_1 + -0x30)) {
  }
  do {
    param_2 = *(int **)(*param_2 + -0x30);
  } while (param_2 != (int *)0x0);
  return;
}



void FUN_00404e90(int *param_1)

{
  int iVar1;
  char *pcVar2;
  int *piVar3;
  int *piVar4;
  
  piVar4 = param_1;
  do {
    piVar3 = param_1;
    if (piVar4 == (int *)0x0) goto LAB_00404eb0;
    iVar1 = *piVar4;
    piVar4 = *(int **)(iVar1 + -0x30);
  } while (*(int *)(iVar1 + -0x54) == 0);
  FUN_0040a880(param_1);
LAB_00404eb0:
  do {
    pcVar2 = *(char **)(*piVar3 + -0x4c);
    piVar3 = *(int **)(*piVar3 + -0x30);
    if (pcVar2 != (char *)0x0) {
      FUN_004078e0((int)param_1,pcVar2);
    }
  } while (piVar3 != (int *)0x0);
  FUN_0040570c(param_1);
  return;
}



undefined4 FUN_00405108(int *param_1,int param_2)

{
  int *piVar1;
  
  if (param_1 != (int *)0x0) {
    piVar1 = thunk_FUN_004051ac(*param_1,param_2);
    if ((char)piVar1 != '\0') {
      return CONCAT31((int3)((uint)piVar1 >> 8),1);
    }
  }
  return 0;
}



int * FUN_0040512c(int *param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 in_stack_00000000;
  
  if (param_1 != (int *)0x0) {
    uVar1 = FUN_00405108(param_1,param_2);
    if ((char)uVar1 == '\0') {
      FUN_004045a8(CONCAT31((int3)((uint)uVar1 >> 8),10),in_stack_00000000);
    }
  }
  return param_1;
}



void FUN_0040515c(int **param_1,int param_2)

{
  int *piStack_8;
  int iStack_4;
  
  piStack_8 = (int *)0x0;
  iStack_4 = param_2;
  FUN_004095b4(&piStack_8,param_1);
  FUN_0040512c(piStack_8,iStack_4);
  return;
}



undefined4 FUN_00405178(int param_1,ushort param_2)

{
  ushort *puVar1;
  uint uVar2;
  ushort *puVar3;
  ushort *puVar4;
  bool bVar5;
  
  do {
    puVar1 = *(ushort **)(param_1 + -0x3c);
    if (puVar1 != (ushort *)0x0) {
      bVar5 = puVar1 + 1 == (ushort *)0x0;
      uVar2 = (uint)*puVar1;
      puVar3 = puVar1 + 1;
      do {
        puVar4 = puVar3;
        if (uVar2 == 0) break;
        uVar2 = uVar2 - 1;
        puVar4 = puVar3 + 1;
        bVar5 = param_2 == *puVar3;
        puVar3 = puVar4;
      } while (!bVar5);
      if (bVar5) {
        return *(undefined4 *)(puVar4 + ((uint)*puVar1 * 2 - uVar2) + -2);
      }
    }
    if (*(int **)(param_1 + -0x30) == (int *)0x0) {
      return 0;
    }
    param_1 = **(int **)(param_1 + -0x30);
  } while( true );
}



int * thunk_FUN_004051ac(int param_1,int param_2)

{
  int *piVar1;
  
  while( true ) {
    if (param_1 == param_2) {
      return (int *)CONCAT31((int3)((uint)param_1 >> 8),1);
    }
    piVar1 = *(int **)(param_1 + -0x30);
    if (piVar1 == (int *)0x0) break;
    param_1 = *piVar1;
  }
  return piVar1;
}



int * FUN_004051ac(int param_1,int param_2)

{
  int *piVar1;
  
  while( true ) {
    if (param_1 == param_2) {
      return (int *)CONCAT31((int3)((uint)param_1 >> 8),1);
    }
    piVar1 = *(int **)(param_1 + -0x30);
    if (piVar1 == (int *)0x0) break;
    param_1 = *piVar1;
  }
  return piVar1;
}



bool FUN_00405218(byte *param_1,byte *param_2)

{
  int iVar1;
  int cchCount2;
  WCHAR local_408 [256];
  WCHAR local_208 [256];
  
  iVar1 = MultiByteToWideChar(0xfde9,0,(LPCSTR)(param_1 + 1),(uint)*param_1,local_408,0x100);
  cchCount2 = MultiByteToWideChar(0xfde9,0,(LPCSTR)(param_2 + 1),(uint)*param_2,local_208,0x100);
  iVar1 = CompareStringW(DAT_00429980,1,local_408,iVar1,local_208,cchCount2);
  return iVar1 == 2;
}



int FUN_00405388(int *param_1,byte *param_2)

{
  int iVar1;
  undefined2 *puVar2;
  bool bVar3;
  int *piVar4;
  int iVar5;
  byte bVar6;
  int iVar7;
  
  iVar5 = 0;
  iVar7 = 0;
  bVar6 = *param_2;
  piVar4 = param_1;
  do {
    iVar1 = *piVar4;
    puVar2 = *(undefined2 **)(iVar1 + -0x44);
    if ((puVar2 != (undefined2 *)0x0) &&
       (iVar7 = CONCAT22((short)((uint)iVar7 >> 0x10),*puVar2), iVar7 != 0)) {
      piVar4 = (int *)(puVar2 + 3);
      do {
        iVar5 = CONCAT31((int3)((uint)iVar5 >> 8),*(byte *)((int)piVar4 + 6));
        if (*(byte *)((int)piVar4 + 6) == bVar6) {
          while ((bVar6 = *(byte *)(iVar5 + 6 + (int)piVar4), (bVar6 & 0x80) == 0 &&
                 (bVar6 = bVar6 ^ param_2[iVar5], (bVar6 & 0x80) == 0))) {
            if ((bVar6 & 0xdf) != 0) goto LAB_004053bd;
            iVar5 = iVar5 + -1;
            if (iVar5 == 0) goto LAB_004053f1;
          }
          bVar3 = FUN_00405218((byte *)((int)piVar4 + 6),param_2);
          iVar5 = 0;
          if (bVar3) {
LAB_004053f1:
            return *piVar4 + (int)param_1;
          }
LAB_004053bd:
          bVar6 = *param_2;
          iVar5 = CONCAT31((int3)((uint)iVar5 >> 8),*(undefined *)((int)piVar4 + 6));
        }
        piVar4 = (int *)(iVar5 + 7 + (int)piVar4);
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
    piVar4 = *(int **)(iVar1 + -0x30);
    if (piVar4 == (int *)0x0) {
      return 0;
    }
  } while( true );
}



// WARNING: Variable defined which should be unmapped: param_6

void FUN_00405424(int param_1,char param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
                 undefined4 param_6,undefined4 param_7)

{
  int *in_FS_OFFSET;
  
  if (-1 < param_2) {
    (**(code **)(param_1 + -0xc))();
  }
  *in_FS_OFFSET = (int)&param_4;
  return;
}



void FUN_00405474(int *param_1)

{
  (**(code **)(*param_1 + -8))();
  return;
}



int * FUN_0040547c(int *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  
  puStack_18 = &stack0xfffffffc;
  puStack_1c = &LAB_004054ab;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  (**(code **)(*param_1 + -0x1c))();
  *in_FS_OFFSET = uStack_20;
  return param_1;
}



int * FUN_004054cc(int *param_1,char param_2)

{
  if (param_2 < '\x01') {
    return param_1;
  }
  (**(code **)(*param_1 + -0x18))();
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004054dc(int *param_1)

{
  int iVar1;
  
  iVar1 = *param_1;
  if ((iVar1 < 0xb) && (1 < _DAT_0042905c)) {
    FUN_00405588(4 << ((byte)iVar1 & 0x1f));
  }
  else {
    if (9 < iVar1) {
      iVar1 = iVar1 + -10;
    }
    if (iVar1 % 0x14 == 0x13) {
      Sleep(1);
    }
    else if (iVar1 % 5 == 4) {
      Sleep(0);
    }
    else {
      SwitchToThread();
    }
  }
  *param_1 = *param_1 + 1;
  if (*param_1 < 0) {
    *param_1 = 10;
  }
  return;
}



void FUN_00405554(int *param_1)

{
  int iVar1;
  int local_8;
  
  local_8 = 0;
  do {
    if (*param_1 == 0) {
      LOCK();
      if (*param_1 == 0) {
        *param_1 = 1;
        iVar1 = 0;
      }
      else {
        iVar1 = *param_1;
      }
      UNLOCK();
      if (iVar1 == 0) {
        return;
      }
    }
    FUN_004054dc(&local_8);
  } while( true );
}



void FUN_00405580(undefined4 *param_1)

{
  LOCK();
  *param_1 = 0;
  UNLOCK();
  return;
}



void FUN_00405588(int param_1)

{
  if (0 < param_1) {
    do {
      param_1 = param_1 + -1;
    } while (0 < param_1);
  }
  return;
}



uint FUN_00405598(void)

{
  ushort uVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  BOOL BVar3;
  DWORD DVar4;
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION p_Var5;
  uint uVar6;
  undefined extraout_CL;
  undefined extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar7;
  undefined *puVar8;
  char *lpProcName;
  DWORD local_10;
  PSYSTEM_LOGICAL_PROCESSOR_INFORMATION local_c;
  uint local_8;
  
  local_10 = 0;
  lpProcName = "GetLogicalProcessorInformation";
  hModule = GetModuleHandleW(L"kernel32.dll");
  pFVar2 = GetProcAddress(hModule,lpProcName);
  if (((pFVar2 == (FARPROC)0x0) ||
      (BVar3 = GetLogicalProcessorInformation((PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)0x0,&local_10),
      BVar3 != 0)) || (DVar4 = GetLastError(), DVar4 != 0x7a)) {
    local_8 = 0x40;
  }
  else {
    local_c = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)FUN_004044b8(local_10);
    puVar8 = &LAB_00405646;
    uVar7 = *in_FS_OFFSET;
    *in_FS_OFFSET = &stack0xffffffe4;
    GetLogicalProcessorInformation(local_c,&local_10);
    p_Var5 = local_c;
    while( true ) {
      if (local_10 == 0) {
        *in_FS_OFFSET = uVar7;
        uVar6 = FUN_004044d4((int)local_c);
        return uVar6;
      }
      if ((*(short *)&p_Var5->Relationship == 2) && ((p_Var5->u).Cache.Level == '\x01')) break;
      p_Var5 = p_Var5 + 1;
      local_10 = local_10 - 0x18;
    }
    uVar1 = (p_Var5->u).Cache.LineSize;
    local_8 = (uint)uVar1;
    FUN_004063c0((char)uVar1,extraout_DL,extraout_CL,uVar7,puVar8);
  }
  return local_8;
}



DWORD FUN_00405698(int param_1)

{
  DWORD DVar1;
  DWORD DVar2;
  
  DVar1 = *(DWORD *)(param_1 + 8);
  DVar2 = GetCurrentThreadId();
  if (DVar1 != DVar2) {
    FUN_004045f4(0x19);
  }
  return DVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004056b0(void)

{
  int iVar1;
  
  if (DAT_00429000 == (byte *)0x0) {
    DAT_00429000 = (byte *)FUN_00405598();
    LOCK();
    UNLOCK();
  }
  if ((1 < _DAT_0042905c) && (DAT_00429004 == 0)) {
    LOCK();
    DAT_00429004 = 1000;
    UNLOCK();
  }
  if ((int)DAT_00429000 < 0x1d) {
    iVar1 = FUN_00403844((byte *)0x1c);
  }
  else {
    iVar1 = FUN_00403844(DAT_00429000);
  }
  *(int *)(iVar1 + 0x10) = DAT_00429004;
  return;
}



void FUN_0040570c(int *param_1)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = (uint *)FUN_00405a94(param_1);
  uVar1 = *puVar2;
  if ((int **)(uVar1 & 0xfffffffe) != (int **)0x0) {
    *puVar2 = 0;
    FUN_00405728((int **)(uVar1 & 0xfffffffe));
  }
  return;
}



void FUN_00405728(int **param_1)

{
  if ((DAT_004298f4 != 0) && (param_1[3] != (int *)0x0)) {
    (**(code **)(DAT_004298f4 + 4))(param_1[3]);
  }
  FUN_00403334(param_1);
  return;
}



void FUN_00405778(int *param_1,uint param_2)

{
  int **ppiVar1;
  
  if (DAT_004298f4 == 0) {
    FUN_004045f4(0x1a);
  }
  ppiVar1 = FUN_00405aa4(param_1);
  FUN_00405820((uint *)ppiVar1,param_2);
  return;
}



int * FUN_004057a0(int param_1)

{
  undefined4 uVar1;
  int *piVar2;
  undefined4 *in_FS_OFFSET;
  
  FUN_00405554((int *)(param_1 + 0x18));
  uVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = &stack0xffffffe8;
  piVar2 = *(int **)(param_1 + 0x14);
  if ((piVar2 != (int *)0x0) && ((int *)*piVar2 != piVar2)) {
    **(undefined4 **)(param_1 + 0x14) = *(undefined4 *)**(undefined4 **)(param_1 + 0x14);
    *in_FS_OFFSET = uVar1;
    piVar2 = (int *)FUN_00405580((undefined4 *)(param_1 + 0x18));
    return piVar2;
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  FUN_004063c0((char)param_1,0,0,uVar1,&LAB_00405812);
  return piVar2;
}



bool FUN_00405820(uint *param_1,uint param_2)

{
  bool bVar1;
  undefined4 uVar2;
  DWORD DVar3;
  DWORD DVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  bool bVar9;
  int local_14;
  
  uVar8 = param_1[4];
  do {
    uVar2 = FUN_00405ce0((int *)param_1);
    if ((char)uVar2 != '\0') {
      return (bool)(char)uVar2;
    }
    if (param_2 == 0) {
      return false;
    }
    bVar1 = false;
    if (0 < (int)uVar8) {
      DVar3 = GetTickCount();
      local_14 = 0;
      for (; 0 < (int)uVar8; uVar8 = uVar8 - 1) {
        if ((param_2 != 0xffffffff) && (DVar4 = GetTickCount(), param_2 <= DVar4 - DVar3)) {
          return false;
        }
        if (1 < (int)*param_1) break;
        if (*param_1 == 0) {
          uVar5 = 0;
          LOCK();
          if (*param_1 == 0) {
            *param_1 = 1;
          }
          else {
            uVar5 = *param_1;
          }
          UNLOCK();
          if (uVar5 == 0) {
            DVar3 = GetCurrentThreadId();
            param_1[2] = DVar3;
            param_1[1] = 1;
            return true;
          }
        }
        FUN_004054dc(&local_14);
      }
      if (param_2 != 0xffffffff) {
        DVar4 = GetTickCount();
        if (param_2 <= DVar4 - DVar3) {
          return false;
        }
        param_2 = param_2 - (DVar4 - DVar3);
      }
    }
    while (uVar5 = *param_1, uVar5 != 0) {
      LOCK();
      if (uVar5 == *param_1) {
        *param_1 = uVar5 + 2;
        uVar6 = uVar5;
      }
      else {
        uVar6 = *param_1;
      }
      UNLOCK();
      if (uVar5 == uVar6) goto LAB_00405900;
    }
  } while( true );
LAB_00405900:
  DVar3 = GetTickCount();
  iVar7 = FUN_00405a24((int)param_1);
  iVar7 = (**(code **)(DAT_004298f4 + 0x10))(0,iVar7,param_2);
  bVar9 = iVar7 == 0;
  if (param_2 != 0xffffffff) {
    DVar4 = GetTickCount();
    if (DVar4 - DVar3 < param_2) {
      param_2 = param_2 - (DVar4 - DVar3);
    }
    else {
      param_2 = 0;
    }
  }
  if (bVar9) {
    do {
      uVar8 = *param_1;
      if ((uVar8 & 1) != 0) goto LAB_00405989;
      LOCK();
      if (uVar8 == *param_1) {
        *param_1 = uVar8 - 2 | 1;
        uVar5 = uVar8;
      }
      else {
        uVar5 = *param_1;
      }
      UNLOCK();
    } while (uVar8 != uVar5);
    bVar1 = true;
  }
  else {
    do {
      uVar8 = *param_1;
      LOCK();
      if (uVar8 == *param_1) {
        *param_1 = uVar8 - 2;
        uVar5 = uVar8;
      }
      else {
        uVar5 = *param_1;
      }
      UNLOCK();
    } while (uVar8 != uVar5);
    bVar1 = true;
  }
LAB_00405989:
  if (bVar1) {
    if (bVar9) {
      DVar3 = GetCurrentThreadId();
      param_1[2] = DVar3;
      param_1[1] = 1;
    }
    return bVar9;
  }
  goto LAB_00405900;
}



void FUN_004059b8(uint *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  FUN_00405698((int)param_1);
  param_1[1] = param_1[1] - 1;
  if (param_1[1] == 0) {
    param_1[2] = 0;
    do {
      uVar1 = *param_1;
      LOCK();
      if (uVar1 == *param_1) {
        *param_1 = uVar1 - 1;
        uVar2 = uVar1;
      }
      else {
        uVar2 = *param_1;
      }
      UNLOCK();
    } while (uVar1 != uVar2);
    if ((uVar1 & 0xfffffffe) != 0) {
      iVar3 = FUN_00405a24((int)param_1);
      (**(code **)(DAT_004298f4 + 0x10))(iVar3,0,0);
    }
  }
  return;
}



void FUN_00405a00(int *param_1)

{
  int **ppiVar1;
  
  if (DAT_004298f4 == 0) {
    FUN_004045f4(0x1a);
  }
  ppiVar1 = FUN_00405aa4(param_1);
  FUN_004059b8((uint *)ppiVar1);
  return;
}



int FUN_00405a24(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  DWORD dwMilliseconds;
  
  dwMilliseconds = 1;
  iVar4 = *(int *)(param_1 + 0xc);
  if (iVar4 == 0) {
    while( true ) {
      iVar2 = (**DAT_004298f4)();
      iVar3 = 0;
      LOCK();
      piVar1 = (int *)(param_1 + 0xc);
      if (*piVar1 == 0) {
        *piVar1 = iVar2;
      }
      else {
        iVar3 = *piVar1;
      }
      UNLOCK();
      iVar4 = iVar2;
      if ((iVar3 != 0) && (iVar4 = iVar3, iVar2 != 0)) {
        (*DAT_004298f4[1])(iVar2);
      }
      if (iVar4 != 0) break;
      Sleep(dwMilliseconds);
      if ((int)dwMilliseconds < 0x201) {
        dwMilliseconds = dwMilliseconds * 2;
      }
      else {
        dwMilliseconds = 1;
      }
    }
  }
  return iVar4;
}



int FUN_00405a84(int *param_1)

{
  return (int)param_1 + *(int *)(*param_1 + -0x34) + -4;
}



int FUN_00405a94(int *param_1)

{
  return (int)param_1 + *(int *)(*param_1 + -0x34) + -4;
}



int ** FUN_00405aa4(int *param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  uint *puVar3;
  uint local_c;
  
  puVar3 = (uint *)((int)param_1 + *(int *)(*param_1 + -0x34) + -4);
  local_c = *puVar3;
  ppiVar2 = (int **)(local_c & 0xfffffffe);
  if (ppiVar2 == (int **)0x0) {
    ppiVar1 = (int **)FUN_004056b0();
    do {
      LOCK();
      if (local_c == *puVar3) {
        *puVar3 = local_c & 1 | (uint)ppiVar1;
      }
      UNLOCK();
      local_c = *puVar3;
      ppiVar2 = (int **)(local_c & 0xfffffffe);
    } while (ppiVar2 == (int **)0x0);
    if (ppiVar1 != ppiVar2) {
      FUN_00403334(ppiVar1);
    }
  }
  return ppiVar2;
}



void FUN_00405af8(int param_1)

{
  int *piVar1;
  
  piVar1 = FUN_004057a0(param_1);
  if (piVar1 != (int *)0x0) {
    (**(code **)(DAT_004298f4 + 0x10))(piVar1[2],0,0);
  }
  return;
}



void FUN_00405b14(int *param_1)

{
  int **ppiVar1;
  
  if (DAT_004298f4 == 0) {
    FUN_004045f4(0x1a);
  }
  ppiVar1 = FUN_00405aa4(param_1);
  FUN_00405af8((int)ppiVar1);
  return;
}



void FUN_00405b90(int param_1,undefined4 *param_2)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined *puStack_10;
  
  puStack_10 = (undefined *)0x405ba5;
  FUN_00405554((int *)(param_1 + 0x18));
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  if (*(undefined4 **)(param_1 + 0x14) == (undefined4 *)0x0) {
    *(undefined4 **)(param_1 + 0x14) = param_2;
    *param_2 = param_2;
  }
  else {
    *param_2 = **(undefined4 **)(param_1 + 0x14);
    **(undefined4 **)(param_1 + 0x14) = param_2;
    *(undefined4 **)(param_1 + 0x14) = param_2;
  }
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00405bf9;
  uStack_14 = 0x405bf1;
  FUN_00405580((undefined4 *)(param_1 + 0x18));
  return;
}



void FUN_00405c00(int param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return;
  }
  uStack_14 = 0x405c23;
  FUN_00405554((int *)(param_1 + 0x18));
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  puVar3 = *(undefined4 **)(param_1 + 0x14);
  if (puVar3 != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)*puVar3;
    while (puVar2 = puVar1, puVar2 != *(undefined4 **)(param_1 + 0x14)) {
      if (puVar2 == param_2) {
        *puVar3 = *puVar2;
        break;
      }
      puVar3 = puVar2;
      puVar1 = (undefined4 *)*puVar2;
    }
    if ((puVar2 == *(undefined4 **)(param_1 + 0x14)) && (puVar2 == param_2)) {
      puVar1 = (undefined4 *)*puVar2;
      if (puVar2 == puVar1) {
        *(undefined4 *)(param_1 + 0x14) = 0;
      }
      else {
        *(undefined4 **)(param_1 + 0x14) = puVar1;
        *puVar3 = puVar1;
      }
    }
  }
  *in_FS_OFFSET = uStack_1c;
  uStack_14 = 0x405c9d;
  uStack_18 = 0x405c95;
  FUN_00405580((undefined4 *)(param_1 + 0x18));
  return;
}



void FUN_00405cbc(int *param_1)

{
  int **ppiVar1;
  
  if (DAT_004298f4 == 0) {
    FUN_004045f4(0x1a);
  }
  ppiVar1 = FUN_00405aa4(param_1);
  FUN_00405ce0((int *)ppiVar1);
  return;
}



undefined4 FUN_00405ce0(int *param_1)

{
  DWORD DVar1;
  int iVar2;
  
  DVar1 = GetCurrentThreadId();
  if (DVar1 == param_1[2]) {
    param_1[1] = param_1[1] + 1;
    return CONCAT31((int3)(DVar1 >> 8),1);
  }
  if (*param_1 == 0) {
    iVar2 = 0;
    LOCK();
    if (*param_1 == 0) {
      *param_1 = 1;
    }
    else {
      iVar2 = *param_1;
    }
    UNLOCK();
    if (iVar2 == 0) {
      DVar1 = GetCurrentThreadId();
      param_1[2] = DVar1;
      param_1[1] = 1;
      return CONCAT31((int3)(DVar1 >> 8),1);
    }
  }
  return 0;
}



void FUN_00405d20(int param_1,uint *param_2,undefined4 param_3)

{
  undefined *puVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  undefined4 local_1c;
  DWORD local_18;
  undefined4 local_14;
  uint local_10;
  undefined local_9;
  undefined4 local_8;
  
  local_1c = 0;
  puStack_2c = (undefined *)0x405d3c;
  local_8 = param_3;
  local_18 = FUN_00405698((int)param_2);
  puStack_2c = (undefined *)0x405d48;
  local_14 = (**(code **)(DAT_004298f4 + 8))();
  puStack_30 = &LAB_00405dc2;
  uStack_34 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_34;
  local_10 = param_2[1];
  puStack_2c = &stack0xfffffffc;
  FUN_00405b90(param_1,&local_1c);
  param_2[1] = 1;
  FUN_004059b8(param_2);
  iVar2 = (**(code **)(DAT_004298f4 + 0x10))(0,local_14,local_8);
  local_9 = iVar2 == 0;
  FUN_00405820(param_2,0xffffffff);
  FUN_00405c00(param_1,&local_1c);
  puVar1 = puStack_2c;
  param_2[1] = local_10;
  *in_FS_OFFSET = uStack_34;
  puStack_2c = &LAB_00405dc9;
  puStack_30 = (undefined *)0x405dc1;
  (**(code **)(DAT_004298f4 + 0xc))(local_14,uStack_34,puVar1);
  return;
}



undefined4 FUN_00405e50(undefined4 param_1)

{
  if (DAT_00427024 != '\0') {
    (*DAT_0042901c)();
    param_1 = 2;
  }
  return param_1;
}



undefined4 FUN_00405e74(void)

{
  (*DAT_0042901c)();
  return 0;
}



void FUN_00405e8c(void)

{
  if (1 < DAT_00427024) {
    FUN_00405e74();
    return;
  }
  return;
}



void FUN_00405ea0(void)

{
  if (1 < DAT_00427024) {
    FUN_00405e74();
    return;
  }
  return;
}



int FUN_00405eb4(int param_1,undefined4 param_2,char *param_3)

{
  if (((param_3 != (char *)0x0) && (param_1 = *(int *)(param_3 + 1), *param_3 != -0x17)) &&
     (*param_3 == -0x15)) {
    param_1 = (int)(char)param_1;
  }
  return param_1;
}



undefined4 * FUN_00405ed4(undefined4 *param_1,undefined4 param_2,char *param_3)

{
  undefined4 uStack_10;
  char *pcStack_c;
  undefined4 uStack_8;
  undefined4 *puStack_4;
  
  if (1 < DAT_00427024) {
    uStack_10 = 0x405ee5;
    pcStack_c = param_3;
    uStack_8 = param_2;
    puStack_4 = param_1;
    FUN_00405eb4((int)param_1,param_2,param_3);
    param_1 = &uStack_10;
    (*DAT_0042901c)();
  }
  return param_1;
}



undefined4 FUN_00405f18(undefined4 param_1)

{
  if (1 < DAT_00427024) {
    (*DAT_0042901c)();
  }
  return param_1;
}



undefined4 FUN_00405f38(undefined param_1,undefined param_2,undefined param_3,int *param_4)

{
  int iVar1;
  LONG LVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int unaff_ESI;
  undefined4 *in_FS_OFFSET;
  PCONTEXT in_stack_00000008;
  undefined4 uStackY_34;
  PCONTEXT pCStackY_30;
  undefined4 uStackY_2c;
  int *piStackY_28;
  undefined4 uStackY_24;
  int iStackY_20;
  int iStackY_1c;
  int *piStackY_18;
  undefined4 uStackY_14;
  
  if ((param_4[1] & 6U) != 0) {
    return 1;
  }
  iStackY_1c = param_4[6];
  iStackY_20 = param_4[5];
  if (*param_4 != 0xeedfade) {
    FUN_00404c40();
    if (DAT_00429018 == (code *)0x0) {
      return 1;
    }
    iStackY_1c = (*DAT_00429018)();
    if (iStackY_1c == 0) {
      return 1;
    }
    if (((*param_4 != 0xeefface) && (iStackY_1c = FUN_00405e50(iStackY_1c), DAT_00427025 != 0)) &&
       (DAT_00427024 == '\0')) {
      LVar2 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&param_4);
      if (LVar2 == 0) {
        return 1;
      }
      iStackY_20 = param_4[3];
      piStackY_28 = param_4;
      goto LAB_00405fec;
    }
    iStackY_20 = param_4[3];
  }
  piStackY_28 = param_4;
  if ((1 < DAT_00427025) && (DAT_00427024 == '\0')) {
    uStackY_14 = 0x405fe4;
    LVar2 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&param_4);
    if (LVar2 == 0) {
      return 1;
    }
  }
LAB_00405fec:
  piStackY_28[1] = piStackY_28[1] | 2;
  uStackY_14 = *in_FS_OFFSET;
  uStackY_24 = 0;
  uStackY_2c = 0x406010;
  pCStackY_30 = in_stack_00000008;
  uStackY_34 = 0x406010;
  piStackY_18 = piStackY_28;
  (*DAT_00429020)();
  uStackY_34 = 0x406019;
  puVar3 = (undefined4 *)FUN_0040ae54();
  uStackY_34 = *puVar3;
  *puVar3 = &uStackY_34;
  iVar1 = *(int *)(unaff_ESI + 4);
  *(undefined **)(unaff_ESI + 4) = &LAB_0040603c;
  FUN_00405ea0();
                    // WARNING: Could not recover jumptable at 0x0040603a. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar4 = (*(code *)(iVar1 + 5))();
  return uVar4;
}



undefined4
FUN_004061ec(undefined param_1,undefined param_2,undefined param_3,int param_4,int param_5)

{
  int iVar1;
  undefined4 *puVar2;
  code *extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  int iStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined *puStack_18;
  
  if ((*(uint *)(param_4 + 4) & 6) != 0) {
    puStack_18 = &LAB_0040626c;
    uStack_1c = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_1c;
    uStack_20 = *in_FS_OFFSET;
    uStack_28 = *(undefined4 *)(param_4 + 0x18);
    uStack_2c = *(undefined4 *)(param_4 + 0x14);
    iStack_24 = param_4;
    uStack_30 = 0x406225;
    puVar2 = (undefined4 *)FUN_0040ae54();
    uStack_30 = *puVar2;
    *puVar2 = &uStack_30;
    iVar1 = *(int *)(param_5 + 4);
    *(undefined **)(param_5 + 4) = &LAB_0040626c;
    FUN_00405ed4(puVar2,extraout_EDX,(char *)(iVar1 + 5));
    (*extraout_ECX)();
    puVar2 = (undefined4 *)FUN_0040ae54();
    *puVar2 = *(undefined4 *)*puVar2;
    *in_FS_OFFSET = uStack_1c;
  }
  return 1;
}



undefined4
FUN_00406294(undefined param_1,undefined param_2,undefined param_3,undefined4 *param_4,int param_5)

{
  int iVar1;
  code *extraout_ECX;
  
  if ((param_4[1] & 6) != 0) {
    iVar1 = *(int *)(param_5 + 4);
    *(undefined4 *)(param_5 + 4) = 0x4062c4;
    FUN_00405ed4(param_4,param_5,(char *)(iVar1 + 5));
    (*extraout_ECX)();
  }
  return 1;
}



void FUN_004062cc(int param_1)

{
  code *pcVar1;
  undefined *puVar2;
  undefined4 uStack_5c;
  code *pcStack_58;
  undefined *puStack_54;
  undefined4 uStack_4c;
  int iStack_44;
  undefined *puStack_30;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined *local_1c;
  undefined local_18 [4];
  int local_14;
  
  if (param_1 == 0) {
    param_1 = FUN_00406a3c(0xd8);
  }
  local_1c = local_18;
  uStack_20 = 7;
  uStack_24 = 1;
  uStack_28 = 0xeedfade;
  puVar2 = local_18;
  local_14 = param_1;
  if (DAT_00429024 != (code *)0x0) {
    uStack_4c = 7;
    pcStack_58 = DAT_00429024;
    uStack_5c = 0x406318;
    puStack_54 = local_18;
    iStack_44 = param_1;
    puStack_30 = &stack0x00000004;
    puStack_54 = (undefined *)FUN_00404590();
    pcVar1 = pcStack_58;
    if (puStack_54 != (undefined *)0x0) {
      puStack_54 = *(undefined **)((int)puStack_54 + 0xc);
    }
    pcStack_58 = (code *)0x1;
    uStack_5c = 0xeedfade;
    (*pcVar1)(&uStack_5c);
    puVar2 = local_1c;
  }
  local_1c = puVar2;
                    // WARNING: Could not recover jumptable at 0x00406332. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_0042901c)();
  return;
}



void FUN_004063c0(undefined param_1,undefined param_2,undefined param_3,undefined4 param_4,
                 int param_5)

{
  undefined4 *in_FS_OFFSET;
  
  *in_FS_OFFSET = param_4;
  (*(code *)(param_5 + 5))();
  return;
}



void FUN_00406518(int param_1)

{
  int *piVar1;
  int iVar2;
  int unaff_EBP;
  int *in_FS_OFFSET;
  
  piVar1 = (int *)(unaff_EBP + -0x10);
  iVar2 = *in_FS_OFFSET;
  *in_FS_OFFSET = (int)piVar1;
  *piVar1 = iVar2;
  *(undefined **)(unaff_EBP + -0xc) = &LAB_00406478;
  *(int *)(unaff_EBP + -8) = unaff_EBP;
  *(int **)(param_1 + 4) = piVar1;
  return;
}



void FUN_00406538(int param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  int *in_FS_OFFSET;
  
  ppiVar1 = *(int ***)(param_1 + 4);
  if (ppiVar1 != (int **)0x0) {
    ppiVar2 = (int **)*in_FS_OFFSET;
    if (ppiVar1 == ppiVar2) {
      *in_FS_OFFSET = (int)*ppiVar1;
      return;
    }
    for (; ppiVar2 != (int **)0xffffffff; ppiVar2 = (int **)*ppiVar2) {
      if ((int **)*ppiVar2 == ppiVar1) {
        *ppiVar2 = *ppiVar1;
        return;
      }
    }
  }
  return;
}



void FUN_00406560(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  
  iVar3 = DAT_0042bba0;
  puStack_14 = &stack0xfffffffc;
  if (DAT_0042bb9c != 0) {
    iVar1 = *(int *)(DAT_0042bb9c + 4);
    puStack_18 = &LAB_004065ae;
    uStack_1c = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_1c;
    if (0 < iVar3) {
      do {
        iVar3 = iVar3 + -1;
        piVar2 = *(int **)(iVar1 + 4 + iVar3 * 8);
        DAT_0042bba0 = iVar3;
        if ((piVar2 != (int *)0x0) && (*piVar2 != 0)) {
          (*(code *)piVar2)();
        }
      } while (0 < iVar3);
    }
    *in_FS_OFFSET = uStack_1c;
  }
  return;
}



void FUN_004065c8(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  
  puStack_18 = &stack0xfffffffc;
  if (DAT_0042bb9c != (int *)0x0) {
    iVar1 = *DAT_0042bb9c;
    iVar4 = 0;
    iVar2 = DAT_0042bb9c[1];
    puStack_1c = &LAB_0040661a;
    uStack_20 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_20;
    if (0 < iVar1) {
      do {
        piVar3 = *(int **)(iVar2 + iVar4 * 8);
        iVar4 = iVar4 + 1;
        DAT_0042bba0 = iVar4;
        if ((piVar3 != (int *)0x0) && (*piVar3 != 0)) {
          (*(code *)piVar3)();
        }
      } while (iVar4 < iVar1);
    }
    *in_FS_OFFSET = uStack_20;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00406634(undefined4 param_1,int param_2)

{
  DAT_0042901c = &DAT_00402798;
  DAT_00429020 = &DAT_004027a0;
  DAT_0042bba0 = 0;
  _DAT_0042903c = *(undefined4 *)(param_2 + 4);
  DAT_0042bb9c = param_1;
  DAT_0042bba4 = param_2;
  FUN_00406518((int)&DAT_0042bb94);
  DAT_00429044 = 0;
  FUN_004065c8();
  return;
}



void FUN_0040667c(undefined4 param_1,ushort param_2,longlong **param_3)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  longlong *local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_1c = &LAB_004066c4;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  FUN_0040ab3c(param_1,&local_8);
  FUN_00407170(param_3,(LPCWSTR)local_8,param_2);
  *in_FS_OFFSET = puStack_1c;
  puStack_18 = (undefined *)0x4066c3;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_004066d4(undefined4 param_1,BSTR *param_2)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  longlong *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_18 = &LAB_00406717;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  FUN_0040ab3c(param_1,&local_8);
  FUN_004072b4(param_2,(OLECHAR *)local_8);
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_0040671e;
  puStack_18 = (undefined *)0x406716;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_00406724(undefined4 param_1,longlong **param_2)

{
  FUN_0040ab3c(param_1,param_2);
  return;
}



void FUN_00406738(int *param_1)

{
  undefined4 uVar1;
  longlong **pplVar2;
  int iVar3;
  code *pcVar4;
  int *piVar5;
  int iVar6;
  
  iVar6 = *param_1;
  piVar5 = param_1 + 1;
  do {
    uVar1 = *(undefined4 *)piVar5[1];
    pplVar2 = (longlong **)*piVar5;
    iVar3 = piVar5[2];
    if ((short)iVar3 == 0) {
      FUN_0040667c(uVar1,(ushort)((uint)iVar3 >> 0x10),pplVar2);
    }
    else if (iVar3 == 1) {
      FUN_004066d4(uVar1,(BSTR *)pplVar2);
    }
    else {
      if (iVar3 != 2) {
        pcVar4 = (code *)swi(3);
        (*pcVar4)();
        return;
      }
      FUN_00406724(uVar1,pplVar2);
    }
    piVar5 = piVar5 + 3;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  return;
}



void FUN_00406780(int *param_1)

{
  int **ppiVar1;
  int iVar2;
  
  iVar2 = *param_1;
  ppiVar1 = (int **)(param_1 + 1);
  do {
    **ppiVar1 = *ppiVar1[1] + (int)ppiVar1[2];
    ppiVar1 = ppiVar1 + 3;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void FUN_004067a4(int *param_1,undefined4 param_2)

{
  BSTR *ppOVar1;
  int iVar2;
  code *pcVar3;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  int *piVar4;
  int iVar5;
  
  iVar5 = *param_1;
  piVar4 = param_1 + 1;
  do {
    ppOVar1 = (BSTR *)*piVar4;
    iVar2 = piVar4[2];
    if ((short)iVar2 == 0) {
      FUN_00406b4c((int *)ppOVar1);
      param_2 = extraout_EDX;
    }
    else if (iVar2 == 1) {
      FUN_00406b70(ppOVar1);
      param_2 = extraout_EDX_00;
    }
    else {
      if (iVar2 != 2) {
        pcVar3 = (code *)swi(3);
        (*pcVar3)(ppOVar1,param_2);
        return;
      }
      FUN_00406b28((int *)ppOVar1);
      param_2 = extraout_EDX_01;
    }
    piVar4 = piVar4 + 3;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  return;
}



void FUN_004067e0(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = 0x10;
  iVar1 = DAT_00427000;
  do {
    s_Runtime_error_at_00000000_004279c1[uVar2 & 0xff] = (char)(iVar1 % 10) + '0';
    iVar1 = iVar1 / 10;
    uVar2 = uVar2 - 1;
  } while (iVar1 != 0);
  uVar3 = 0x1c;
  uVar2 = DAT_00427004;
  do {
    s_Runtime_error_at_00000000_004279c1[uVar3 & 0xff] = s_0123456789ABCDEF_004279df[uVar2 & 0xf];
    uVar2 = uVar2 >> 4;
    uVar3 = uVar3 - 1;
  } while (uVar2 != 0);
  return;
}



bool FUN_0040683c(undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar3 = (undefined4 *)*param_1;
  for (iVar2 = 0xc; iVar1 = DAT_00427000, iVar2 != 0; iVar2 = iVar2 + -1) {
    *param_1 = *puVar3;
    puVar3 = puVar3 + 1;
    param_1 = param_1 + 1;
  }
  LOCK();
  DAT_00427000 = 0;
  UNLOCK();
  return (bool)('\x01' - (iVar1 != 0));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00406868(undefined4 param_1,undefined4 param_2,DWORD param_3)

{
  HANDLE pvVar1;
  LPCVOID lpBuffer;
  char *lpBuffer_00;
  DWORD DVar2;
  DWORD *lpNumberOfBytesWritten;
  DWORD *lpNumberOfBytesWritten_00;
  LPOVERLAPPED p_Var3;
  DWORD local_4;
  
  local_4 = param_3;
  if (DAT_00429054 != '\0') {
    if ((_DAT_00429340 == -0x284e) && (_DAT_00429348 != 0)) {
      (*DAT_00429358)(&DAT_0042933c);
    }
    lpNumberOfBytesWritten = &local_4;
    lpNumberOfBytesWritten_00 = &local_4;
    p_Var3 = (LPOVERLAPPED)0x0;
    DVar2 = 0x1d;
    lpBuffer_00 = s_Runtime_error_at_00000000_004279c1;
    pvVar1 = GetStdHandle(0xfffffff5);
    WriteFile(pvVar1,lpBuffer_00,DVar2,lpNumberOfBytesWritten,p_Var3);
    p_Var3 = (LPOVERLAPPED)0x0;
    DVar2 = 2;
    lpBuffer = (LPCVOID)FUN_004070e0((int)&DAT_004068fc);
    pvVar1 = GetStdHandle(0xfffffff5);
    WriteFile(pvVar1,lpBuffer,DVar2,lpNumberOfBytesWritten_00,p_Var3);
    return;
  }
  if (DAT_00427026 == '\0') {
    MessageBoxA((HWND)0x0,s_Runtime_error_at_00000000_004279c1,s_Error_004279bb,0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00406900(void)

{
  HMODULE hLibModule;
  code *pcVar1;
  undefined4 uVar2;
  DWORD DVar3;
  int *piVar4;
  DWORD extraout_ECX;
  undefined *extraout_ECX_00;
  int iVar5;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 *puVar6;
  undefined4 *puVar7;
  byte bVar8;
  
  bVar8 = 0;
  if (DAT_00427004 != 0) {
    uVar2 = FUN_004067e0();
    FUN_00406868(uVar2,extraout_EDX,extraout_ECX);
    DAT_00427004 = 0;
  }
  if ((_DAT_0042bbc8 != 0) && (DVar3 = GetCurrentThreadId(), DVar3 == _DAT_0042bbf0)) {
    FUN_00406538((int)&DAT_0042bbc4);
    FUN_0040683c((undefined4 *)&DAT_0042bbc4);
  }
  pcVar1 = DAT_00429050;
  if (DAT_0042bbbc == 0) {
    while (DAT_00429050 = pcVar1, pcVar1 != (code *)0x0) {
      DAT_00429050 = (code *)0x0;
      (*pcVar1)();
      pcVar1 = DAT_00429050;
    }
  }
  while( true ) {
    if ((DAT_0042bbbc == 2) && (DAT_00427000 == 0)) {
      DAT_0042bba0 = 0;
    }
    if (DAT_0042bbbc == 0) {
      piVar4 = (int *)FUN_0040455c();
      while (piVar4 != (int *)0x0) {
        FUN_00404df4(piVar4);
        piVar4 = (int *)FUN_0040455c();
      }
    }
    FUN_00406560();
    if (((DAT_0042bbbc < 2) || (DAT_00427000 != 0)) && (DAT_0042bba4 != (undefined4 *)0x0)) {
      FUN_00409500(DAT_0042bba4,extraout_EDX_00,extraout_ECX_00);
      hLibModule = (HMODULE)DAT_0042bba4[4];
      if ((hLibModule != (HMODULE)DAT_0042bba4[1]) && (hLibModule != (HMODULE)0x0)) {
        FreeLibrary(hLibModule);
      }
    }
    FUN_00406538((int)&DAT_0042bb94);
    if (DAT_0042bbbc == 1) {
      (*DAT_0042bbb8)();
    }
    if (DAT_0042bbbc != 0) {
      FUN_0040683c(&DAT_0042bb94);
    }
    if (DAT_0042bb94 == (undefined4 *)0x0) break;
    puVar6 = DAT_0042bb94;
    puVar7 = &DAT_0042bb94;
    for (iVar5 = 0xc; iVar5 != 0; iVar5 = iVar5 + -1) {
      *puVar7 = *puVar6;
      puVar6 = puVar6 + (uint)bVar8 * -2 + 1;
      puVar7 = puVar7 + (uint)bVar8 * -2 + 1;
    }
  }
  if (DAT_00429034 != (code *)0x0) {
    (*DAT_00429034)();
  }
                    // WARNING: Subroutine does not return
  ExitProcess(DAT_00427000);
}



void FUN_00406a30(undefined4 param_1)

{
  DAT_00427000 = param_1;
  FUN_00406900();
  return;
}



void FUN_00406a3c(byte param_1)

{
  undefined4 in_stack_00000000;
  
  DAT_00427004 = in_stack_00000000;
  FUN_00406a30((uint)param_1);
  return;
}



void FUN_00406a58(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 in_stack_00000000;
  
  if (DAT_00429030 == (code *)0x0) {
    FUN_004045a8(CONCAT31((int3)((uint)param_1 >> 8),0x15),in_stack_00000000);
  }
  else {
    (*DAT_00429030)(param_1,param_2,param_3);
  }
  return;
}



undefined2 * FUN_00406a94(int param_1)

{
  int iVar1;
  undefined2 *puVar2;
  bool bVar3;
  
  if (param_1 < 1) {
    return (undefined2 *)0x0;
  }
  iVar1 = param_1 * 2;
  if ((!SCARRY4(param_1,param_1)) && (bVar3 = SCARRY4(iVar1,0xe), iVar1 = iVar1 + 0xe, !bVar3)) {
    puVar2 = (undefined2 *)FUN_004044b8(iVar1);
    *(undefined4 *)(puVar2 + 2) = 1;
    *(int *)(puVar2 + 4) = param_1;
    (puVar2 + 6)[param_1] = 0;
    puVar2[1] = 2;
    *puVar2 = (short)DAT_0042997c;
    return puVar2 + 6;
  }
  puVar2 = (undefined2 *)thunk_FUN_004045f4((byte)iVar1);
  return puVar2;
}



undefined2 * FUN_00406ad4(int param_1,int param_2)

{
  uint uVar1;
  undefined2 *puVar2;
  
  if (param_1 < 1) {
    return (undefined2 *)0x0;
  }
  if (!SCARRY4(param_1,0xe)) {
    uVar1 = param_1 + 0xeU & 0xfffffffe;
    puVar2 = (undefined2 *)FUN_004044b8(uVar1);
    *(undefined2 *)((uVar1 - 2) + (int)puVar2) = 0;
    *(int *)(puVar2 + 4) = param_1;
    *(undefined4 *)(puVar2 + 2) = 1;
    if (param_2 == 0) {
      param_2 = DAT_00429978;
    }
    *puVar2 = (short)param_2;
    puVar2[1] = 1;
    return puVar2 + 6;
  }
  puVar2 = (undefined2 *)thunk_FUN_004045f4((byte)(param_1 + 0xeU));
  return puVar2;
}



int * FUN_00406b28(int *param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *param_1;
  if ((iVar2 != 0) && (*param_1 = 0, 0 < *(int *)(iVar2 + -8))) {
    LOCK();
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      FUN_004044d4(iVar2 + -0xc);
    }
  }
  return param_1;
}



int * FUN_00406b4c(int *param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *param_1;
  if ((iVar2 != 0) && (*param_1 = 0, 0 < *(int *)(iVar2 + -8))) {
    LOCK();
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      FUN_004044d4(iVar2 + -0xc);
    }
  }
  return param_1;
}



BSTR * FUN_00406b70(BSTR *param_1)

{
  BSTR bstrString;
  
  bstrString = *param_1;
  if (bstrString != (BSTR)0x0) {
    *param_1 = (BSTR)0x0;
    SysFreeString(bstrString);
  }
  return param_1;
}



void FUN_00406b88(int *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  do {
    iVar2 = *param_1;
    if ((iVar2 != 0) && (*param_1 = 0, 0 < *(int *)(iVar2 + -8))) {
      LOCK();
      piVar1 = (int *)(iVar2 + -8);
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (*piVar1 == 0) {
        FUN_004044d4(iVar2 + -0xc);
      }
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + -1;
  } while (param_2 != 0);
  return;
}



void FUN_00406bb8(int *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  do {
    iVar2 = *param_1;
    if ((iVar2 != 0) && (*param_1 = 0, 0 < *(int *)(iVar2 + -8))) {
      LOCK();
      piVar1 = (int *)(iVar2 + -8);
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (*piVar1 == 0) {
        FUN_004044d4(iVar2 + -0xc);
      }
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + -1;
  } while (param_2 != 0);
  return;
}



void FUN_00406be8(BSTR *param_1,int param_2)

{
  BSTR bstrString;
  
  do {
    bstrString = *param_1;
    if (bstrString != (BSTR)0x0) {
      *param_1 = (BSTR)0x0;
      SysFreeString(bstrString);
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + -1;
  } while (param_2 != 0);
  return;
}



void FUN_00406c0c(int param_1)

{
  int iVar1;
  
  if ((param_1 != 0) &&
     (iVar1 = *(int *)(param_1 + -8), iVar1 != -1 && SCARRY4(iVar1,1) == iVar1 + 1 < 0)) {
    LOCK();
    *(int *)(param_1 + -8) = *(int *)(param_1 + -8) + 1;
    UNLOCK();
  }
  return;
}



void FUN_00406c1c(LPSTR param_1,int param_2,LPCWSTR param_3,UINT param_4,int param_5)

{
  if (param_4 == 0) {
    param_4 = DAT_00429978;
  }
  FUN_0040aba8(param_4,0,param_3,(LPBOOL)0x0,(LPCSTR)0x0,param_2,param_1,param_5);
  return;
}



void FUN_00406c48(LPSTR param_1,int param_2,LPCWSTR param_3,int param_4)

{
  FUN_00406c1c(param_1,param_2,param_3,DAT_00429978,param_4);
  return;
}



void FUN_00406c64(LPWSTR param_1,int param_2,LPCSTR param_3,UINT param_4,int param_5)

{
  FUN_0040abd0(param_4,0,param_3,param_2,param_1,param_5);
  return;
}



void FUN_00406c80(longlong **param_1,longlong *param_2,int param_3)

{
  longlong *plVar1;
  
  plVar1 = (longlong *)FUN_00406a94(param_3);
  if (param_2 != (longlong *)0x0) {
    FUN_0040465c(param_2,plVar1,param_3 << 1);
  }
  FUN_00406b4c((int *)param_1);
  *param_1 = plVar1;
  return;
}



BSTR * FUN_00406cb0(BSTR *param_1,OLECHAR *param_2,UINT param_3)

{
  BSTR pOVar1;
  BSTR *ppOVar2;
  
  if (param_3 == 0) {
    pOVar1 = *param_1;
    if (pOVar1 != (BSTR)0x0) {
      *param_1 = (BSTR)0x0;
      SysFreeString(pOVar1);
    }
    return param_1;
  }
  ppOVar2 = (BSTR *)SysAllocStringLen(param_2,param_3);
  if (ppOVar2 != (BSTR *)0x0) {
    pOVar1 = *param_1;
    *param_1 = (BSTR)ppOVar2;
    SysFreeString(pOVar1);
    return ppOVar2;
  }
  ppOVar2 = (BSTR *)FUN_004045f4(1);
  return ppOVar2;
}



void FUN_00406cd4(longlong **param_1,LPCSTR param_2,int param_3,UINT param_4)

{
  int iVar1;
  undefined8 local_1008;
  LPCSTR local_8;
  
  local_1008._4_4_ = param_1;
  local_8 = param_2;
  if (param_3 < 1) {
    FUN_00406b28((int *)param_1);
  }
  else {
    if ((param_3 + 1 < 0x7ff) &&
       (iVar1 = FUN_00406c64((LPWSTR)&local_1008,0x7ff,param_2,param_4,param_3), 0 < iVar1)) {
      FUN_00406c80(param_1,&local_1008,iVar1);
      return;
    }
    FUN_004072d0(param_1,param_3 + 1);
    iVar1 = FUN_00406c64((LPWSTR)*param_1,param_3 + 1,local_8,param_4,param_3);
    if (iVar1 < 0) {
      iVar1 = 0;
    }
    FUN_004072d0(param_1,iVar1);
  }
  return;
}



void FUN_00406d68(longlong **param_1,LPCSTR param_2,int param_3)

{
  FUN_00406cd4(param_1,param_2,param_3,DAT_00429978);
  return;
}



void FUN_00406d78(longlong **param_1,LPCWSTR param_2,int param_3,ushort param_4)

{
  uint uVar1;
  
  if (param_3 < 1) {
    FUN_00406b4c((int *)param_1);
  }
  else {
    if (param_4 == 0) {
      param_4 = (ushort)DAT_00429978;
    }
    uVar1 = FUN_00406c1c((LPSTR)0x0,0,param_2,(uint)param_4,param_3);
    FUN_004070f8(param_1,uVar1,0);
    if ((int)uVar1 < 1) {
      FUN_00406b4c((int *)param_1);
    }
    else {
      FUN_00406c1c((LPSTR)*param_1,uVar1,param_2,(uint)param_4,param_3);
      *(ushort *)((int)*param_1 + -0xc) = param_4;
    }
  }
  return;
}



void FUN_00406dfc(longlong **param_1,longlong *param_2)

{
  longlong *plVar1;
  int iVar2;
  longlong *plVar3;
  
  if (param_2 != (longlong *)0x0) {
    iVar2 = *(int *)(param_2 + -1);
    if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
      plVar3 = (longlong *)FUN_00406a94(*(int *)((int)param_2 + -4));
      FUN_0040465c(param_2,plVar3,*(int *)((int)param_2 + -4) << 1);
      param_2 = plVar3;
    }
    else {
      LOCK();
      *(int *)(param_2 + -1) = *(int *)(param_2 + -1) + 1;
      UNLOCK();
    }
  }
  LOCK();
  plVar3 = *param_1;
  *param_1 = param_2;
  UNLOCK();
  if ((plVar3 != (longlong *)0x0) && (0 < *(int *)(plVar3 + -1))) {
    LOCK();
    plVar1 = plVar3 + -1;
    *(int *)plVar1 = *(int *)plVar1 + -1;
    UNLOCK();
    if (*(int *)plVar1 == 0) {
      FUN_004044d4((int)plVar3 + -0xc);
    }
  }
  return;
}



void FUN_00406e44(int *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  if ((param_2 != 0) &&
     (iVar2 = *(int *)(param_2 + -8), iVar2 != -1 && SCARRY4(iVar2,1) == iVar2 + 1 < 0)) {
    LOCK();
    *(int *)(param_2 + -8) = *(int *)(param_2 + -8) + 1;
    UNLOCK();
  }
  LOCK();
  iVar2 = *param_1;
  *param_1 = param_2;
  UNLOCK();
  if ((iVar2 != 0) && (0 < *(int *)(iVar2 + -8))) {
    LOCK();
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      FUN_004044d4(iVar2 + -0xc);
    }
  }
  return;
}



BSTR * FUN_00406e70(BSTR *param_1,OLECHAR *param_2)

{
  BSTR bstrString;
  BSTR *ppOVar1;
  
  if (*param_1 != param_2) {
    if ((param_2 == (OLECHAR *)0x0) || (*(uint *)(param_2 + -2) >> 1 == 0)) {
      bstrString = *param_1;
      if (bstrString != (BSTR)0x0) {
        *param_1 = (BSTR)0x0;
        SysFreeString(bstrString);
      }
      return param_1;
    }
    param_1 = (BSTR *)SysReAllocStringLen(param_1,param_2,*(uint *)(param_2 + -2) >> 1);
    if (param_1 == (BSTR *)0x0) {
      ppOVar1 = (BSTR *)FUN_004045f4(1);
      return ppOVar1;
    }
  }
  return param_1;
}



void FUN_00406e98(longlong **param_1,longlong *param_2)

{
  longlong *plVar1;
  int iVar2;
  longlong *plVar3;
  
  if (param_2 != (longlong *)0x0) {
    iVar2 = *(int *)(param_2 + -1);
    if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
      plVar3 = (longlong *)
               FUN_00406ad4(*(int *)((int)param_2 + -4),(uint)*(ushort *)((int)param_2 + -0xc));
      FUN_0040465c(param_2,plVar3,*(uint *)((int)param_2 + -4));
      param_2 = plVar3;
    }
    else {
      LOCK();
      *(int *)(param_2 + -1) = *(int *)(param_2 + -1) + 1;
      UNLOCK();
    }
  }
  LOCK();
  plVar3 = *param_1;
  *param_1 = param_2;
  UNLOCK();
  if ((plVar3 != (longlong *)0x0) && (0 < *(int *)(plVar3 + -1))) {
    LOCK();
    plVar1 = plVar3 + -1;
    *(int *)plVar1 = *(int *)plVar1 + -1;
    UNLOCK();
    if (*(int *)plVar1 == 0) {
      FUN_004044d4((int)plVar3 + -0xc);
    }
  }
  return;
}



int FUN_00406eec(int param_1)

{
  int iVar1;
  
  iVar1 = 0;
  if (param_1 != 0) {
    for (; *(char *)(param_1 + iVar1) != '\0'; iVar1 = iVar1 + 1) {
    }
  }
  return iVar1;
}



int FUN_00406f00(int param_1)

{
  int iVar1;
  
  iVar1 = 0;
  if (param_1 != 0) {
    for (; *(short *)(param_1 + iVar1 * 2) != 0; iVar1 = iVar1 + 1) {
    }
  }
  return iVar1;
}



longlong * FUN_00406f14(longlong **param_1)

{
  longlong *plVar1;
  longlong *plVar2;
  
  plVar2 = *param_1;
  if ((plVar2 != (longlong *)0x0) && (*(int *)(plVar2 + -1) != 1)) {
    plVar1 = (longlong *)FUN_00406a94(*(int *)((int)plVar2 + -4));
    LOCK();
    plVar2 = *param_1;
    *param_1 = plVar1;
    UNLOCK();
    FUN_0040465c(plVar2,plVar1,*(int *)((int)plVar2 + -4) << 1);
    if (0 < *(int *)(plVar2 + -1)) {
      LOCK();
      plVar1 = plVar2 + -1;
      *(int *)plVar1 = *(int *)plVar1 + -1;
      UNLOCK();
      if (*(int *)plVar1 == 0) {
        FUN_004044d4((int)plVar2 + -0xc);
      }
    }
    plVar2 = *param_1;
  }
  return plVar2;
}



longlong * FUN_00406f58(longlong **param_1)

{
  longlong *plVar1;
  longlong *plVar2;
  
  plVar2 = *param_1;
  if ((plVar2 != (longlong *)0x0) && (*(int *)(plVar2 + -1) != 1)) {
    plVar1 = (longlong *)
             FUN_00406ad4(*(int *)((int)plVar2 + -4),(uint)*(ushort *)((int)plVar2 + -0xc));
    LOCK();
    plVar2 = *param_1;
    *param_1 = plVar1;
    UNLOCK();
    FUN_0040465c(plVar2,plVar1,*(uint *)((int)plVar2 + -4));
    if (0 < *(int *)(plVar2 + -1)) {
      LOCK();
      plVar1 = plVar2 + -1;
      *(int *)plVar1 = *(int *)plVar1 + -1;
      UNLOCK();
      if (*(int *)plVar1 == 0) {
        FUN_004044d4((int)plVar2 + -0xc);
      }
    }
    plVar2 = *param_1;
  }
  return plVar2;
}



longlong * thunk_FUN_00406f14(longlong **param_1)

{
  longlong *plVar1;
  longlong *plVar2;
  
  plVar2 = *param_1;
  if ((plVar2 != (longlong *)0x0) && (*(int *)(plVar2 + -1) != 1)) {
    plVar1 = (longlong *)FUN_00406a94(*(int *)((int)plVar2 + -4));
    LOCK();
    plVar2 = *param_1;
    *param_1 = plVar1;
    UNLOCK();
    FUN_0040465c(plVar2,plVar1,*(int *)((int)plVar2 + -4) << 1);
    if (0 < *(int *)(plVar2 + -1)) {
      LOCK();
      plVar1 = plVar2 + -1;
      *(int *)plVar1 = *(int *)plVar1 + -1;
      UNLOCK();
      if (*(int *)plVar1 == 0) {
        FUN_004044d4((int)plVar2 + -0xc);
      }
    }
    plVar2 = *param_1;
  }
  return plVar2;
}



longlong * thunk_FUN_00406f58(longlong **param_1)

{
  longlong *plVar1;
  longlong *plVar2;
  
  plVar2 = *param_1;
  if ((plVar2 != (longlong *)0x0) && (*(int *)(plVar2 + -1) != 1)) {
    plVar1 = (longlong *)
             FUN_00406ad4(*(int *)((int)plVar2 + -4),(uint)*(ushort *)((int)plVar2 + -0xc));
    LOCK();
    plVar2 = *param_1;
    *param_1 = plVar1;
    UNLOCK();
    FUN_0040465c(plVar2,plVar1,*(uint *)((int)plVar2 + -4));
    if (0 < *(int *)(plVar2 + -1)) {
      LOCK();
      plVar1 = plVar2 + -1;
      *(int *)plVar1 = *(int *)plVar1 + -1;
      UNLOCK();
      if (*(int *)plVar1 == 0) {
        FUN_004044d4((int)plVar2 + -0xc);
      }
    }
    plVar2 = *param_1;
  }
  return plVar2;
}



longlong * thunk_FUN_00406f14(longlong **param_1)

{
  longlong *plVar1;
  longlong *plVar2;
  
  plVar2 = *param_1;
  if ((plVar2 != (longlong *)0x0) && (*(int *)(plVar2 + -1) != 1)) {
    plVar1 = (longlong *)FUN_00406a94(*(int *)((int)plVar2 + -4));
    LOCK();
    plVar2 = *param_1;
    *param_1 = plVar1;
    UNLOCK();
    FUN_0040465c(plVar2,plVar1,*(int *)((int)plVar2 + -4) << 1);
    if (0 < *(int *)(plVar2 + -1)) {
      LOCK();
      plVar1 = plVar2 + -1;
      *(int *)plVar1 = *(int *)plVar1 + -1;
      UNLOCK();
      if (*(int *)plVar1 == 0) {
        FUN_004044d4((int)plVar2 + -0xc);
      }
    }
    plVar2 = *param_1;
  }
  return plVar2;
}



int * FUN_00406fb4(int *param_1,int *param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_3 >> 2;
  do {
    if (uVar1 == 0) {
LAB_00406fe4:
      uVar1 = param_3 & 3;
      if (((uVar1 != 0) && (*(char *)param_1 == *(char *)param_2)) &&
         ((uVar1 == 1 ||
          ((*(char *)((int)param_1 + 1) == *(char *)((int)param_2 + 1) &&
           ((uVar1 == 2 || (*(char *)((int)param_1 + 2) == *(char *)((int)param_2 + 2))))))))) {
        return (int *)0x0;
      }
      return param_1;
    }
    if (*param_1 != *param_2) {
      return param_1;
    }
    if (uVar1 == 1) {
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      goto LAB_00406fe4;
    }
    if (param_1[1] != param_2[1]) {
      return param_1;
    }
    param_1 = param_1 + 2;
    param_2 = param_2 + 2;
    uVar1 = uVar1 - 2;
  } while( true );
}



void FUN_00407024(byte *param_1,int param_2,int param_3,byte *param_4)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  
  bVar1 = *param_1;
  if (bVar1 == 0) {
    *param_4 = 0;
    return;
  }
  if (param_2 < 1) {
    param_2 = 1;
LAB_0040703c:
    iVar2 = ((uint)bVar1 - param_2) + 1;
    if (-1 < param_3) {
      if (iVar2 < param_3) {
        param_3 = iVar2;
      }
      goto LAB_00407047;
    }
  }
  else if (param_2 <= (int)(uint)bVar1) goto LAB_0040703c;
  param_3 = 0;
LAB_00407047:
  *param_4 = (byte)param_3;
  pbVar3 = param_1 + param_2;
  for (; param_4 = param_4 + 1, param_3 != 0; param_3 = param_3 + -1) {
    *param_4 = *pbVar3;
    pbVar3 = pbVar3 + 1;
  }
  return;
}



void FUN_00407068(longlong **param_1,LPCWSTR param_2,ushort param_3)

{
  uint uVar1;
  LPCWSTR pWVar2;
  
  uVar1 = 0;
  pWVar2 = param_2;
  if (param_2 != (LPCWSTR)0x0) {
    for (; *pWVar2 != L'\0'; pWVar2 = pWVar2 + 4) {
      if (pWVar2[1] == L'\0') {
LAB_00407098:
        pWVar2 = pWVar2 + 1;
        break;
      }
      if (pWVar2[2] == L'\0') {
LAB_00407095:
        pWVar2 = pWVar2 + 1;
        goto LAB_00407098;
      }
      if (pWVar2[3] == L'\0') {
        pWVar2 = pWVar2 + 1;
        goto LAB_00407095;
      }
    }
    uVar1 = (uint)((int)pWVar2 - (int)param_2) >> 1;
  }
  FUN_00406d78(param_1,param_2,uVar1,param_3);
  return;
}



int FUN_004070e0(int param_1)

{
  int iVar1;
  
  if (param_1 == 0) {
    iVar1 = FUN_004070e0((int)PTR_DAT_004279f0);
    return iVar1 + 0xc;
  }
  return param_1;
}



void FUN_004070f8(longlong **param_1,uint param_2,int param_3)

{
  longlong *plVar1;
  uint uVar2;
  longlong *plVar3;
  int local_14;
  
  local_14 = 0;
  plVar3 = (longlong *)0x0;
  if (0 < (int)param_2) {
    plVar3 = *param_1;
    if ((plVar3 != (longlong *)0x0) && (*(int *)(plVar3 + -1) == 1)) {
      if (!SCARRY4(param_2,0xd)) {
        local_14 = (int)plVar3 + -0xc;
        FUN_004044ec(&local_14,param_2 + 0xd);
        *param_1 = (longlong *)(local_14 + 0xc);
        *(uint *)(local_14 + 8) = param_2;
        *(undefined *)(param_2 + (int)(longlong *)(local_14 + 0xc)) = 0;
        return;
      }
      thunk_FUN_004045f4((byte)((int)plVar3 + -0xc));
      return;
    }
    plVar3 = (longlong *)FUN_00406ad4(param_2,param_3);
    plVar1 = *param_1;
    if (plVar1 != (longlong *)0x0) {
      uVar2 = *(uint *)((int)plVar1 + -4);
      if ((int)param_2 <= (int)*(uint *)((int)plVar1 + -4)) {
        uVar2 = param_2;
      }
      FUN_0040465c(plVar1,plVar3,uVar2);
    }
  }
  FUN_00406b4c((int *)param_1);
  *param_1 = plVar3;
  return;
}



void FUN_00407170(longlong **param_1,LPCWSTR param_2,ushort param_3)

{
  int iVar1;
  
  iVar1 = 0;
  if (param_2 != (LPCWSTR)0x0) {
    iVar1 = *(int *)(param_2 + -2);
  }
  FUN_00406d78(param_1,param_2,iVar1,param_3);
  return;
}



int FUN_004071e4(int param_1)

{
  int iVar1;
  
  if (param_1 == 0) {
    iVar1 = FUN_004070e0((int)PTR_DAT_004279f4);
    return iVar1 + 0xc;
  }
  return param_1;
}



void FUN_004071fc(longlong **param_1,undefined4 param_2)

{
  undefined4 uStack_4;
  
  uStack_4 = param_2;
  FUN_00406c80(param_1,(longlong *)&uStack_4,1);
  return;
}



void FUN_0040720c(longlong **param_1,LPCSTR param_2)

{
  int iVar1;
  char *pcVar2;
  
  iVar1 = 0;
  pcVar2 = param_2;
  if (param_2 != (LPCSTR)0x0) {
    for (; *pcVar2 != '\0'; pcVar2 = pcVar2 + 4) {
      if (pcVar2[1] == '\0') {
LAB_0040722d:
        pcVar2 = pcVar2 + 1;
        break;
      }
      if (pcVar2[2] == '\0') {
LAB_0040722c:
        pcVar2 = pcVar2 + 1;
        goto LAB_0040722d;
      }
      if (pcVar2[3] == '\0') {
        pcVar2 = pcVar2 + 1;
        goto LAB_0040722c;
      }
    }
    iVar1 = (int)pcVar2 - (int)param_2;
  }
  FUN_00406d68(param_1,param_2,iVar1);
  return;
}



void FUN_0040723c(longlong **param_1,longlong *param_2)

{
  uint uVar1;
  longlong *plVar2;
  
  uVar1 = 0;
  plVar2 = param_2;
  if (param_2 != (longlong *)0x0) {
    for (; *(short *)plVar2 != 0; plVar2 = plVar2 + 1) {
      if (*(short *)((int)plVar2 + 2) == 0) {
LAB_00407265:
        plVar2 = (longlong *)((int)plVar2 + 2);
        break;
      }
      if (*(short *)((int)plVar2 + 4) == 0) {
LAB_00407262:
        plVar2 = (longlong *)((int)plVar2 + 2);
        goto LAB_00407265;
      }
      if (*(short *)((int)plVar2 + 6) == 0) {
        plVar2 = (longlong *)((int)plVar2 + 2);
        goto LAB_00407262;
      }
    }
    uVar1 = (uint)((int)plVar2 - (int)param_2) >> 1;
  }
  FUN_00406c80(param_1,param_2,uVar1);
  return;
}



void FUN_00407278(longlong **param_1,longlong *param_2,uint param_3)

{
  uint uVar1;
  longlong *plVar2;
  bool bVar3;
  
  bVar3 = true;
  uVar1 = param_3;
  plVar2 = param_2;
  do {
    if (uVar1 == 0) break;
    uVar1 = uVar1 - 1;
    bVar3 = *(short *)plVar2 == 0;
    plVar2 = (longlong *)((int)plVar2 + 2);
  } while (!bVar3);
  if (bVar3) {
    uVar1 = ~uVar1;
  }
  FUN_00406c80(param_1,param_2,uVar1 + param_3);
  return;
}



void FUN_00407294(longlong **param_1,LPCSTR param_2)

{
  if (param_2 != (LPCSTR)0x0) {
    FUN_00406cd4(param_1,param_2,*(int *)(param_2 + -4),(uint)*(ushort *)(param_2 + -0xc));
    return;
  }
  FUN_00406d68(param_1,(LPCSTR)0x0,0);
  return;
}



void FUN_004072b4(BSTR *param_1,OLECHAR *param_2)

{
  UINT UVar1;
  
  UVar1 = 0;
  if (param_2 != (OLECHAR *)0x0) {
    UVar1 = *(UINT *)(param_2 + -2);
  }
  FUN_00406cb0(param_1,param_2,UVar1);
  return;
}



void FUN_004072c4(longlong **param_1,byte *param_2)

{
  FUN_00406d68(param_1,(LPCSTR)(param_2 + 1),(uint)*param_2);
  return;
}



// WARNING: Removing unreachable block (ram,0x00407310)

void FUN_004072d0(longlong **param_1,int param_2)

{
  longlong *plVar1;
  int iVar2;
  longlong *plVar3;
  int iStack_10;
  
  plVar3 = (longlong *)0x0;
  if (0 < param_2) {
    plVar3 = *param_1;
    if ((plVar3 != (longlong *)0x0) && (*(int *)(plVar3 + -1) == 1)) {
      iStack_10 = (int)plVar3 + -0xc;
      if ((!SCARRY4(param_2,param_2)) && (!SCARRY4(param_2 * 2,0xe))) {
        FUN_004044ec(&iStack_10,param_2 * 2 + 0xe);
        *param_1 = (longlong *)(iStack_10 + 0xc);
        *(int *)(iStack_10 + 8) = param_2;
        *(undefined2 *)((int)(longlong *)(iStack_10 + 0xc) + param_2 * 2) = 0;
        return;
      }
      thunk_FUN_004045f4((byte)iStack_10);
      return;
    }
    iStack_10 = 0x407327;
    plVar3 = (longlong *)FUN_00406a94(param_2);
    plVar1 = *param_1;
    if (plVar1 != (longlong *)0x0) {
      iVar2 = *(int *)((int)plVar1 + -4);
      if (param_2 <= *(int *)((int)plVar1 + -4)) {
        iVar2 = param_2;
      }
      iStack_10 = 0x407341;
      FUN_0040465c(plVar1,plVar3,iVar2 << 1);
    }
  }
  iStack_10 = 0x407348;
  FUN_00406b4c((int *)param_1);
  *param_1 = plVar3;
  return;
}



void FUN_00407350(longlong **param_1,longlong *param_2)

{
  longlong *plVar1;
  int iVar2;
  longlong *plVar3;
  int iVar4;
  uint uVar5;
  
  if (param_2 == (longlong *)0x0) {
    return;
  }
  plVar3 = *param_1;
  if (plVar3 != (longlong *)0x0) {
    iVar2 = *(int *)((int)plVar3 + -4);
    uVar5 = *(int *)((int)param_2 + -4) + iVar2;
    if ((uVar5 & 0xc0000000) == 0) {
      if (param_2 == plVar3) {
        FUN_004072d0(param_1,uVar5);
        param_2 = *param_1;
        iVar4 = iVar2;
      }
      else {
        FUN_004072d0(param_1,uVar5);
        iVar4 = *(int *)((int)param_2 + -4);
      }
      FUN_0040465c(param_2,(longlong *)((int)*param_1 + iVar2 * 2),iVar4 << 1);
      return;
    }
    thunk_FUN_004045f4((byte)param_1);
    return;
  }
  if (param_2 != (longlong *)0x0) {
    iVar2 = *(int *)(param_2 + -1);
    if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
      plVar3 = (longlong *)FUN_00406a94(*(int *)((int)param_2 + -4));
      FUN_0040465c(param_2,plVar3,*(int *)((int)param_2 + -4) << 1);
      param_2 = plVar3;
    }
    else {
      LOCK();
      *(int *)(param_2 + -1) = *(int *)(param_2 + -1) + 1;
      UNLOCK();
    }
  }
  LOCK();
  plVar3 = *param_1;
  *param_1 = param_2;
  UNLOCK();
  if ((plVar3 != (longlong *)0x0) && (0 < *(int *)(plVar3 + -1))) {
    LOCK();
    plVar1 = plVar3 + -1;
    *(int *)plVar1 = *(int *)plVar1 + -1;
    UNLOCK();
    if (*(int *)plVar1 == 0) {
      FUN_004044d4((int)plVar3 + -0xc);
    }
  }
  return;
}



void FUN_004073a8(longlong **param_1,longlong *param_2,longlong *param_3)

{
  longlong *plVar1;
  int iVar2;
  uint uVar3;
  longlong *plVar4;
  
  if (param_2 == (longlong *)0x0) {
    FUN_00406dfc(param_1,param_3);
    return;
  }
  if (param_3 == (longlong *)0x0) {
    if (param_2 != (longlong *)0x0) {
      iVar2 = *(int *)(param_2 + -1);
      if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
        plVar4 = (longlong *)FUN_00406a94(*(int *)((int)param_2 + -4));
        FUN_0040465c(param_2,plVar4,*(int *)((int)param_2 + -4) << 1);
        param_2 = plVar4;
      }
      else {
        LOCK();
        *(int *)(param_2 + -1) = *(int *)(param_2 + -1) + 1;
        UNLOCK();
      }
    }
    LOCK();
    plVar4 = *param_1;
    *param_1 = param_2;
    UNLOCK();
    if ((plVar4 != (longlong *)0x0) && (0 < *(int *)(plVar4 + -1))) {
      LOCK();
      plVar1 = plVar4 + -1;
      *(int *)plVar1 = *(int *)plVar1 + -1;
      UNLOCK();
      if (*(int *)plVar1 == 0) {
        FUN_004044d4((int)plVar4 + -0xc);
      }
    }
    return;
  }
  if (param_2 == *param_1) {
    FUN_00407350(param_1,param_3);
    return;
  }
  if (param_3 != *param_1) {
    FUN_00406dfc(param_1,param_2);
    FUN_00407350(param_1,param_3);
    return;
  }
  uVar3 = *(int *)((int)param_2 + -4) + *(int *)((int)param_3 + -4);
  if ((uVar3 & 0xc0000000) == 0) {
    plVar4 = (longlong *)FUN_00406a94(uVar3);
    FUN_0040465c(param_2,plVar4,*(int *)((int)param_2 + -4) << 1);
    FUN_0040465c(param_3,(longlong *)(*(int *)((int)param_2 + -4) * 2 + (int)plVar4),
                 *(int *)((int)param_3 + -4) << 1);
    if (plVar4 != (longlong *)0x0) {
      *(int *)(plVar4 + -1) = *(int *)(plVar4 + -1) + -1;
    }
    FUN_00406dfc(param_1,plVar4);
    return;
  }
  thunk_FUN_004045f4((byte)uVar3);
  return;
}



void FUN_00407430(longlong **param_1,int param_2)

{
  uint uVar1;
  longlong *plVar2;
  int iVar3;
  longlong *plVar4;
  longlong *plVar5;
  longlong **pplVar6;
  code *UNRECOVERED_JUMPTABLE;
  longlong *local_1c;
  
  plVar5 = (longlong *)0x0;
  plVar2 = *(longlong **)(&stack0x00000000 + param_2 * 4);
  if ((plVar2 == (longlong *)0x0) || (*param_1 != plVar2)) {
    uVar1 = 0;
    iVar3 = param_2;
  }
  else {
    uVar1 = *(uint *)((int)plVar2 + -4);
    iVar3 = param_2 + -1;
    plVar5 = plVar2;
  }
  do {
    plVar2 = *(longlong **)(&stack0x00000000 + iVar3 * 4);
    if (plVar2 != (longlong *)0x0) {
      uVar1 = uVar1 + *(int *)((int)plVar2 + -4);
      if ((uVar1 & 0xc0000000) != 0) {
        thunk_FUN_004045f4((byte)uVar1);
        return;
      }
      if (plVar5 == plVar2) {
        plVar5 = (longlong *)0x0;
      }
    }
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  if (plVar5 == (longlong *)0x0) {
    plVar2 = (longlong *)FUN_00406a94(uVar1);
    pplVar6 = (longlong **)0x0;
    local_1c = plVar2;
  }
  else {
    iVar3 = *(int *)((int)plVar5 + -4);
    FUN_004072d0(param_1,uVar1);
    param_2 = param_2 + -1;
    plVar2 = (longlong *)(iVar3 * 2 + (int)*param_1);
    pplVar6 = param_1;
    local_1c = *param_1;
  }
  do {
    plVar5 = *(longlong **)(&stack0x00000000 + param_2 * 4);
    plVar4 = plVar2;
    if (plVar5 != (longlong *)0x0) {
      uVar1 = *(int *)((int)plVar5 + -4) * 2;
      plVar4 = (longlong *)((int)plVar2 + uVar1);
      FUN_0040465c(plVar5,plVar2,uVar1);
    }
    param_2 = param_2 + -1;
    plVar2 = plVar4;
  } while (param_2 != 0);
  if (pplVar6 == (longlong **)0x0) {
    if (local_1c != (longlong *)0x0) {
      *(int *)(local_1c + -1) = *(int *)(local_1c + -1) + -1;
    }
    FUN_00406dfc(param_1,local_1c);
  }
                    // WARNING: Could not recover jumptable at 0x004074d7. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)(UNRECOVERED_JUMPTABLE);
  return;
}



void FUN_004074e0(int param_1,int param_2,int param_3,longlong **param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = param_1;
  if (param_1 != 0) {
    iVar2 = *(int *)(param_1 + -4);
  }
  if (param_2 < 1) {
    iVar1 = 0;
  }
  else {
    iVar1 = param_2 + -1;
    if (iVar2 < param_2 + -1) {
      iVar1 = iVar2;
    }
  }
  if (param_3 < 0) {
    iVar3 = 0;
  }
  else {
    iVar3 = iVar2 - iVar1;
    if (param_3 < iVar2 - iVar1) {
      iVar3 = param_3;
    }
  }
  FUN_00406c80(param_4,(longlong *)(iVar1 * 2 + param_1),iVar3);
  return;
}



void FUN_00407528(longlong *param_1,longlong **param_2,int param_3)

{
  int iVar1;
  longlong *plVar2;
  longlong *plVar3;
  longlong *plVar4;
  longlong *plVar5;
  
  plVar3 = param_1;
  if (param_1 != (longlong *)0x0) {
    plVar3 = *(longlong **)((int)param_1 + -4);
  }
  if (0 < (int)plVar3) {
    plVar4 = *param_2;
    if (plVar4 != (longlong *)0x0) {
      plVar4 = *(longlong **)((int)plVar4 + -4);
    }
    if (param_3 < 1) {
      plVar5 = (longlong *)0x0;
    }
    else {
      plVar5 = (longlong *)(param_3 + -1);
      if ((int)plVar4 < (int)(longlong *)(param_3 + -1)) {
        plVar5 = plVar4;
      }
    }
    plVar2 = *param_2;
    iVar1 = (int)plVar3 + (int)plVar4;
    if (iVar1 < 0) {
      thunk_FUN_004045f4((byte)iVar1);
    }
    FUN_004072d0(param_2,iVar1);
    if ((int)plVar5 < (int)plVar4) {
      FUN_0040465c((longlong *)((int)*param_2 + (int)plVar5 * 2),
                   (longlong *)((int)*param_2 + ((int)plVar3 + (int)plVar5) * 2),
                   ((int)plVar4 - (int)plVar5) * 2);
    }
    if (plVar2 == param_1) {
      FUN_0040465c(*param_2,(longlong *)((int)*param_2 + (int)plVar5 * 2),(int)plVar3 * 2);
    }
    else {
      FUN_0040465c(param_1,(longlong *)((int)*param_2 + (int)plVar5 * 2),(int)plVar3 * 2);
    }
  }
  return;
}



void FUN_00407764(int param_1,char *param_2)

{
  code *pcVar1;
  bool bVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  piVar3 = (int *)(param_2 + (byte)param_2[1] + 10);
  iVar4 = *(int *)(param_2 + (byte)param_2[1] + 6);
  if (((*param_2 == '\x16') && (*(char *)(piVar3 + iVar4 * 2) != '\0')) &&
     (pcVar1 = *(code **)((int)(piVar3 + iVar4 * 2) + 1), pcVar1 != (code *)0x0)) {
    (*pcVar1)();
  }
  else if (iVar4 != 0) {
    do {
      if ((char **)*piVar3 != (char **)0x0) {
        FUN_004077b4((undefined4 *)(piVar3[1] + param_1),*(char **)*piVar3,1);
      }
      piVar3 = piVar3 + 2;
      iVar5 = iVar4 + -1;
      bVar2 = 0 < iVar4;
      iVar4 = iVar5;
    } while (iVar5 != 0 && bVar2);
  }
  return;
}



void FUN_004077b4(undefined4 *param_1,char *param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  
  if (param_3 == 0) {
    return;
  }
  cVar1 = *param_2;
  uVar3 = (uint)(byte)param_2[1];
  if ((cVar1 == '\n') || (cVar1 == '\v')) {
LAB_004077fc:
    do {
      *param_1 = 0;
      param_1 = param_1 + 1;
      iVar4 = param_3 + -1;
      bVar2 = 0 < param_3;
      param_3 = iVar4;
    } while (iVar4 != 0 && bVar2);
  }
  else {
    if (cVar1 == '\f') {
      do {
        *param_1 = 0;
        param_1[1] = 0;
        param_1[2] = 0;
        param_1[3] = 0;
        param_1 = param_1 + 4;
        iVar4 = param_3 + -1;
        bVar2 = 0 < param_3;
        param_3 = iVar4;
      } while (iVar4 != 0 && bVar2);
      return;
    }
    if (cVar1 == '\r') {
      do {
        iVar4 = *(int *)(param_2 + uVar3 + 2);
        FUN_004077b4(param_1,**(char ***)(param_2 + uVar3 + 10),*(int *)(param_2 + uVar3 + 6));
        iVar5 = param_3 + -1;
        bVar2 = 0 < param_3;
        param_1 = (undefined4 *)((int)param_1 + iVar4);
        param_3 = iVar5;
      } while (iVar5 != 0 && bVar2);
      return;
    }
    if (cVar1 != '\x0e') {
      if (((cVar1 == '\x0f') || (cVar1 == '\x11')) || (cVar1 == '\x12')) goto LAB_004077fc;
      if (cVar1 != '\x16') {
        FUN_004045f4(2);
        return;
      }
    }
    do {
      iVar4 = *(int *)(param_2 + uVar3 + 2);
      FUN_00407764((int)param_1,param_2);
      iVar5 = param_3 + -1;
      bVar2 = 0 < param_3;
      param_1 = (undefined4 *)((int)param_1 + iVar4);
      param_3 = iVar5;
    } while (iVar5 != 0 && bVar2);
  }
  return;
}



undefined4 FUN_00407850(char *param_1)

{
  byte bVar1;
  undefined4 uVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  
  uVar2 = 0;
  for (; *param_1 == '\r'; param_1 = **(char ***)(param_1 + (byte)param_1[1] + 10)) {
  }
  if (*param_1 == '\x16') {
    pcVar3 = param_1 + *(int *)(param_1 + (byte)param_1[1] + 6) * 8 + (byte)param_1[1] + 10;
    if ((*pcVar3 == '\0') || (*(int *)(pcVar3 + 1) == 0)) {
      uVar2 = 0;
    }
    else {
      uVar2 = CONCAT31((int3)((uint)pcVar3 >> 8),1);
    }
  }
  if (((char)uVar2 == '\0') &&
     (((*param_1 == '\x0e' || (*param_1 == '\x16')) &&
      (bVar1 = param_1[1], *(int *)(param_1 + bVar1 + 6) != 0)))) {
    iVar5 = *(int *)(param_1 + bVar1 + 6);
    iVar4 = 0;
    do {
      if ((*(char ***)(param_1 + iVar4 * 8 + bVar1 + 10) != (char **)0x0) &&
         (uVar2 = FUN_00407850(**(char ***)(param_1 + iVar4 * 8 + bVar1 + 10)), (char)uVar2 != '\0')
         ) {
        return uVar2;
      }
      iVar4 = iVar4 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  return uVar2;
}



int FUN_004078e0(int param_1,char *param_2)

{
  code *pcVar1;
  bool bVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  
  piVar4 = (int *)(param_2 + (byte)param_2[1] + 10);
  iVar3 = *(int *)(param_2 + (byte)param_2[1] + 6);
  if (((*param_2 == '\x16') && (1 < *(byte *)(piVar4 + iVar3 * 2))) &&
     (pcVar1 = *(code **)((int)(piVar4 + iVar3 * 2) + 5), pcVar1 != (code *)0x0)) {
    (*pcVar1)();
  }
  else if (iVar3 != 0) {
    do {
      if ((char **)*piVar4 == (char **)0x0) {
        iVar3 = iVar3 + -1;
        do {
          if (**(char **)piVar4[2] != '\x0f') {
            iVar3 = FUN_004045f4(2);
            return iVar3;
          }
          FUN_0040a8a0((int *)(piVar4[3] + param_1));
          iVar5 = iVar3 + -1;
          bVar2 = 0 < iVar3;
          iVar3 = iVar5;
          piVar4 = piVar4 + 2;
        } while (iVar5 != 0 && bVar2);
        return param_1;
      }
      FUN_00407970((int **)(piVar4[1] + param_1),*(char **)*piVar4,1);
      piVar4 = piVar4 + 2;
      iVar5 = iVar3 + -1;
      bVar2 = 0 < iVar3;
      iVar3 = iVar5;
    } while (iVar5 != 0 && bVar2);
  }
  return param_1;
}



void FUN_00407958(void)

{
  if (DAT_00427010 != (code *)0x0) {
    (*DAT_00427010)();
    return;
  }
  FUN_004045f4(0x10);
  return;
}



int ** FUN_00407970(int **param_1,char *param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  int **ppiVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  if (param_3 != 0) {
    cVar1 = *param_2;
    uVar4 = (uint)(byte)param_2[1];
    if (cVar1 == '\n') {
      if (param_3 < 2) {
        FUN_00406b4c((int *)param_1);
      }
      else {
        FUN_00406bb8((int *)param_1,param_3);
      }
    }
    else if (cVar1 == '\x12') {
      if (param_3 < 2) {
        FUN_00406b28((int *)param_1);
      }
      else {
        FUN_00406b88((int *)param_1,param_3);
      }
    }
    else if (cVar1 == '\v') {
      if (param_3 < 2) {
        FUN_00406b70((BSTR *)param_1);
      }
      else {
        FUN_00406be8((BSTR *)param_1,param_3);
      }
    }
    else if (cVar1 == '\f') {
      do {
        FUN_00407958();
        iVar6 = param_3 + -1;
        bVar2 = 0 < param_3;
        param_3 = iVar6;
      } while (iVar6 != 0 && bVar2);
    }
    else {
      ppiVar3 = param_1;
      if (cVar1 == '\r') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00407970(ppiVar3,**(char ***)(param_2 + uVar4 + 10),*(int *)(param_2 + uVar4 + 6));
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else {
        if (cVar1 != '\x0e') {
          if (cVar1 == '\x0f') {
            do {
              FUN_00409570(ppiVar3);
              iVar6 = param_3 + -1;
              bVar2 = 0 < param_3;
              ppiVar3 = ppiVar3 + 1;
              param_3 = iVar6;
            } while (iVar6 != 0 && bVar2);
            return param_1;
          }
          if (cVar1 == '\x11') {
            do {
              FUN_004088c8((int *)ppiVar3,(int)param_2);
              iVar6 = param_3 + -1;
              bVar2 = 0 < param_3;
              ppiVar3 = ppiVar3 + 1;
              param_3 = iVar6;
            } while (iVar6 != 0 && bVar2);
            return param_1;
          }
          if (cVar1 != '\x16') {
            ppiVar3 = (int **)FUN_004045f4(2);
            return ppiVar3;
          }
        }
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_004078e0((int)ppiVar3,param_2);
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
    }
  }
  return param_1;
}



void FUN_00407a8c(int **param_1,char *param_2)

{
  FUN_00407970(param_1,param_2,1);
  return;
}



void FUN_00407a98(undefined param_1,undefined4 param_2)

{
  if (DAT_00427014 != (code *)0x0) {
    (*DAT_00427014)(param_1,param_2);
    return;
  }
  FUN_004045f4(0x10);
  return;
}



void FUN_00407abc(int param_1,int param_2,char *param_3)

{
  char cVar1;
  code *pcVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  int *piVar10;
  int *piVar11;
  int *piVar12;
  
  piVar9 = (int *)(param_3 + (byte)param_3[1] + 10);
  iVar8 = piVar9[-1];
  if (((*param_3 == '\x16') && (2 < *(byte *)(piVar9 + iVar8 * 2))) &&
     (pcVar2 = *(code **)((int)(piVar9 + iVar8 * 2) + 9), pcVar2 != (code *)0x0)) {
    (*pcVar2)(param_1,param_2,pcVar2,param_3,0,0);
  }
  else {
    iVar4 = 0;
    iVar7 = piVar9[-2];
    if (iVar8 != 0) {
      piVar11 = piVar9 + iVar8 * 2;
      iVar5 = iVar8;
      do {
        if (piVar9[iVar5 * 2 + -2] == 0) {
          iVar8 = iVar8 + -1;
          piVar12 = piVar9 + iVar5 * 2;
          break;
        }
        iVar5 = iVar5 + -1;
        piVar12 = piVar11;
      } while (iVar5 != 0);
      do {
        piVar10 = piVar9;
        if (((piVar12 != piVar11) && (*piVar12 != 0)) &&
           ((*piVar9 == 0 || ((uint)piVar12[1] < (uint)piVar9[1] || piVar12[1] == piVar9[1])))) {
          LOCK();
          UNLOCK();
          piVar10 = piVar12;
          piVar12 = piVar9;
        }
        uVar6 = piVar10[1] - iVar4;
        if (uVar6 != 0 && iVar4 <= piVar10[1]) {
          FUN_0040465c((longlong *)(iVar4 + param_2),(longlong *)(iVar4 + param_1),uVar6);
        }
        iVar5 = piVar10[1];
        pcVar3 = *(char **)*piVar10;
        cVar1 = *pcVar3;
        if (cVar1 == '\x0f') {
          if (piVar10 < piVar12) {
            FUN_00409588((int **)(iVar5 + param_1),*(int ***)(iVar5 + param_2));
            iVar4 = 4;
          }
          else {
            FUN_0040a8cc((int *)(int **)(iVar5 + param_1),*(int ***)(iVar5 + param_2));
            iVar4 = 4;
          }
        }
        else {
          if (piVar12 < piVar10) {
LAB_00407b9d:
            FUN_004045f4(2);
            return;
          }
          if (cVar1 == '\n') {
            FUN_00406e98((longlong **)(iVar5 + param_1),*(longlong **)(iVar5 + param_2));
            iVar4 = 4;
          }
          else if (cVar1 == '\v') {
            FUN_00406e70((BSTR *)(iVar5 + param_1),*(OLECHAR **)(iVar5 + param_2));
            iVar4 = 4;
          }
          else if (cVar1 == '\x12') {
            FUN_00406dfc((longlong **)(iVar5 + param_1),*(longlong **)(iVar5 + param_2));
            iVar4 = 4;
          }
          else if (cVar1 == '\f') {
            FUN_00407a98((char)iVar5 + (char)param_1,iVar5 + param_2);
            iVar4 = 0x10;
          }
          else if (cVar1 == '\r') {
            uVar6 = (uint)(byte)pcVar3[1];
            iVar4 = *(int *)(pcVar3 + uVar6 + 2);
            FUN_00407ee4((double **)(iVar5 + param_1),(double **)(iVar5 + param_2),
                         **(char ***)(pcVar3 + uVar6 + 10),*(int *)(pcVar3 + uVar6 + 6));
          }
          else {
            if (cVar1 != '\x0e') {
              if (cVar1 == '\x11') {
                FUN_0040890c((double **)(iVar5 + param_1),*(double **)(iVar5 + param_2),(int)pcVar3)
                ;
                iVar4 = 4;
                goto LAB_00407c63;
              }
              if (cVar1 != '\x16') goto LAB_00407b9d;
            }
            iVar4 = *(int *)(pcVar3 + (byte)pcVar3[1] + 2);
            FUN_00407abc(iVar5 + param_1,iVar5 + param_2,pcVar3);
          }
        }
LAB_00407c63:
        iVar4 = iVar4 + piVar10[1];
        piVar9 = piVar10 + 2;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
    if (iVar7 - iVar4 != 0 && iVar4 <= iVar7) {
      FUN_0040465c((longlong *)(iVar4 + param_2),(longlong *)(iVar4 + param_1),iVar7 - iVar4);
    }
  }
  return;
}



void FUN_00407c88(int param_1,int param_2,char *param_3)

{
  byte bVar1;
  byte bVar2;
  char *pcVar3;
  longlong *plVar4;
  longlong *plVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint local_20;
  uint local_14;
  
  bVar1 = param_3[1];
  if (*param_3 == '\x16') {
    FUN_00407abc(param_1,param_2,param_3);
    FUN_004078e0(param_2,param_3);
  }
  else {
    uVar9 = 0;
    local_14 = *(uint *)(param_3 + bVar1 + 6);
    if (local_14 != 0) {
      iVar8 = local_14 - 1;
      do {
        if (*(int *)(param_3 + iVar8 * 8 + bVar1 + 10) == 0) {
          local_14 = local_14 - 1;
          uVar6 = iVar8 + 1;
          break;
        }
        iVar8 = iVar8 + -1;
        uVar6 = local_14;
      } while (iVar8 != -1);
      local_20 = 0;
      do {
        if ((*(int *)(param_3 + local_20 * 8 + bVar1 + 10) == 0) ||
           ((uVar6 != *(uint *)(param_3 + bVar1 + 6) &&
            (*(uint *)(param_3 + uVar6 * 8 + bVar1 + 0xe) <=
             *(uint *)(param_3 + local_20 * 8 + bVar1 + 0xe))))) {
          uVar7 = uVar6 + 1;
        }
        else {
          uVar7 = uVar6;
          uVar6 = local_20;
          local_20 = local_20 + 1;
        }
        if (uVar9 < *(uint *)(param_3 + uVar6 * 8 + bVar1 + 0xe)) {
          FUN_0040465c((longlong *)(param_2 + uVar9),(longlong *)(param_1 + uVar9),
                       *(uint *)(param_3 + uVar6 * 8 + bVar1 + 0xe) - uVar9);
        }
        uVar9 = *(uint *)(param_3 + uVar6 * 8 + bVar1 + 0xe);
        pcVar3 = **(char ***)(param_3 + uVar6 * 8 + bVar1 + 10);
        plVar4 = (longlong *)(param_1 + uVar9);
        plVar5 = (longlong *)(param_2 + uVar9);
        switch(*pcVar3) {
        case '\n':
          FUN_00406e98((longlong **)plVar4,*(longlong **)plVar5);
          FUN_00406b4c((int *)plVar5);
          uVar9 = uVar9 + 4;
          break;
        case '\v':
          FUN_00406e70((BSTR *)plVar4,*(OLECHAR **)plVar5);
          FUN_00406b70((BSTR *)plVar5);
          uVar9 = uVar9 + 4;
          break;
        case '\f':
          FUN_00407a98((char)plVar4,plVar5);
          FUN_00407958();
          uVar9 = uVar9 + 0x10;
          break;
        case '\r':
          bVar2 = pcVar3[1];
          FUN_00408008(plVar4,plVar5,**(char ***)(pcVar3 + bVar2 + 10),*(int *)(pcVar3 + bVar2 + 6))
          ;
          uVar9 = uVar9 + *(int *)(pcVar3 + bVar2 + 2);
          break;
        case '\x0e':
        case '\x16':
          bVar2 = pcVar3[1];
          FUN_00407c88((int)plVar4,(int)plVar5,pcVar3);
          uVar9 = uVar9 + *(int *)(pcVar3 + bVar2 + 2);
          break;
        case '\x0f':
          if (local_20 < uVar6) {
            FUN_0040a8cc((int *)plVar4,*(int ***)plVar5);
            FUN_0040a8a0((int *)plVar5);
          }
          else {
            FUN_00409588((int **)plVar4,*(int ***)plVar5);
            FUN_00409570((int **)plVar5);
          }
          uVar9 = uVar9 + 4;
          break;
        default:
          FUN_004045f4(2);
          break;
        case '\x11':
          FUN_0040890c((double **)plVar4,*(double **)plVar5,(int)pcVar3);
          FUN_004088c8((int *)plVar5,(int)pcVar3);
          uVar9 = uVar9 + 4;
          break;
        case '\x12':
          FUN_00406dfc((longlong **)plVar4,*(longlong **)plVar5);
          FUN_00406b28((int *)plVar5);
          uVar9 = uVar9 + 4;
        }
        local_14 = local_14 - 1;
        uVar6 = uVar7;
      } while (local_14 != 0);
    }
    if (uVar9 < *(uint *)(param_3 + bVar1 + 2)) {
      FUN_0040465c((longlong *)(param_2 + uVar9),(longlong *)(param_1 + uVar9),
                   *(uint *)(param_3 + bVar1 + 2) - uVar9);
    }
  }
  return;
}



void FUN_00407ee4(double **param_1,double **param_2,char *param_3,int param_4)

{
  int *piVar1;
  char cVar2;
  
  cVar2 = *param_3;
  if (cVar2 == '\n') {
    do {
      FUN_00406e98((longlong **)param_1,(longlong *)*param_2);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\v') {
    do {
      FUN_00406e70((BSTR *)param_1,(OLECHAR *)*param_2);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\x12') {
    do {
      FUN_00406dfc((longlong **)param_1,(longlong *)*param_2);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\f') {
    do {
      FUN_00407a98((char)param_1,param_2);
      param_1 = param_1 + 4;
      param_2 = param_2 + 4;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\r') {
    piVar1 = (int *)(param_3 + (byte)param_3[1] + 2);
    do {
      FUN_00407ee4(param_1,param_2,*(char **)piVar1[2],piVar1[1]);
      param_1 = (double **)((int)param_1 + *piVar1);
      param_2 = (double **)((int)param_2 + *piVar1);
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else {
    if (cVar2 != '\x0e') {
      if (cVar2 == '\x0f') {
        do {
          FUN_00409588((int **)param_1,(int **)*param_2);
          param_1 = param_1 + 1;
          param_2 = param_2 + 1;
          param_4 = param_4 + -1;
        } while (param_4 != 0);
        return;
      }
      if (cVar2 == '\x11') {
        do {
          FUN_0040890c(param_1,*param_2,(int)param_3);
          param_1 = param_1 + 1;
          param_2 = param_2 + 1;
          param_4 = param_4 + -1;
        } while (param_4 != 0);
        return;
      }
      if (cVar2 != '\x16') {
        FUN_004045f4(2);
        return;
      }
    }
    do {
      FUN_00407abc((int)param_1,(int)param_2,param_3);
      param_1 = (double **)((int)param_1 + *(int *)(param_3 + (byte)param_3[1] + 2));
      param_2 = (double **)((int)param_2 + *(int *)(param_3 + (byte)param_3[1] + 2));
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  return;
}



void FUN_00408008(longlong *param_1,longlong *param_2,char *param_3,int param_4)

{
  byte bVar1;
  longlong *local_8;
  
  if (param_4 != 0) {
    local_8 = param_2;
    switch(*param_3) {
    case '\a':
    case '\n':
    case '\v':
    case '\x0f':
    case '\x11':
    case '\x12':
      FUN_0040465c(param_2,param_1,param_4 * 4);
      break;
    case '\b':
      FUN_0040465c(param_2,param_1,param_4 * 8);
      break;
    default:
      FUN_004045f4(2);
      break;
    case '\f':
      FUN_0040465c(param_2,param_1,param_4 << 4);
      break;
    case '\r':
      bVar1 = param_3[1];
      if (0 < param_4) {
        do {
          FUN_00408008(param_1,local_8,**(char ***)(param_3 + bVar1 + 10),
                       *(int *)(param_3 + bVar1 + 6));
          param_1 = (longlong *)((int)param_1 + *(int *)(param_3 + bVar1 + 2));
          local_8 = (longlong *)((int)local_8 + *(int *)(param_3 + bVar1 + 2));
          param_4 = param_4 + -1;
        } while (0 < param_4);
      }
      break;
    case '\x0e':
    case '\x16':
      bVar1 = param_3[1];
      if (0 < param_4) {
        do {
          FUN_00407c88((int)param_1,(int)local_8,param_3);
          param_1 = (longlong *)((int)param_1 + *(int *)(param_3 + bVar1 + 2));
          local_8 = (longlong *)((int)local_8 + *(int *)(param_3 + bVar1 + 2));
          param_4 = param_4 + -1;
        } while (0 < param_4);
      }
    }
  }
  return;
}



void FUN_00408110(int **param_1,char *param_2)

{
  FUN_00407a8c(param_1,param_2);
  FUN_004044d4((int)param_1);
  return;
}



void FUN_00408120(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  undefined3 in_register_00000001;
  undefined3 in_register_00000005;
  undefined3 in_register_00000009;
  
  if (param_4 != 0) {
    FUN_00407ee4((double **)CONCAT31(in_register_00000001,param_1),
                 (double **)CONCAT31(in_register_00000009,param_2),
                 (char *)CONCAT31(in_register_00000005,param_3),param_4);
  }
  return;
}



int ** thunk_FUN_00407970(int **param_1,char *param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  int **ppiVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  if (param_3 != 0) {
    cVar1 = *param_2;
    uVar4 = (uint)(byte)param_2[1];
    if (cVar1 == '\n') {
      if (param_3 < 2) {
        FUN_00406b4c((int *)param_1);
      }
      else {
        FUN_00406bb8((int *)param_1,param_3);
      }
    }
    else if (cVar1 == '\x12') {
      if (param_3 < 2) {
        FUN_00406b28((int *)param_1);
      }
      else {
        FUN_00406b88((int *)param_1,param_3);
      }
    }
    else if (cVar1 == '\v') {
      if (param_3 < 2) {
        FUN_00406b70((BSTR *)param_1);
      }
      else {
        FUN_00406be8((BSTR *)param_1,param_3);
      }
    }
    else if (cVar1 == '\f') {
      do {
        FUN_00407958();
        iVar6 = param_3 + -1;
        bVar2 = 0 < param_3;
        param_3 = iVar6;
      } while (iVar6 != 0 && bVar2);
    }
    else {
      ppiVar3 = param_1;
      if (cVar1 == '\r') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00407970(ppiVar3,**(char ***)(param_2 + uVar4 + 10),*(int *)(param_2 + uVar4 + 6));
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else {
        if (cVar1 != '\x0e') {
          if (cVar1 == '\x0f') {
            do {
              FUN_00409570(ppiVar3);
              iVar6 = param_3 + -1;
              bVar2 = 0 < param_3;
              ppiVar3 = ppiVar3 + 1;
              param_3 = iVar6;
            } while (iVar6 != 0 && bVar2);
            return param_1;
          }
          if (cVar1 == '\x11') {
            do {
              FUN_004088c8((int *)ppiVar3,(int)param_2);
              iVar6 = param_3 + -1;
              bVar2 = 0 < param_3;
              ppiVar3 = ppiVar3 + 1;
              param_3 = iVar6;
            } while (iVar6 != 0 && bVar2);
            return param_1;
          }
          if (cVar1 != '\x16') {
            ppiVar3 = (int **)FUN_004045f4(2);
            return ppiVar3;
          }
        }
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_004078e0((int)ppiVar3,param_2);
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
    }
  }
  return param_1;
}



void FUN_00408140(int param_1,char *param_2)

{
  byte bVar1;
  char *pcVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  uint local_10;
  
  puStack_20 = &stack0xfffffffc;
  bVar1 = param_2[1];
  if (((*param_2 == '\x16') &&
      (pcVar2 = param_2 + *(int *)(param_2 + bVar1 + 6) * 8 + bVar1 + 10, *pcVar2 != '\0')) &&
     (*(int *)(pcVar2 + 1) != 0)) {
    puStack_20 = (undefined *)0x408183;
    (**(code **)(pcVar2 + 1))(param_1);
    return;
  }
  if (*(int *)(param_2 + bVar1 + 6) != 0) {
    local_10 = 0;
    puStack_24 = &LAB_004081e9;
    uStack_28 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_28;
    while ((local_10 < *(uint *)(param_2 + bVar1 + 6) &&
           (*(char ***)(param_2 + local_10 * 8 + bVar1 + 10) != (char **)0x0))) {
      FUN_00408234(*(int *)(param_2 + local_10 * 8 + bVar1 + 0xe) + param_1,
                   **(char ***)(param_2 + local_10 * 8 + bVar1 + 10),1);
      local_10 = local_10 + 1;
    }
    *in_FS_OFFSET = uStack_28;
  }
  return;
}



void FUN_00408234(int param_1,char *param_2,int param_3)

{
  byte bVar1;
  code *pcVar2;
  char *pcVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_2c;
  undefined *puStack_28;
  undefined *puStack_24;
  char *local_c;
  
  puStack_24 = &stack0xfffffffc;
  for (local_c = param_2; *local_c == '\r'; local_c = **(char ***)(local_c + (byte)local_c[1] + 10))
  {
    param_3 = param_3 * *(int *)(local_c + (byte)local_c[1] + 6);
  }
  bVar1 = local_c[1];
  if (((*local_c == '\x16') &&
      (pcVar3 = local_c + *(int *)(local_c + bVar1 + 6) * 8 + bVar1 + 10, *pcVar3 != '\0')) &&
     (*(int *)(pcVar3 + 1) != 0)) {
    pcVar2 = *(code **)(pcVar3 + 1);
    puStack_28 = &LAB_004082db;
    uStack_2c = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_2c;
    puStack_24 = &stack0xfffffffc;
    for (; param_3 != 0; param_3 = param_3 + -1) {
      (*pcVar2)(param_1);
      param_1 = param_1 + *(int *)(local_c + bVar1 + 2);
    }
    *in_FS_OFFSET = uStack_2c;
  }
  else if ((*local_c == '\x0e') || (*local_c == '\x16')) {
    puStack_28 = &LAB_00408352;
    uStack_2c = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_2c;
    for (; param_3 != 0; param_3 = param_3 + -1) {
      FUN_00408140(param_1,local_c);
      param_1 = param_1 + *(int *)(local_c + bVar1 + 2);
    }
    *in_FS_OFFSET = uStack_2c;
  }
  return;
}



int FUN_0040838c(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  return param_1 * param_4;
}



int FUN_004083b0(int param_1,uint param_2,undefined4 param_3,uint param_4,uint param_5)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  bool bVar5;
  
  if ((param_5 == 0) && ((param_2 == 0 || (param_4 == 0)))) {
    param_1 = (int)(CONCAT44(param_2,param_1) / (ulonglong)param_4);
  }
  else {
    iVar1 = 0x40;
    uVar3 = 0;
    uVar2 = 0;
    do {
      bVar4 = param_1 < 0;
      param_1 = param_1 * 2;
      bVar5 = (int)param_2 < 0;
      param_2 = param_2 << 1 | (uint)bVar4;
      bVar4 = (int)uVar2 < 0;
      uVar2 = uVar2 << 1 | (uint)bVar5;
      uVar3 = uVar3 << 1 | (uint)bVar4;
      if ((param_5 <= uVar3) && ((param_5 < uVar3 || (param_4 <= uVar2)))) {
        bVar4 = uVar2 < param_4;
        uVar2 = uVar2 - param_4;
        uVar3 = (uVar3 - param_5) - (uint)bVar4;
        param_1 = param_1 + 1;
      }
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined FUN_004083fc(char *param_1)

{
  byte bVar1;
  char *pcVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  
  if (param_1 != (char *)0x0) {
    while( true ) {
      if (param_1 == _DAT_0042bbf4) {
        return DAT_0042bbf8;
      }
      if (*param_1 != '\r') break;
      param_1 = **(char ***)(param_1 + (byte)param_1[1] + 10);
    }
    if (((*param_1 == '\x0e') && (bVar1 = param_1[1], *(int *)(param_1 + bVar1 + 6) != 0)) &&
       (iVar4 = *(int *)(param_1 + bVar1 + 6), -1 < iVar4 + -1)) {
      iVar5 = 0;
      do {
        if (*(int *)(param_1 + iVar5 * 8 + bVar1 + 10) == 0) {
          return 1;
        }
        pcVar2 = **(char ***)(param_1 + iVar5 * 8 + bVar1 + 10);
        if ((*pcVar2 == '\r') &&
           (cVar3 = FUN_004083fc(**(char ***)(pcVar2 + (byte)pcVar2[1] + 10)), cVar3 != '\0')) {
          return 1;
        }
        if ((*pcVar2 == '\x0e') && (cVar3 = FUN_004083fc(pcVar2), cVar3 != '\0')) {
          return 1;
        }
        iVar5 = iVar5 + 1;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  return 0;
}



uint FUN_00408498(char *param_1)

{
  LPVOID pvVar1;
  uint uVar2;
  
  pvVar1 = FUN_0040ae54();
  if (param_1 == *(char **)((int)pvVar1 + 8)) {
    pvVar1 = FUN_0040ae54();
    uVar2 = (uint)*(byte *)((int)pvVar1 + 0xc);
  }
  else {
    uVar2 = FUN_004083fc(param_1);
    pvVar1 = FUN_0040ae54();
    *(char **)((int)pvVar1 + 8) = param_1;
    pvVar1 = FUN_0040ae54();
    *(char *)((int)pvVar1 + 0xc) = (char)uVar2;
  }
  return uVar2;
}



void FUN_004084dc(longlong **param_1,int param_2,int param_3,int *param_4)

{
  int iVar1;
  char **ppcVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_40;
  undefined *puStack_3c;
  longlong *local_28;
  longlong *local_24;
  char *local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  longlong **local_8;
  
  local_24 = *param_1;
  iVar1 = *param_4;
  local_10 = param_3;
  local_c = param_2;
  local_8 = param_1;
  if (iVar1 < 1) {
    if (iVar1 < 0) {
      FUN_004045f4(4);
    }
    FUN_004088c8((int *)local_8,local_c);
  }
  else {
    iVar6 = 0;
    if (local_24 != (longlong *)0x0) {
      iVar6 = *(int *)((int)local_24 + -4);
      local_24 = local_24 + -1;
    }
    iVar5 = (uint)*(byte *)(param_2 + 1) + param_2;
    local_1c = *(int *)(iVar5 + 2);
    ppcVar2 = *(char ***)(iVar5 + 6);
    if (ppcVar2 == (char **)0x0) {
      local_20 = (char *)0x0;
    }
    else {
      local_20 = *ppcVar2;
    }
    iVar5 = iVar1 * local_1c;
    if (iVar5 / iVar1 != local_1c) {
      FUN_004045f4(4);
    }
    iVar5 = iVar5 + 8;
    if (iVar5 < 0) {
      FUN_004045f4(4);
    }
    if ((local_24 == (longlong *)0x0) || (*(int *)local_24 == 1)) {
      local_28 = local_24;
      if (local_20 == (char *)0x0) {
        FUN_004044ec((int *)&local_28,iVar5);
      }
      else {
        uVar3 = FUN_00408498(local_20);
        if ((char)uVar3 == '\0') {
          if (iVar1 < iVar6) {
            thunk_FUN_00407970((int **)((int)local_24 + iVar1 * local_1c + 8),local_20,iVar6 - iVar1
                              );
          }
          FUN_004044ec((int *)&local_28,iVar5);
        }
        else {
          local_18 = iVar6;
          if (iVar1 < iVar6) {
            local_18 = iVar1;
          }
          local_28 = (longlong *)FUN_004044b8(iVar5);
          FUN_004048f8((double *)(local_28 + 1),local_18 * local_1c,0);
          if (local_24 != (longlong *)0x0) {
            puStack_3c = (undefined *)0x4085eb;
            FUN_00408008(local_28 + 1,local_24 + 1,local_20,local_18);
            if (iVar1 < iVar6) {
              thunk_FUN_00407970((int **)((int)local_24 + iVar1 * local_1c + 8),local_20,
                                 iVar6 - iVar1);
            }
            FUN_004044d4((int)local_24);
          }
        }
      }
      local_24 = local_28;
    }
    else {
      local_24 = (longlong *)FUN_004044b8(iVar5);
      local_18 = iVar6;
      if (iVar1 < iVar6) {
        local_18 = iVar1;
      }
      if (local_20 == (char *)0x0) {
        FUN_0040465c(*local_8,local_24 + 1,local_18 * local_1c);
      }
      else {
        FUN_004048f8((double *)(local_24 + 1),local_18 * local_1c,0);
        puStack_3c = (undefined *)0x408695;
        FUN_00408120((char)local_24 + '\b',(char)*local_8,(char)local_20,local_18);
      }
      FUN_004088c8((int *)local_8,local_c);
    }
    *(int *)local_24 = 1;
    *(int *)((int)local_24 + 4) = iVar1;
    local_24 = local_24 + 1;
    if (((iVar6 < iVar1) &&
        (FUN_004048f8((double *)(local_1c * iVar6 + (int)local_24),(iVar1 - iVar6) * local_1c,0),
        local_20 != (char *)0x0)) && (uVar4 = FUN_00407850(local_20), (char)uVar4 != '\0')) {
      FUN_00408234((int)(iVar6 * local_1c + (int)local_24),local_20,iVar1 - iVar6);
    }
    if (1 < local_10) {
      local_10 = local_10 + -1;
      local_14 = 0;
      puStack_3c = &LAB_0040875a;
      uStack_40 = *in_FS_OFFSET;
      *in_FS_OFFSET = &uStack_40;
      if (0 < iVar1) {
        do {
          FUN_004084dc((longlong **)((int)local_24 + local_14 * 4),(int)local_20,local_10,
                       param_4 + 1);
          local_14 = local_14 + 1;
        } while (local_14 < iVar1);
      }
      *in_FS_OFFSET = uStack_40;
    }
    *local_8 = local_24;
  }
  return;
}



void FUN_004087a4(longlong **param_1,int param_2,int param_3)

{
  FUN_004084dc(param_1,param_2,param_3,(int *)&stack0x00000004);
  return;
}



void FUN_004087b0(int param_1,int param_2,double **param_3)

{
  if (param_1 != 0) {
    FUN_004087d4(param_1,param_2,0,param_3,*(int *)(param_1 + -4));
    return;
  }
  FUN_004088c8((int *)param_3,param_2);
  return;
}



void FUN_004087d4(int param_1,int param_2,int param_3,double **param_4,int param_5)

{
  longlong *plVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined4 *puVar5;
  double *pdVar6;
  int local_14;
  
  pdVar6 = (double *)0x0;
  if (param_1 != 0) {
    if (param_3 < 0) {
      param_5 = param_5 + param_3;
      param_3 = 0;
    }
    iVar2 = *(int *)(param_1 + -4);
    if (iVar2 < param_3) {
      param_3 = iVar2;
    }
    if (iVar2 - param_3 < param_5) {
      param_5 = iVar2 - param_3;
    }
    if (param_5 < 0) {
      param_5 = 0;
    }
    if (0 < param_5) {
      iVar2 = param_2 + (uint)*(byte *)(param_2 + 1);
      iVar3 = *(int *)(iVar2 + 2);
      piVar4 = *(int **)(iVar2 + 6);
      if (piVar4 == (int *)0x0) {
        local_14 = 0;
      }
      else {
        local_14 = *piVar4;
      }
      puVar5 = (undefined4 *)FUN_004044b8(param_5 * iVar3 + 8);
      *puVar5 = 1;
      puVar5[1] = param_5;
      pdVar6 = (double *)(puVar5 + 2);
      plVar1 = (longlong *)(param_1 + param_3 * iVar3);
      if (0 < param_5) {
        if (local_14 == 0) {
          FUN_0040465c(plVar1,(longlong *)pdVar6,param_5 * iVar3);
        }
        else {
          FUN_004048f8(pdVar6,param_5 * iVar3,0);
          FUN_00408120((char)pdVar6,(char)plVar1,(char)local_14,param_5);
        }
      }
    }
  }
  FUN_004088c8((int *)param_4,param_2);
  *param_4 = pdVar6;
  return;
}



int * FUN_004088c8(int *param_1,int param_2)

{
  int **ppiVar1;
  int **ppiVar2;
  char **ppcVar3;
  
  ppiVar2 = (int **)*param_1;
  if ((ppiVar2 != (int **)0x0) && (*param_1 = 0, 0 < (int)ppiVar2[-2])) {
    LOCK();
    ppiVar1 = ppiVar2 + -2;
    *ppiVar1 = (int *)((int)*ppiVar1 + -1);
    UNLOCK();
    if (*ppiVar1 == (int *)0x0) {
      ppcVar3 = *(char ***)(*(byte *)(param_2 + 1) + 6 + param_2);
      if ((ppcVar3 != (char **)0x0) && (ppiVar2[-1] != (int *)0x0)) {
        FUN_00407970(ppiVar2,*ppcVar3,(int)ppiVar2[-1]);
      }
      FUN_004044d4((int)(ppiVar2 + -2));
    }
  }
  return param_1;
}



void FUN_0040890c(double **param_1,double *param_2,int param_3)

{
  double *pdVar1;
  double *pdVar2;
  
  if (param_2 != (double *)0x0) {
    if (*(int *)(param_2 + -1) < 0) {
      FUN_004087b0((int)param_2,param_3,param_1);
      return;
    }
    LOCK();
    *(int *)(param_2 + -1) = *(int *)(param_2 + -1) + 1;
    UNLOCK();
  }
  pdVar2 = *param_1;
  if ((pdVar2 != (double *)0x0) && (0 < *(int *)(pdVar2 + -1))) {
    LOCK();
    pdVar1 = pdVar2 + -1;
    *(int *)pdVar1 = *(int *)pdVar1 + -1;
    UNLOCK();
    if (*(int *)pdVar1 == 0) {
      *(int *)(pdVar2 + -1) = *(int *)(pdVar2 + -1) + 1;
      FUN_004088c8((int *)param_1,param_3);
    }
  }
  *param_1 = param_2;
  return;
}



undefined4 FUN_00408948(int param_1)

{
  int iVar1;
  longlong local_214 [65];
  
  if (*(int *)(param_1 + 0x10) == 0) {
    GetModuleFileNameW(*(HMODULE *)(param_1 + 4),(LPWSTR)local_214,0x20a);
    iVar1 = FUN_0040930c(local_214);
    *(int *)(param_1 + 0x10) = iVar1;
    if (iVar1 == 0) {
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 4);
    }
  }
  return *(undefined4 *)(param_1 + 0x10);
}



int FUN_00408990(int param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = DAT_00427030;
  if (DAT_00427030 != (int *)0x0) {
    do {
      if (((param_1 == piVar2[1]) || (param_1 == piVar2[2])) || (param_1 == piVar2[3])) {
        iVar1 = FUN_00408948((int)piVar2);
        return iVar1;
      }
      piVar2 = (int *)*piVar2;
    } while (piVar2 != (int *)0x0);
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004089c4(void)

{
  DWORD DVar1;
  HMODULE pHVar2;
  char *pcVar3;
  
  InitializeCriticalSection((LPCRITICAL_SECTION)&lpCriticalSection_0042bc0c);
  _DAT_0042bc24 = 0x7f;
  DVar1 = GetVersion();
  DAT_0042bc08 = 5 < (DVar1 & 0xff);
  if ((bool)DAT_0042bc08) {
    pcVar3 = "GetThreadPreferredUILanguages";
    pHVar2 = GetModuleHandleW(L"kernel32.dll");
    _DAT_0042bbfc = GetProcAddress(pHVar2,pcVar3);
    pcVar3 = "SetThreadPreferredUILanguages";
    pHVar2 = GetModuleHandleW(L"kernel32.dll");
    _DAT_0042bc00 = GetProcAddress(pHVar2,pcVar3);
    pcVar3 = "GetThreadUILanguage";
    pHVar2 = GetModuleHandleW(L"kernel32.dll");
    _DAT_0042bc04 = GetProcAddress(pHVar2,pcVar3);
  }
  return;
}



void FUN_00408ab4(void)

{
  DeleteCriticalSection((LPCRITICAL_SECTION)&lpCriticalSection_0042bc0c);
  return;
}



void FUN_00408ac0(short *param_1,int param_2,short *param_3)

{
  short sVar1;
  
  if (param_2 == 0) {
    *param_1 = 0;
  }
  else {
    if (0 < param_2) {
      do {
        sVar1 = *param_3;
        *param_1 = sVar1;
        if (sVar1 == 0) {
          return;
        }
        param_1 = param_1 + 1;
        param_3 = param_3 + 1;
        param_2 = param_2 + -1;
      } while (0 < param_2);
    }
    if (param_2 == 0) {
      param_1[-1] = 0;
    }
  }
  return;
}



LPCWSTR FUN_00408af4(LPCWSTR param_1)

{
  for (; (*param_1 != L'\0' && (*param_1 != L'\\')); param_1 = CharNextW(param_1)) {
  }
  return param_1;
}



short * FUN_00408b18(short *param_1,int param_2)

{
  HMODULE hModule;
  FARPROC pFVar1;
  int iVar2;
  LPCWSTR pWVar3;
  LPCWSTR pWVar4;
  int iVar5;
  WCHAR local_46e [261];
  _WIN32_FIND_DATAW local_264;
  HANDLE local_14;
  short *local_10;
  int local_c;
  short *local_8;
  
  local_10 = param_1;
  local_c = param_2;
  local_8 = param_1;
  hModule = GetModuleHandleW(L"kernel32.dll");
  if (((hModule == (HMODULE)0x0) ||
      (pFVar1 = GetProcAddress(hModule,"GetLongPathNameW"), pFVar1 == (FARPROC)0x0)) ||
     (iVar2 = (*pFVar1)(), iVar2 == 0)) {
    if (*local_8 == 0x5c) {
      if (local_8[1] != 0x5c) {
        return local_10;
      }
      pWVar3 = FUN_00408af4(local_8 + 2);
      if (*pWVar3 == L'\0') {
        return local_10;
      }
      pWVar3 = FUN_00408af4(pWVar3 + 1);
      if (*pWVar3 == L'\0') {
        return local_10;
      }
    }
    else {
      pWVar3 = local_8 + 2;
    }
    iVar2 = (int)pWVar3 - (int)local_8 >> 1;
    if (iVar2 < 0) {
      iVar2 = iVar2 + (uint)(((int)pWVar3 - (int)local_8 & 1U) != 0);
    }
    if (iVar2 + 1 < 0x106) {
      FUN_00408ac0(local_46e,iVar2 + 1,local_8);
      while (*pWVar3 != L'\0') {
        pWVar4 = FUN_00408af4(pWVar3 + 1);
        iVar5 = (int)pWVar4 - (int)pWVar3 >> 1;
        if (iVar5 < 0) {
          iVar5 = iVar5 + (uint)(((int)pWVar4 - (int)pWVar3 & 1U) != 0);
        }
        if (0x105 < iVar5 + iVar2 + 1) {
          return local_10;
        }
        iVar5 = (int)pWVar4 - (int)pWVar3 >> 1;
        if (iVar5 < 0) {
          iVar5 = iVar5 + (uint)(((int)pWVar4 - (int)pWVar3 & 1U) != 0);
        }
        FUN_00408ac0(local_46e + iVar2,iVar5 + 1,pWVar3);
        local_14 = FindFirstFileW(local_46e,&local_264);
        if (local_14 == (HANDLE)0xffffffff) {
          return local_10;
        }
        FindClose(local_14);
        iVar5 = lstrlenW(local_264.cFileName);
        if (0x105 < iVar5 + iVar2 + 2) {
          return local_10;
        }
        local_46e[iVar2] = L'\\';
        FUN_00408ac0(local_46e + iVar2 + 1,0x104 - iVar2,local_264.cFileName);
        iVar5 = lstrlenW(local_264.cFileName);
        iVar2 = iVar2 + iVar5 + 1;
        pWVar3 = pWVar4;
      }
      FUN_00408ac0(local_8,local_c,local_46e);
    }
  }
  else {
    FUN_00408ac0(local_8,local_c,local_46e);
  }
  return local_10;
}



void FUN_00408d08(int param_1,longlong **param_2)

{
  short *psVar1;
  LSTATUS LVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar3;
  undefined4 uStack_230;
  undefined *puStack_22c;
  undefined *puStack_228;
  WCHAR local_21e [261];
  DWORD local_14;
  HKEY local_10;
  longlong *local_c;
  int local_8;
  
  puStack_228 = (undefined *)0x408d1f;
  local_8 = param_1;
  FUN_00406c0c(param_1);
  puStack_22c = &LAB_00408f2d;
  uStack_230 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_230;
  if (local_8 == 0) {
    puStack_228 = &stack0xfffffffc;
    GetModuleFileNameW((HMODULE)0x0,local_21e,0x105);
  }
  else {
    puStack_228 = &stack0xfffffffc;
    psVar1 = (short *)FUN_004071e4(local_8);
    FUN_00408ac0(local_21e,0x105,psVar1);
  }
  if (local_21e[0] != L'\0') {
    local_c = (longlong *)0x0;
    LVar2 = RegOpenKeyExW((HKEY)0x80000001,L"Software\\Embarcadero\\Locales",0,0xf0019,&local_10);
    if (LVar2 != 0) {
      LVar2 = RegOpenKeyExW((HKEY)0x80000002,L"Software\\Embarcadero\\Locales",0,0xf0019,&local_10);
      if (LVar2 != 0) {
        LVar2 = RegOpenKeyExW((HKEY)0x80000001,L"Software\\CodeGear\\Locales",0,0xf0019,&local_10);
        if (LVar2 != 0) {
          LVar2 = RegOpenKeyExW((HKEY)0x80000002,L"Software\\CodeGear\\Locales",0,0xf0019,&local_10)
          ;
          if (LVar2 != 0) {
            LVar2 = RegOpenKeyExW((HKEY)0x80000001,L"Software\\Borland\\Locales",0,0xf0019,&local_10
                                 );
            if (LVar2 != 0) {
              LVar2 = RegOpenKeyExW((HKEY)0x80000001,L"Software\\Borland\\Delphi\\Locales",0,0xf0019
                                    ,&local_10);
              if (LVar2 != 0) goto LAB_00408f17;
            }
          }
        }
      }
    }
    uVar3 = *in_FS_OFFSET;
    *in_FS_OFFSET = &stack0xfffffdc4;
    FUN_00408b18(local_21e,0x105);
    LVar2 = RegQueryValueExW(local_10,local_21e,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)0x0,&local_14);
    if (LVar2 == 0) {
      local_c = (longlong *)FUN_004044b8(local_14);
      RegQueryValueExW(local_10,local_21e,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)local_c,&local_14);
      FUN_0040723c(param_2,local_c);
    }
    else {
      LVar2 = RegQueryValueExW(local_10,(LPCWSTR)&lpValueName_00409020,(LPDWORD)0x0,(LPDWORD)0x0,
                               (LPBYTE)0x0,&local_14);
      if (LVar2 == 0) {
        local_c = (longlong *)FUN_004044b8(local_14);
        RegQueryValueExW(local_10,(LPCWSTR)&lpValueName_00409020,(LPDWORD)0x0,(LPDWORD)0x0,
                         (LPBYTE)local_c,&local_14);
        FUN_0040723c(param_2,local_c);
      }
    }
    *in_FS_OFFSET = uVar3;
    if (local_c != (longlong *)0x0) {
      FUN_004044d4((int)local_c);
    }
    RegCloseKey(local_10);
    return;
  }
LAB_00408f17:
  *in_FS_OFFSET = uStack_230;
  puStack_228 = &LAB_00408f34;
  puStack_22c = (undefined *)0x408f2c;
  FUN_00406b28(&local_8);
  return;
}



void FUN_00409024(int param_1,longlong **param_2)

{
  undefined *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  longlong *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_18 = &LAB_0040907b;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  puVar1 = &stack0xfffffffc;
  if (DAT_004279f8 == (longlong *)0x0) {
    FUN_00408d08(param_1,&local_8);
    FUN_00409088((int)local_8);
    puVar1 = puStack_14;
  }
  puStack_14 = puVar1;
  FUN_0040723c(param_2,DAT_004279f8);
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_00409082;
  puStack_18 = (undefined *)0x40907a;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_00409088(int param_1)

{
  byte *pbVar1;
  int iVar2;
  longlong *plVar3;
  
  if (DAT_004279f8 != (longlong *)0x0) {
    FUN_00403334((int **)DAT_004279f8);
  }
  iVar2 = param_1;
  if (param_1 != 0) {
    iVar2 = *(int *)(param_1 + -4);
  }
  if (iVar2 < 1) {
    DAT_004279f8 = (longlong *)0x0;
  }
  else {
    pbVar1 = (byte *)((iVar2 + 1) * 2);
    DAT_004279f8 = (longlong *)FUN_00402fb0(pbVar1);
    plVar3 = (longlong *)FUN_004071e4(param_1);
    FUN_0040465c(plVar3,DAT_004279f8,(uint)pbVar1);
  }
  return;
}



void FUN_004090e4(int param_1)

{
  LPCWSTR lpFileName;
  HANDLE hFindFile;
  undefined4 *in_FS_OFFSET;
  _WIN32_FIND_DATAW *lpFindFileData;
  undefined4 uStack_268;
  undefined *puStack_264;
  undefined *puStack_260;
  _WIN32_FIND_DATAW local_258;
  int local_8;
  
  puStack_260 = (undefined *)0x4090f9;
  local_8 = param_1;
  FUN_00406c0c(param_1);
  puStack_264 = &LAB_00409142;
  uStack_268 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_268;
  lpFindFileData = &local_258;
  puStack_260 = &stack0xfffffffc;
  lpFileName = (LPCWSTR)FUN_004071e4(local_8);
  hFindFile = FindFirstFileW(lpFileName,lpFindFileData);
  if (hFindFile != (HANDLE)0xffffffff) {
    FindClose(hFindFile);
  }
  *in_FS_OFFSET = uStack_268;
  puStack_260 = &LAB_00409149;
  puStack_264 = (undefined *)0x409141;
  FUN_00406b28(&local_8);
  return;
}



void FUN_00409150(longlong *param_1,int param_2,longlong **param_3)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  longlong *local_18;
  int local_14;
  longlong **local_10;
  int local_c;
  longlong *local_8;
  
  local_18 = (longlong *)0x0;
  puStack_28 = (undefined *)0x40916f;
  local_10 = param_3;
  local_c = param_2;
  local_8 = param_1;
  FUN_00406c0c((int)param_1);
  puStack_28 = (undefined *)0x409177;
  FUN_00406c0c(local_c);
  puStack_2c = &LAB_00409226;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  puStack_28 = &stack0xfffffffc;
  FUN_00406b28((int *)local_10);
  iVar2 = 1;
  while( true ) {
    iVar4 = local_c;
    if (local_c != 0) {
      iVar4 = *(int *)(local_c + -4);
    }
    iVar3 = iVar2;
    if (iVar4 < iVar2) break;
    while( true ) {
      iVar4 = local_c;
      if (local_c != 0) {
        iVar4 = *(int *)(local_c + -4);
      }
      if ((iVar4 < iVar3) || (*(short *)(local_c + -2 + iVar3 * 2) == 0x2c)) break;
      iVar3 = iVar3 + 1;
    }
    local_14 = iVar2;
    if (iVar3 != iVar2) {
      FUN_004074e0(local_c,iVar2,iVar3 - iVar2,&local_18);
      FUN_004073a8(local_10,local_8,local_18);
      cVar1 = FUN_004090e4((int)*local_10);
      if (cVar1 != '\0') goto LAB_00409203;
    }
    iVar2 = iVar3 + 1;
  }
  FUN_00406b28((int *)local_10);
LAB_00409203:
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_0040922d;
  puStack_2c = (undefined *)0x409218;
  FUN_00406b28((int *)&local_18);
  puStack_2c = (undefined *)0x409225;
  FUN_00406b88(&local_c,2);
  return;
}



void FUN_00409234(int param_1,int param_2,longlong **param_3)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  longlong *local_14;
  longlong *local_10;
  int local_c;
  int local_8;
  
  local_10 = (longlong *)0x0;
  local_14 = (longlong *)0x0;
  puStack_20 = (undefined *)0x409254;
  local_c = param_2;
  local_8 = param_1;
  FUN_00406c0c(param_1);
  puStack_20 = (undefined *)0x40925c;
  FUN_00406c0c(local_c);
  puStack_24 = &LAB_004092fc;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  puStack_20 = &stack0xfffffffc;
  FUN_00406b28((int *)param_3);
  if (local_c != 0) {
    FUN_00406e44((int *)&local_14,local_c);
    iVar1 = local_c;
    if (local_c != 0) {
      iVar1 = *(int *)(local_c + -4);
    }
    if (0 < iVar1) {
      do {
        if (*(short *)(local_c + -2 + iVar1 * 2) == 0x2e) {
          FUN_004074e0(local_c,1,iVar1,&local_14);
          break;
        }
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
    FUN_00409024(local_8,&local_10);
    if (local_10 == (longlong *)0x0) {
      FUN_00406b28((int *)param_3);
    }
    else {
      FUN_00409150(local_14,(int)local_10,param_3);
    }
  }
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &LAB_00409303;
  puStack_24 = (undefined *)0x4092fb;
  FUN_00406b88((int *)&local_14,4);
  return;
}



void FUN_0040930c(longlong *param_1)

{
  LPCWSTR lpLibFileName;
  undefined4 *in_FS_OFFSET;
  HANDLE hFile;
  longlong *plVar1;
  DWORD dwFlags;
  undefined4 uStack_230;
  undefined *puStack_22c;
  undefined *puStack_228;
  longlong *local_21c;
  longlong *local_218;
  longlong local_212 [65];
  longlong *local_8;
  
  puStack_228 = &stack0xfffffffc;
  local_218 = (longlong *)0x0;
  local_21c = (longlong *)0x0;
  local_8 = (longlong *)0x0;
  puStack_22c = &LAB_004093c6;
  uStack_230 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_230;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)local_212,0x105);
  FUN_0040723c(&local_218,param_1);
  plVar1 = local_218;
  FUN_00407278(&local_21c,local_212,0x105);
  FUN_00409234((int)local_21c,(int)plVar1,&local_8);
  if (local_8 != (longlong *)0x0) {
    dwFlags = 2;
    hFile = (HANDLE)0x0;
    lpLibFileName = (LPCWSTR)FUN_004071e4((int)local_8);
    LoadLibraryExW(lpLibFileName,hFile,dwFlags);
  }
  *in_FS_OFFSET = uStack_230;
  puStack_228 = &LAB_004093cd;
  puStack_22c = (undefined *)0x4093bd;
  FUN_00406b88((int *)&local_21c,2);
  puStack_22c = (undefined *)0x4093c5;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_004093d8(undefined *param_1,undefined4 param_2)

{
  char cVar1;
  undefined4 uVar2;
  int *piVar3;
  
  piVar3 = DAT_00427030;
  if (DAT_00427030 != (int *)0x0) {
    do {
      uVar2 = FUN_00408948((int)piVar3);
      cVar1 = (*(code *)param_1)(uVar2,param_2);
      if (cVar1 == '\0') {
        return;
      }
      piVar3 = (int *)*piVar3;
    } while (piVar3 != (int *)0x0);
  }
  return;
}



void FUN_00409424(int *param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  
  ppiVar2 = DAT_00427034;
  if ((DAT_00427034 == (int **)0x0) || (DAT_00427034[1] != param_1)) {
    if (DAT_00427034 != (int **)0x0) {
      do {
        ppiVar1 = (int **)*ppiVar2;
        if ((ppiVar1 != (int **)0x0) && (ppiVar1[1] == param_1)) {
          *ppiVar2 = *ppiVar1;
          FUN_004044d4((int)ppiVar1);
          return;
        }
        ppiVar2 = (int **)*ppiVar2;
      } while (ppiVar2 != (int **)0x0);
    }
  }
  else {
    DAT_00427034 = (int **)*DAT_00427034;
    FUN_004044d4((int)ppiVar2);
  }
  return;
}



void FUN_00409480(undefined4 param_1,undefined4 param_2,undefined *param_3)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  int *local_c;
  
  local_c = DAT_00427034;
  if (DAT_00427034 != (int *)0x0) {
    do {
      puStack_20 = &LAB_004094bb;
      uStack_24 = *in_FS_OFFSET;
      *in_FS_OFFSET = &uStack_24;
      puStack_1c = &stack0xfffffffc;
      (*(code *)local_c[1])(param_1,param_2,param_3);
      *in_FS_OFFSET = uStack_24;
      local_c = (int *)*local_c;
      param_3 = puStack_1c;
      param_2 = uStack_24;
    } while (local_c != (int *)0x0);
  }
  return;
}



void FUN_004094dc(int **param_1)

{
  int **ppiVar1;
  
  ppiVar1 = DAT_00427030;
  if (DAT_00427030 != (int **)0x0) {
    do {
      if (param_1 == ppiVar1) {
        return;
      }
      ppiVar1 = (int **)*ppiVar1;
    } while (ppiVar1 != (int **)0x0);
  }
  *param_1 = (int *)DAT_00427030;
  DAT_00427030 = param_1;
  return;
}



void FUN_00409500(undefined4 *param_1,undefined4 param_2,undefined *param_3)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 *local_8;
  
  puStack_c = &stack0xfffffffc;
  puStack_10 = &LAB_00409564;
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  local_8 = param_1;
  FUN_00409480(param_1[1],0,param_3);
  *in_FS_OFFSET = uStack_14;
  puVar1 = DAT_00427030;
  if (local_8 == DAT_00427030) {
    DAT_00427030 = (undefined4 *)*local_8;
  }
  else {
    for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
      if ((undefined4 *)*puVar1 == local_8) {
        *puVar1 = *local_8;
        return;
      }
    }
  }
  return;
}



int ** FUN_00409570(int **param_1)

{
  int **ppiVar1;
  
  ppiVar1 = (int **)*param_1;
  if (ppiVar1 != (int **)0x0) {
    *param_1 = (int *)0x0;
    (*(code *)(*ppiVar1)[2])();
    param_1 = ppiVar1;
  }
  return param_1;
}



void FUN_00409588(int **param_1,int **param_2)

{
  int *piVar1;
  
  if (param_2 == (int **)0x0) {
    piVar1 = *param_1;
    *param_1 = (int *)0x0;
    if (piVar1 != (int *)0x0) {
      (**(code **)(*piVar1 + 8))();
    }
    return;
  }
  (*(code *)(*param_2)[1])();
  piVar1 = *param_2;
  *param_2 = (int *)param_1;
  if (piVar1 == (int *)0x0) {
    return;
  }
  (**(code **)(*piVar1 + 8))();
  return;
}



int ** FUN_004095b4(int **param_1,int **param_2)

{
  int iVar1;
  int **ppiVar2;
  
  if (param_2 == (int **)0x0) {
    ppiVar2 = (int **)*param_1;
    if (ppiVar2 != (int **)0x0) {
      *param_1 = (int *)0x0;
      (*(code *)(*ppiVar2)[2])();
      param_1 = ppiVar2;
    }
    return param_1;
  }
  iVar1 = (*(code *)**param_2)();
  if (iVar1 != 0) {
    ppiVar2 = (int **)FUN_004045f4(0x17);
    return ppiVar2;
  }
  if (*param_1 != (int *)0x0) {
    (**(code **)(**param_1 + 8))();
  }
  *param_1 = (int *)param_2;
  return param_2;
}



void FUN_004095e4(int *param_1)

{
  if (param_1 != (int *)0x0) {
    (**(code **)(*param_1 + 4))();
  }
  return;
}



void FUN_00409c08(int *param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = *param_1;
  if (iVar2 != 0) {
    *param_1 = 0;
    piVar3 = (int *)(iVar2 + -8);
    if (0 < *piVar3) {
      LOCK();
      iVar1 = *piVar3;
      *piVar3 = *piVar3 + -1;
      UNLOCK();
      if (iVar1 == 1) {
        FUN_00403334((int **)(iVar2 + -8));
      }
    }
  }
  return;
}



void FUN_00409c38(longlong **param_1,int *param_2)

{
  longlong *plVar1;
  int *piVar2;
  int *piVar3;
  int **ppiVar4;
  
  plVar1 = *param_1;
  piVar3 = (int *)((int)param_2 * 4 + 8);
  if (plVar1 == (longlong *)0x0) {
    ppiVar4 = (int **)FUN_00403844((byte *)piVar3);
  }
  else {
    piVar2 = *(int **)((int)plVar1 + -4);
    if (*(int *)(plVar1 + -1) == 1) {
      ppiVar4 = FUN_0040352c((int **)(plVar1 + -1),piVar3);
    }
    else {
      ppiVar4 = (int **)FUN_00402fb0((byte *)piVar3);
      piVar3 = piVar2;
      if ((int)param_2 < (int)piVar2) {
        piVar3 = param_2;
      }
      FUN_0040465c(*param_1,(longlong *)(ppiVar4 + 2),(int)piVar3 * 4);
      FUN_00409c08((int *)*param_1);
    }
    if ((int)piVar2 < (int)param_2) {
      FUN_004048f8((double *)(ppiVar4 + (int)piVar2 + 2),((int)param_2 - (int)piVar2) * 4,0);
    }
  }
  *ppiVar4 = (int *)0x1;
  ppiVar4[1] = param_2;
  *param_1 = (longlong *)(ppiVar4 + 2);
  return;
}



int FUN_00409cd0(void)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_00403844((byte *)0x100);
  uVar2 = FUN_004056b0();
  *(undefined4 *)(iVar1 + 4) = uVar2;
  return iVar1;
}



void FUN_00409cec(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  iVar2 = 0x1f;
  piVar3 = (int *)(param_1 + 8);
  do {
    iVar5 = *piVar3;
    if (iVar5 != 0) {
      iVar5 = *(int *)(iVar5 + -4);
    }
    if (-1 < iVar5 + -1) {
      iVar4 = 0;
      do {
        puVar1 = *(undefined4 **)(*piVar3 + iVar4 * 4);
        if (puVar1 != (undefined4 *)0x0) {
          *puVar1 = 0;
          *(undefined4 *)(*piVar3 + iVar4 * 4) = 0;
        }
        iVar4 = iVar4 + 1;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
    iVar5 = piVar3[0x1f];
    if (iVar5 != 0) {
      iVar5 = *(int *)(iVar5 + -4);
    }
    if (-1 < iVar5 + -1) {
      iVar4 = 0;
      do {
        puVar1 = *(undefined4 **)(piVar3[0x1f] + iVar4 * 4);
        if (puVar1 != (undefined4 *)0x0) {
          *puVar1 = 0;
          puVar1[1] = 0;
          *(undefined4 *)(piVar3[0x1f] + iVar4 * 4) = 0;
        }
        iVar4 = iVar4 + 1;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void FUN_00409d70(int param_1)

{
  if (DAT_004298f4 != 0) {
    FUN_00405820(*(uint **)(param_1 + 4),0xffffffff);
  }
  return;
}



void FUN_00409d88(int param_1)

{
  if (DAT_004298f4 != 0) {
    FUN_004059b8(*(uint **)(param_1 + 4));
  }
  return;
}



bool FUN_00409dac(int **param_1)

{
  int iVar1;
  int **ppiVar2;
  
  if (param_1 != (int **)0x0) {
    FUN_00409cec((int)param_1);
    iVar1 = 0x1f;
    ppiVar2 = param_1 + 2;
    do {
      FUN_00409c08((int *)ppiVar2);
      ppiVar2 = ppiVar2 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    iVar1 = 0x1f;
    ppiVar2 = param_1 + 0x21;
    do {
      FUN_00409c08((int *)ppiVar2);
      ppiVar2 = ppiVar2 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    FUN_00405728((int **)param_1[1]);
    FUN_00408110(param_1,"\x0e\tTInstItem");
  }
  return param_1 != (int **)0x0;
}



void FUN_00409e0c(int param_1,int param_2,uint param_3)

{
  int iVar1;
  undefined extraout_CL;
  uint uVar2;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar4;
  
  uVar2 = ((param_3 >> 0xd) + (param_3 >> 5)) % 0x1f;
  FUN_00409d70(param_1);
  uVar4 = *in_FS_OFFSET;
  *in_FS_OFFSET = &stack0xffffffdc;
  iVar1 = *(int *)(param_2 + uVar2 * 4);
  if (iVar1 != 0) {
    iVar1 = *(int *)(iVar1 + -4);
  }
  if (-1 < iVar1 + -1) {
    iVar3 = 0;
    do {
      if (*(int *)(*(int *)(param_2 + uVar2 * 4) + iVar3 * 4) == 0) {
        iVar1 = *(int *)(param_2 + uVar2 * 4);
        *(uint *)(iVar1 + iVar3 * 4) = param_3;
        FUN_004063c0((char)iVar1,(char)param_3,extraout_CL,uVar4,&LAB_00409ec7);
        return;
      }
      iVar3 = iVar3 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  iVar1 = *(int *)(param_2 + uVar2 * 4);
  if (iVar1 != 0) {
    iVar1 = *(int *)(iVar1 + -4);
  }
  if (iVar1 == 0) {
    FUN_00409c38((longlong **)(param_2 + uVar2 * 4),(int *)0xa);
  }
  else {
    FUN_00409c38((longlong **)(param_2 + uVar2 * 4),(int *)(iVar1 * 2));
  }
  *(uint *)(*(int *)(param_2 + uVar2 * 4) + iVar1 * 4) = param_3;
  *in_FS_OFFSET = uVar4;
  FUN_00409d88(param_1);
  return;
}



void FUN_00409fa4(int param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 8);
  if (iVar1 != 0) {
    iVar1 = *(int *)(iVar1 + -4);
  }
  if (iVar1 == 0) {
    FUN_00409c38((longlong **)(param_1 + 8),(int *)0xa);
  }
  else {
    iVar1 = *(int *)(param_1 + 8);
    if (iVar1 != 0) {
      iVar1 = *(int *)(iVar1 + -4);
    }
    if (iVar1 == *(int *)(param_1 + 4)) {
      iVar1 = *(int *)(param_1 + 8);
      if (iVar1 != 0) {
        iVar1 = *(int *)(iVar1 + -4);
      }
      FUN_00409c38((longlong **)(param_1 + 8),(int *)(iVar1 * 2));
    }
  }
  iVar1 = *(int *)(param_1 + 4);
  if (param_2 < iVar1) {
    FUN_0040465c((longlong *)(*(int *)(param_1 + 8) + param_2 * 4),
                 (longlong *)(*(int *)(param_1 + 8) + 4 + param_2 * 4),(iVar1 - param_2) * 4);
    *(undefined4 *)(*(int *)(param_1 + 8) + param_2 * 4) = param_3;
  }
  else {
    *(undefined4 *)(*(int *)(param_1 + 8) + iVar1 * 4) = param_3;
  }
  *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
  return;
}



undefined4 FUN_0040a02c(int param_1,int param_2,uint *param_3)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 local_14;
  
  local_14 = 0;
  if (*(int *)(param_1 + 4) < 1) {
    *param_3 = 0;
  }
  else {
    uVar3 = 0;
    iVar4 = *(int *)(param_1 + 4) + -1;
    if (-1 < iVar4) {
      do {
        uVar2 = iVar4 + uVar3 >> 1;
        iVar1 = **(int **)(*(int *)(param_1 + 8) + uVar2 * 4);
        if (iVar1 - param_2 < 0) {
          uVar3 = uVar2 + 1;
        }
        else {
          iVar4 = uVar2 - 1;
          if (iVar1 == param_2) {
            local_14 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar2 * 4);
            uVar3 = uVar2;
          }
        }
      } while ((int)uVar3 <= iVar4);
    }
    *param_3 = uVar3;
  }
  return local_14;
}



void FUN_0040a09c(undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_1[1];
  if (-1 < iVar1 + -1) {
    iVar2 = 0;
    do {
      FUN_00409dac(*(int ***)(param_1[2] + iVar2 * 4));
      iVar2 = iVar2 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  param_1[1] = 0;
  FUN_00405728((int **)*param_1);
  FUN_00409c08(param_1 + 2);
  return;
}



void FUN_0040a0d4(undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_004056b0();
  *param_1 = uVar1;
  param_1[1] = 0;
  return;
}



void FUN_0040a0e8(uint **param_1)

{
  if (DAT_004298f4 != 0) {
    FUN_00405820(*param_1,0xffffffff);
  }
  return;
}



int FUN_0040a0fc(int param_1,int param_2,uint param_3)

{
  int iVar1;
  uint local_10;
  
  local_10 = param_3;
  iVar1 = FUN_0040a02c(param_1,param_2,&local_10);
  if ((iVar1 != 0) && ((int)local_10 < *(int *)(param_1 + 4))) {
    if ((int)local_10 < *(int *)(param_1 + 4) + -1) {
      FUN_0040465c((longlong *)(*(int *)(param_1 + 8) + 4 + local_10 * 4),
                   (longlong *)(*(int *)(param_1 + 8) + local_10 * 4),
                   ((*(int *)(param_1 + 4) - local_10) + -1) * 4);
    }
    *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + -1;
  }
  return iVar1;
}



void FUN_0040a150(uint **param_1)

{
  if (DAT_004298f4 != 0) {
    FUN_004059b8(*param_1);
  }
  return;
}



void FUN_0040a210(longlong *param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_0040a228(param_1);
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)FUN_00409cd0();
  }
  *puVar1 = param_2;
  return;
}



undefined4 * FUN_0040a228(longlong *param_1)

{
  longlong *plVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  
  LOCK();
  plVar1 = param_1 + 1;
  iVar2 = *(int *)plVar1;
  *(int *)plVar1 = *(int *)plVar1 + 1;
  UNLOCK();
  do {
    puVar3 = *(undefined4 **)param_1;
    if (puVar3 == (undefined4 *)0x0) break;
    LOCK();
    if (*param_1 == *param_1) {
      *param_1 = CONCAT44(iVar2 + 1,*puVar3);
      puVar4 = puVar3;
      iVar5 = *(int *)((int)param_1 + 4);
    }
    else {
      puVar4 = *(undefined4 **)param_1;
      iVar5 = (int)((ulonglong)*param_1 >> 0x20);
    }
    UNLOCK();
  } while ((iVar5 != *(int *)((int)param_1 + 4)) || (puVar4 != puVar3));
  if (puVar3 != (undefined4 *)0x0) {
    LOCK();
    *(int *)((int)param_1 + 0xc) = *(int *)((int)param_1 + 0xc) + -1;
    UNLOCK();
  }
  return puVar3;
}



void FUN_0040a2c4(longlong *param_1)

{
  bool bVar1;
  int **ppiVar2;
  undefined4 *puVar3;
  int iVar4;
  
  if (*(char *)(param_1 + 0x12a) != '\0') {
    iVar4 = 0xc5;
    puVar3 = (undefined4 *)((int)param_1 + 0x14);
    do {
      FUN_0040a09c(puVar3);
      puVar3 = puVar3 + 3;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    do {
      ppiVar2 = (int **)FUN_0040a228(param_1);
      bVar1 = FUN_00409dac(ppiVar2);
    } while (bVar1);
    if (*(int ***)(param_1 + 2) != (int **)0x0) {
      FUN_00405728(*(int ***)(param_1 + 2));
    }
  }
  return;
}



void FUN_0040a308(int param_1)

{
  int *piVar1;
  int iVar2;
  int **ppiVar3;
  undefined4 *puVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  
  if (*(char *)(param_1 + 0x950) == '\0') {
    if (*(int *)(param_1 + 0x10) == 0) {
      puStack_14 = (undefined *)0x40a32f;
      iVar2 = FUN_004056b0();
      ppiVar3 = (int **)0x0;
      LOCK();
      piVar1 = (int *)(param_1 + 0x10);
      if (*piVar1 == 0) {
        *piVar1 = iVar2;
      }
      else {
        ppiVar3 = (int **)*piVar1;
      }
      UNLOCK();
      if (ppiVar3 != (int **)0x0) {
        puStack_14 = (undefined *)0x40a348;
        FUN_00405728(ppiVar3);
      }
    }
    puStack_14 = (undefined *)0x40a356;
    FUN_00405820(*(uint **)(param_1 + 0x10),0xffffffff);
    puStack_18 = &LAB_0040a3ab;
    uStack_1c = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_1c;
    if (*(char *)(param_1 + 0x950) == '\0') {
      iVar2 = 0xc5;
      puVar4 = (undefined4 *)(param_1 + 0x14);
      puStack_14 = &stack0xfffffffc;
      do {
        FUN_0040a0d4(puVar4);
        puVar4 = puVar4 + 3;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      *(undefined *)(param_1 + 0x950) = 1;
    }
    *in_FS_OFFSET = uStack_1c;
    puStack_14 = (undefined *)0x40a3b2;
    puStack_18 = (undefined *)0x40a3aa;
    FUN_004059b8(*(uint **)(param_1 + 0x10));
    return;
  }
  return;
}



void FUN_0040a3b8(int param_1,uint param_2)

{
  uint extraout_ECX;
  uint uVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  
  if (*(char *)(param_1 + 0x950) != '\0') {
    uVar1 = ((param_2 >> 0xd) + (param_2 >> 5)) % 0xc5;
    puStack_1c = (undefined *)0x40a3fe;
    FUN_0040a0e8((uint **)(param_1 + 0x14 + uVar1 * 0xc));
    puStack_20 = &LAB_0040a43d;
    uStack_24 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_24;
    puStack_1c = &stack0xfffffffc;
    FUN_0040a0fc(param_1 + 0x14 + uVar1 * 0xc,param_2,extraout_ECX);
    *in_FS_OFFSET = uStack_24;
    puStack_1c = &DAT_0040a444;
    puStack_20 = (undefined *)0x40a43c;
    FUN_0040a150((uint **)(param_1 + 0x14 + uVar1 * 0xc));
    return;
  }
  return;
}



void FUN_0040a464(longlong *param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  uint local_14;
  uint local_10;
  undefined4 local_c;
  longlong *local_8;
  
  local_c = param_2;
  local_8 = param_1;
  if (*(char *)(param_1 + 0x12a) == '\0') {
    puStack_28 = (undefined *)0x40a488;
    FUN_0040a308((int)param_1);
  }
  uVar3 = ((param_3 >> 0xd) + (param_3 >> 5)) % 0xc5;
  puStack_28 = (undefined *)0x40a4b1;
  local_10 = uVar3;
  FUN_0040a0e8((uint **)((int)local_8 + uVar3 * 0xc + 0x14));
  puStack_2c = &LAB_0040a519;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  puStack_28 = &stack0xfffffffc;
  iVar1 = FUN_0040a02c((int)local_8 + uVar3 * 0xc + 0x14,param_3,&local_14);
  if (iVar1 == 0) {
    uVar2 = FUN_0040a210(local_8,param_3);
    FUN_00409fa4((int)local_8 + uVar3 * 0xc + 0x14,local_14,uVar2);
  }
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_0040a520;
  puStack_2c = (undefined *)0x40a518;
  FUN_0040a150((uint **)((int)local_8 + local_10 * 0xc + 0x14));
  return;
}



void FUN_0040a540(int param_1,undefined4 param_2,uint param_3)

{
  uint uVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  uint local_14;
  uint local_10;
  undefined4 local_c;
  int local_8;
  
  if (*(char *)(param_1 + 0x950) != '\0') {
    uVar1 = ((param_3 >> 0xd) + (param_3 >> 5)) % 0xc5;
    puStack_28 = (undefined *)0x40a589;
    local_10 = uVar1;
    local_c = param_2;
    local_8 = param_1;
    FUN_0040a0e8((uint **)(param_1 + 0x14 + uVar1 * 0xc));
    puStack_2c = &LAB_0040a5cb;
    uStack_30 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_30;
    puStack_28 = &stack0xfffffffc;
    FUN_0040a02c(local_8 + 0x14 + uVar1 * 0xc,param_3,&local_14);
    *in_FS_OFFSET = uStack_30;
    puStack_28 = &DAT_0040a5d2;
    puStack_2c = (undefined *)0x40a5ca;
    FUN_0040a150((uint **)(local_8 + 0x14 + local_10 * 0xc));
    return;
  }
  return;
}



void FUN_0040a828(int *param_1)

{
  uint *puVar1;
  
  puVar1 = (uint *)FUN_00405a84(param_1);
  LOCK();
  *puVar1 = *puVar1 | 1;
  UNLOCK();
  return;
}



void FUN_0040a834(undefined4 param_1,int *param_2)

{
  if (param_2 != (int *)0x0) {
    if ((*(byte *)((int)param_2 + *(int *)(*param_2 + -0x34) + -4) & 1) == 0) {
      FUN_0040a828(param_2);
    }
    FUN_0040a464((longlong *)&DAT_0042bc28,param_1,(uint)param_2);
  }
  return;
}



void FUN_0040a86c(undefined4 param_1,uint param_2)

{
  if (param_2 != 0) {
    FUN_0040a540((int)&DAT_0042bc28,param_1,param_2);
  }
  return;
}



void FUN_0040a880(int *param_1)

{
  if ((*(byte *)((int)param_1 + *(int *)(*param_1 + -0x34) + -4) & 1) != 0) {
    FUN_0040a3b8((int)&DAT_0042bc28,(uint)param_1);
  }
  return;
}



int * FUN_0040a8a0(int *param_1)

{
  uint uVar1;
  
  if (*param_1 != 0) {
    uVar1 = FUN_0040515c((int **)*param_1,(int)&DAT_004014bc);
    *param_1 = 0;
    FUN_0040a86c(param_1,uVar1);
  }
  return param_1;
}



void FUN_0040a8cc(int *param_1,int **param_2)

{
  int *piVar1;
  int *piVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  int **local_8;
  
  puStack_10 = (undefined *)0x40a8de;
  local_8 = param_2;
  FUN_004095e4((int *)param_2);
  puStack_14 = &LAB_0040a925;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  puStack_10 = &stack0xfffffffc;
  piVar1 = FUN_0040a8a0(param_1);
  piVar2 = (int *)FUN_0040515c(local_8,(int)&DAT_004014bc);
  FUN_0040a834(piVar1,piVar2);
  *param_1 = (int)local_8;
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_0040a92c;
  puStack_14 = (undefined *)0x40a924;
  FUN_00409570((int **)&local_8);
  return;
}



uint FUN_0040a9d0(LPWSTR param_1,uint param_2,LPCSTR param_3,int param_4)

{
  uint uVar1;
  
  uVar1 = 0;
  if (param_3 != (LPCSTR)0x0) {
    if ((param_1 == (LPWSTR)0x0) || (param_2 == 0)) {
      uVar1 = FUN_0040abd0(0xfde9,0,param_3,0,(LPWSTR)0x0,param_4);
    }
    else {
      uVar1 = FUN_0040abd0(0xfde9,0,param_3,param_2,param_1,param_4);
      if (((uVar1 != 0) && (uVar1 <= param_2)) && ((param_4 != -1 || (param_1[uVar1 - 1] != L'\0')))
         ) {
        if (param_2 == uVar1) {
          if (((1 < uVar1) && (0xdbff < (ushort)param_1[uVar1 - 1])) &&
             ((ushort)param_1[uVar1 - 1] < 0xe000)) {
            uVar1 = uVar1 - 1;
          }
        }
        else {
          uVar1 = uVar1 + 1;
        }
        param_1[uVar1 - 1] = L'\0';
      }
    }
  }
  return uVar1;
}



void FUN_0040aa98(byte *param_1,longlong **param_2)

{
  LPWSTR pWVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  longlong *local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_1c = &LAB_0040ab1a;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  FUN_00406b28((int *)param_2);
  if (*param_1 != 0) {
    uVar3 = (uint)*param_1;
    FUN_004072d0(&local_8,uVar3);
    uVar2 = uVar3;
    pWVar1 = (LPWSTR)FUN_004071e4((int)local_8);
    uVar2 = FUN_0040a9d0(pWVar1,uVar3 + 1,(LPCSTR)(param_1 + 1),uVar2);
    if ((int)uVar2 < 1) {
      FUN_00406b28((int *)&local_8);
    }
    else {
      FUN_004072d0(&local_8,uVar2 - 1);
    }
    FUN_00406dfc(param_2,local_8);
  }
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_0040ab21;
  puStack_1c = (undefined *)0x40ab19;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_0040ab28(byte *param_1,longlong **param_2)

{
  FUN_0040aa98(param_1,param_2);
  return;
}



void FUN_0040ab3c(undefined4 param_1,longlong **param_2)

{
  HINSTANCE hInstance;
  int **in_stack_00000ff4;
  int *uID;
  longlong *lpBuffer;
  int iVar1;
  longlong local_1008 [511];
  int iStack_c;
  
  iVar1 = 2;
  do {
    iStack_c = iVar1;
    lpBuffer = local_1008;
    iVar1 = iStack_c + -1;
  } while (iStack_c + -1 != 0);
  if (in_stack_00000ff4 != (int **)0x0) {
    if (in_stack_00000ff4[1] < (int *)0x10000) {
      iVar1 = 0x1000;
      uID = in_stack_00000ff4[1];
      hInstance = (HINSTANCE)FUN_00408990(**in_stack_00000ff4);
      iVar1 = LoadStringW(hInstance,(UINT)uID,(LPWSTR)lpBuffer,iVar1);
      FUN_00406c80(param_2,local_1008,iVar1);
    }
    else {
      FUN_0040723c(param_2,(longlong *)in_stack_00000ff4[1]);
    }
  }
  return;
}



void FUN_0040aba8(UINT param_1,DWORD param_2,LPCWSTR param_3,LPBOOL param_4,LPCSTR param_5,
                 int param_6,LPSTR param_7,int param_8)

{
  WideCharToMultiByte(param_1,param_2,param_3,param_8,param_7,param_6,param_5,param_4);
  return;
}



void FUN_0040abd0(UINT param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWSTR param_5,int param_6)

{
  MultiByteToWideChar(param_1,param_2,param_3,param_6,param_5,param_4);
  return;
}



DWORD FUN_0040abf0(void)

{
  _SYSTEM_INFO _Stack_24;
  
  GetSystemInfo(&_Stack_24);
  return _Stack_24.dwNumberOfProcessors;
}



void FUN_0040ac04(void)

{
  DWORD DVar1;
  
  DVar1 = GetVersion();
  if ((((DVar1 & 0xff) != 5) || ((DVar1 & 0xff00) == 0)) && ((DVar1 & 0xff) < 6)) {
    DAT_00429980 = 0x409;
    return;
  }
  DAT_00429980 = 0x7f;
  return;
}



void FUN_0040ac80(undefined4 *param_1,char param_2,undefined4 *param_3)

{
  *param_3 = *param_1;
  param_3[1] = param_1[1];
  param_3[2] = param_1[2];
  param_3[3] = param_1[3];
  if (param_2 != '\0') {
    *param_3 = CONCAT22(CONCAT11((char)*(undefined2 *)param_3,
                                 (char)((ushort)*(undefined2 *)param_3 >> 8)),
                        CONCAT11((char)((uint)*param_3 >> 0x10),(char)((uint)*param_3 >> 0x18)));
    *(ushort *)(param_3 + 1) =
         CONCAT11((char)*(undefined2 *)(param_3 + 1),
                  (char)((ushort)*(undefined2 *)(param_3 + 1) >> 8));
    *(ushort *)((int)param_3 + 6) =
         CONCAT11((char)*(undefined2 *)((int)param_3 + 6),
                  (char)((ushort)*(undefined2 *)((int)param_3 + 6) >> 8));
  }
  return;
}



undefined4
FUN_0040ad94(undefined param_1,undefined param_2,undefined param_3,undefined4 *param_4,
            undefined4 param_5)

{
  undefined4 uVar1;
  
  LOCK();
  uVar1 = *param_4;
  *param_4 = param_5;
  UNLOCK();
  return uVar1;
}



BOOL __stdcall FreeLibrary(HMODULE hLibModule)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040ada4. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FreeLibrary(hLibModule);
  return BVar1;
}



HMODULE __stdcall GetModuleHandleW(LPCWSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040adac. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetModuleHandleW(lpModuleName);
  return pHVar1;
}



HLOCAL __stdcall LocalAlloc(UINT uFlags,SIZE_T uBytes)

{
  HLOCAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040adb4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = LocalAlloc(uFlags,uBytes);
  return pvVar1;
}



HLOCAL __stdcall LocalFree(HLOCAL hMem)

{
  HLOCAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040adbc. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = LocalFree(hMem);
  return pvVar1;
}



LPVOID __stdcall TlsGetValue(DWORD dwTlsIndex)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040adc4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = TlsGetValue(dwTlsIndex);
  return pvVar1;
}



BOOL __stdcall TlsSetValue(DWORD dwTlsIndex,LPVOID lpTlsValue)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040adcc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = TlsSetValue(dwTlsIndex,lpTlsValue);
  return BVar1;
}



DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040add4. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetLastError();
  return DVar1;
}



HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040addc. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = LoadLibraryA(lpLibFileName);
  return pHVar1;
}



void __stdcall
RaiseException(DWORD dwExceptionCode,DWORD dwExceptionFlags,DWORD nNumberOfArguments,
              ULONG_PTR *lpArguments)

{
                    // WARNING: Could not recover jumptable at 0x0040ade4. Too many branches
                    // WARNING: Treating indirect jump as call
  RaiseException(dwExceptionCode,dwExceptionFlags,nNumberOfArguments,lpArguments);
  return;
}



FARPROC __stdcall GetProcAddress(HMODULE hModule,LPCSTR lpProcName)

{
  FARPROC pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040adec. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = GetProcAddress(hModule,lpProcName);
  return pFVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

FARPROC thunk_FUN_0040b40c(undefined param_1,undefined param_2,undefined param_3,undefined4 param_4,
                          undefined4 param_5)

{
  FARPROC pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040adf4. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = (FARPROC)(*_DAT_00427a04)();
  return pFVar1;
}



void FUN_0040adfc(SIZE_T param_1)

{
  LocalAlloc(0x40,param_1);
  return;
}



undefined4 FUN_0040ae08(void)

{
  return 0x14;
}



void FUN_0040ae10(void)

{
  SIZE_T SVar1;
  LPVOID lpTlsValue;
  
  SVar1 = FUN_0040ae08();
  if (SVar1 != 0) {
    if (_tls_index == 0xffffffff) {
      FUN_00406a3c(0xe2);
    }
    lpTlsValue = (LPVOID)FUN_0040adfc(SVar1);
    if (lpTlsValue == (LPVOID)0x0) {
      FUN_00406a3c(0xe2);
    }
    else {
      TlsSetValue(_tls_index,lpTlsValue);
    }
  }
  return;
}



LPVOID FUN_0040ae54(void)

{
  LPVOID pvVar1;
  int in_FS_OFFSET;
  
  if (DAT_0042c580 == '\0') {
    return *(LPVOID *)(*(int *)(in_FS_OFFSET + 0x2c) + _tls_index * 4);
  }
  pvVar1 = TlsGetValue(_tls_index);
  if (pvVar1 != (LPVOID)0x0) {
    return pvVar1;
  }
  FUN_0040ae10();
  pvVar1 = TlsGetValue(_tls_index);
  if (pvVar1 != (LPVOID)0x0) {
    return pvVar1;
  }
  return DAT_0042c59c;
}



void FUN_0040ae94(void)

{
  FUN_004094dc((int **)&DAT_00427a08);
  return;
}



void FUN_0040aea0(void)

{
  return;
}



void FUN_0040aea4(void)

{
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  FUN_0040aea0();
  return;
}



void __dbk_fcall_wrapper(void)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  
                    // 0xb294  2  __dbk_fcall_wrapper
  puStack_18 = &stack0xfffffffc;
  puStack_1c = &LAB_0040b335;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  FUN_0040aea4();
  *in_FS_OFFSET = uStack_20;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040b3c0(int param_1)

{
  _tls_index = 0;
  _DAT_00427a0c = GetModuleHandleW((LPCWSTR)0x0);
  _DAT_00427a10 = 0;
  _DAT_00427a14 = 0;
  _DAT_00427a1c = param_1 + 8;
  DAT_0042c584 = _DAT_00427a0c;
  FUN_0040ae94();
  FUN_00406634(param_1,(int)&DAT_00427a08);
  return;
}



FARPROC FUN_0040b40c(undefined param_1,undefined param_2,undefined param_3,uint *param_4,
                    HMODULE *param_5)

{
  undefined uVar1;
  HMODULE pHVar2;
  HMODULE pHVar3;
  int *piVar4;
  undefined extraout_CL;
  undefined extraout_CL_00;
  undefined extraout_CL_01;
  undefined extraout_CL_02;
  undefined extraout_CL_03;
  undefined uVar5;
  int iVar6;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  HMODULE hLibModule;
  uint *puVar7;
  undefined4 *puVar8;
  uint *puVar9;
  undefined4 *puVar10;
  HMODULE *ppHVar11;
  bool bVar12;
  byte bVar13;
  uint uVar14;
  uint uVar15;
  undefined4 local_5c;
  uint *local_58;
  HMODULE *local_54;
  LPCSTR local_50;
  uint local_4c;
  HMODULE local_48;
  HMODULE local_44;
  HMODULE local_40;
  HMODULE local_3c;
  uint local_38;
  LPCSTR local_34;
  HMODULE *local_30;
  int local_2c;
  int local_28;
  int local_24;
  int local_20;
  uint local_1c;
  undefined4 *local_18;
  undefined4 *local_14;
  undefined4 *local_10;
  int local_c;
  undefined4 *local_8;
  
  bVar13 = 0;
  puVar7 = &DAT_00427a28;
  puVar9 = &local_38;
  for (iVar6 = 8; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar9 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar9 = puVar9 + 1;
  }
  local_38 = *param_4;
  local_34 = (LPCSTR)FUN_0040b8bc((char)local_38,(char)param_4[1],0,param_4[1]);
  uVar14 = param_4[2];
  local_30 = (HMODULE *)FUN_0040b8cc((char)local_34,extraout_DL,(char)uVar14,uVar14);
  uVar15 = param_4[3];
  local_2c = FUN_0040b8dc((char)uVar15,extraout_DL_00,(char)uVar14,uVar15);
  local_28 = FUN_0040b8ec((char)local_2c,(char)param_4[4],(char)uVar15,param_4[4]);
  uVar14 = param_4[5];
  local_24 = FUN_0040b8ec((char)local_28,extraout_DL_01,(char)uVar14,uVar14);
  local_20 = FUN_0040b8ec((char)param_4[6],extraout_DL_02,(char)uVar14,param_4[6]);
  local_1c = param_4[7];
  puVar8 = &DAT_00427a48;
  puVar10 = &local_5c;
  for (iVar6 = 9; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar10 = *puVar8;
    puVar8 = puVar8 + (uint)bVar13 * -2 + 1;
    puVar10 = puVar10 + (uint)bVar13 * -2 + 1;
  }
  local_58 = param_4;
  local_54 = param_5;
  local_50 = local_34;
  if ((local_38 & 1) == 0) {
    local_8 = &local_5c;
    RaiseException(0xc06d0057,0,1,(ULONG_PTR *)&local_8);
    return (FARPROC)0x0;
  }
  local_c = (int)param_5 - local_2c;
  hLibModule = *local_30;
  if (local_c < 0) {
    local_c = local_c + 3;
  }
  local_c = local_c >> 2;
  ppHVar11 = (HMODULE *)(local_c * 4 + local_28);
  bVar12 = (*(byte *)((int)ppHVar11 + 3) & 0x80) == 0;
  local_4c = (uint)bVar12;
  if (local_4c == 0) {
    pHVar3 = (HMODULE)((uint)*ppHVar11 & 0xffff);
    pHVar2 = (HMODULE)0x0;
    local_48 = pHVar3;
  }
  else {
    pHVar3 = *ppHVar11;
    iVar6 = FUN_0040b8fc(bVar12,(char)pHVar3,0,pHVar3);
    pHVar2 = (HMODULE)(iVar6 + 2);
    local_48 = pHVar2;
  }
  uVar5 = SUB41(pHVar3,0);
  pHVar3 = (HMODULE)0x0;
  if ((DAT_0042c590 != (code *)0x0) &&
     (pHVar2 = (HMODULE)(*DAT_0042c590)(), pHVar3 = pHVar2, uVar5 = extraout_CL,
     pHVar2 != (HMODULE)0x0)) goto LAB_0040b6be;
  if (hLibModule == (HMODULE)0x0) {
    if (DAT_0042c590 != (code *)0x0) {
      pHVar2 = (HMODULE)(*DAT_0042c590)();
      hLibModule = pHVar2;
      uVar5 = extraout_CL_00;
    }
    if (hLibModule == (HMODULE)0x0) {
      pHVar2 = LoadLibraryA(local_50);
      hLibModule = pHVar2;
      uVar5 = extraout_CL_01;
    }
    uVar1 = SUB41(pHVar2,0);
    if (hLibModule == (HMODULE)0x0) {
      pHVar2 = (HMODULE)GetLastError();
      uVar5 = extraout_CL_02;
      local_3c = pHVar2;
      if (DAT_0042c594 != (code *)0x0) {
        pHVar2 = (HMODULE)(*DAT_0042c594)();
        hLibModule = pHVar2;
        uVar5 = extraout_CL_03;
      }
      uVar1 = SUB41(pHVar2,0);
      if (hLibModule == (HMODULE)0x0) {
        local_10 = &local_5c;
        RaiseException(0xc06d007e,0,1,(ULONG_PTR *)&local_10);
        return (FARPROC)local_40;
      }
    }
    pHVar2 = (HMODULE)FUN_0040ad94(uVar1,(char)local_30,uVar5,local_30,hLibModule);
    if (hLibModule == pHVar2) {
      FreeLibrary(hLibModule);
    }
    else if ((param_4[6] != 0) &&
            (local_14 = (undefined4 *)LocalAlloc(0x40,8), local_14 != (undefined4 *)0x0)) {
      local_14[1] = param_4;
      *local_14 = DAT_00427a24;
      DAT_00427a24 = local_14;
    }
  }
  local_44 = hLibModule;
  if (DAT_0042c590 != (code *)0x0) {
    pHVar3 = (HMODULE)(*DAT_0042c590)();
  }
  if (pHVar3 == (HMODULE)0x0) {
    if ((((param_4[5] == 0) || (param_4[7] == 0)) ||
        (piVar4 = (int *)((int)&hLibModule->unused + hLibModule[0xf].unused), *piVar4 != 0x4550)) ||
       (((piVar4[2] != local_1c || ((HMODULE)piVar4[0xd] != hLibModule)) ||
        (pHVar2 = *(HMODULE *)(local_24 + local_c * 4), pHVar2 == (HMODULE)0x0)))) {
      pHVar3 = (HMODULE)GetProcAddress(hLibModule,(LPCSTR)local_48);
      goto LAB_0040b66f;
    }
  }
  else {
LAB_0040b66f:
    pHVar2 = pHVar3;
    if (pHVar3 == (HMODULE)0x0) {
      local_3c = (HMODULE)GetLastError();
      if (DAT_0042c594 != (code *)0x0) {
        pHVar3 = (HMODULE)(*DAT_0042c594)();
      }
      pHVar2 = pHVar3;
      if (pHVar3 == (HMODULE)0x0) {
        local_18 = &local_5c;
        RaiseException(0xc06d007f,0,1,(ULONG_PTR *)&local_18);
        pHVar2 = local_40;
      }
    }
  }
  *param_5 = pHVar2;
LAB_0040b6be:
  if (DAT_0042c590 != (code *)0x0) {
    local_3c = (HMODULE)0x0;
    local_44 = hLibModule;
    local_40 = pHVar2;
    (*DAT_0042c590)();
  }
  return (FARPROC)pHVar2;
}



undefined4 FUN_0040b6ec(undefined param_1,undefined param_2,byte param_3,uint param_4)

{
  undefined4 *puVar1;
  HMODULE hLibModule;
  undefined4 *hMem;
  undefined uVar2;
  char *pcVar3;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  HMODULE *ppHVar7;
  int iVar9;
  int iVar10;
  uint uVar11;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 local_8;
  int iVar8;
  
  uVar11 = (uint)param_3;
  local_8 = 0;
  if (param_4 == 0) {
    pcVar3 = (char *)0x0;
    puVar1 = DAT_00427a24;
  }
  else {
    uVar11 = param_4;
    pcVar3 = FUN_0040b90c(0,param_2,param_3,param_4);
    puVar1 = DAT_00427a24;
  }
  do {
    do {
      hMem = puVar1;
      if (hMem == (undefined4 *)0x0) {
        return local_8;
      }
      uVar12 = *(undefined4 *)(hMem[1] + 4);
      uVar4 = FUN_0040b8bc((char)hMem[1],(char)uVar12,(char)uVar11,uVar12);
      uVar11 = uVar4;
      pcVar5 = FUN_0040b90c((char)uVar4,extraout_DL,(char)uVar12,uVar4);
      puVar1 = (undefined4 *)*hMem;
      uVar2 = extraout_DL_00;
    } while ((param_4 != 0) &&
            ((pcVar5 != pcVar3 ||
             (iVar6 = FUN_0040b920((char)puVar1,(char)pcVar5,(char)pcVar5,param_4,uVar4,pcVar5),
             uVar11 = extraout_ECX, uVar2 = extraout_DL_01, iVar6 != 0))));
    if ((hMem != (undefined4 *)0x0) && (uVar11 = hMem[1], *(int *)(uVar11 + 0x18) != 0)) {
      iVar6 = hMem[1];
      ppHVar7 = (HMODULE *)
                FUN_0040b8cc((char)*(undefined4 *)(iVar6 + 8),uVar2,(char)uVar11,
                             *(undefined4 *)(iVar6 + 8));
      hLibModule = *ppHVar7;
      uVar12 = *(undefined4 *)(iVar6 + 0x18);
      uVar2 = SUB41(ppHVar7,0);
      iVar8 = FUN_0040b8ec(uVar2,uVar2,(char)uVar12,uVar12);
      uVar13 = *(undefined4 *)(iVar6 + 0xc);
      iVar9 = FUN_0040b8dc((char)uVar13,extraout_DL_02,(char)uVar12,uVar13);
      iVar6 = iVar9;
      iVar10 = FUN_0040b950((char)iVar9,extraout_DL_03,(char)uVar13,iVar9);
      FUN_0040b968((char)(iVar10 << 2),(char)iVar8,(char)iVar6,iVar9,iVar8,iVar10 << 2);
      FreeLibrary(hLibModule);
      *ppHVar7 = (HMODULE)0x0;
      uVar11 = extraout_ECX_00;
      if (hMem != (undefined4 *)0x0) {
        FUN_0040b990(uVar2,0,(char)extraout_ECX_00,hMem);
        LocalFree(hMem);
        uVar11 = extraout_ECX_01;
      }
      local_8 = 1;
    }
  } while (param_4 == 0);
  return local_8;
}



undefined4 FUN_0040b7fc(undefined param_1,undefined param_2,undefined param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  int iVar5;
  uint uVar6;
  FARPROC pFVar7;
  undefined uVar8;
  undefined4 extraout_ECX;
  undefined4 uVar9;
  uint extraout_ECX_00;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 uVar10;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  uint uVar11;
  int iVar12;
  uint uVar13;
  undefined4 local_8;
  
  local_8 = 0x8007007e;
  uVar9 = 0;
  iVar1 = FUN_0040b9b4(0,0,param_3,0x31000);
  uVar10 = extraout_EDX;
  do {
    uVar8 = (undefined)uVar9;
    iVar5 = *(int *)(iVar1 + 4);
    if (iVar5 == 0) {
LAB_0040b871:
      if (*(int *)(iVar1 + 4) != 0) {
        uVar9 = *(undefined4 *)(iVar1 + 0xc);
        uVar6 = FUN_0040b9c4((char)iVar5,(char)uVar9,uVar8,uVar9);
        uVar13 = uVar6;
        pFVar7 = (FARPROC)FUN_0040b950((char)uVar6,extraout_DL_01,(char)uVar9,uVar6);
        uVar11 = (int)pFVar7 * 4 + uVar6;
        uVar9 = extraout_EDX_02;
        for (; uVar6 < uVar11; uVar6 = uVar6 + 4) {
          pFVar7 = FUN_0040b40c((char)pFVar7,(char)uVar9,(char)uVar13,iVar1,uVar6);
          uVar9 = extraout_EDX_03;
          uVar13 = extraout_ECX_00;
        }
        local_8 = 0;
      }
      return local_8;
    }
    iVar2 = FUN_0040b8bc((char)iVar5,(char)uVar10,uVar8,iVar5);
    iVar12 = iVar2;
    pcVar3 = FUN_0040b90c((char)iVar2,extraout_DL,(char)iVar5,iVar2);
    uVar9 = param_4;
    pcVar4 = FUN_0040b90c((char)param_4,extraout_DL_00,(char)iVar12,param_4);
    uVar10 = extraout_EDX_00;
    if (pcVar3 == pcVar4) {
      iVar5 = FUN_0040b920((char)pcVar4,(char)param_4,(char)uVar9,param_4,iVar2,pcVar3);
      uVar8 = (undefined)extraout_ECX;
      uVar9 = extraout_ECX;
      uVar10 = extraout_EDX_01;
      if (iVar5 == 0) {
        iVar5 = 0;
        goto LAB_0040b871;
      }
    }
    iVar1 = iVar1 + 0x20;
  } while( true );
}



void FUN_0040b8b4(void)

{
  undefined in_AL;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040b6ec(in_AL,in_DL,in_CL,0);
  return;
}



int FUN_0040b8bc(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  return param_4 + 0x400000;
}



int FUN_0040b8cc(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  return param_4 + 0x400000;
}



int FUN_0040b8dc(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  return param_4 + 0x400000;
}



int FUN_0040b8ec(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  return param_4 + 0x400000;
}



int FUN_0040b8fc(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  return param_4 + 0x400000;
}



char * FUN_0040b90c(undefined param_1,undefined param_2,undefined param_3,char *param_4)

{
  char cVar1;
  char *pcVar2;
  
  pcVar2 = param_4;
  do {
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  return pcVar2 + (-1 - (int)param_4);
}



int FUN_0040b920(undefined param_1,undefined param_2,undefined param_3,byte *param_4,byte *param_5,
                int param_6)

{
  if (param_6 == 0) {
    return 0;
  }
  for (; (param_6 = param_6 + -1, param_6 != 0 && (*param_4 == *param_5)); param_4 = param_4 + 1) {
    param_5 = param_5 + 1;
  }
  return (uint)*param_4 - (uint)*param_5;
}



int FUN_0040b950(undefined param_1,undefined param_2,undefined param_3,int *param_4)

{
  int iVar1;
  
  iVar1 = 0;
  for (; *param_4 != 0; param_4 = param_4 + 1) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}



undefined *
FUN_0040b968(undefined param_1,undefined param_2,undefined param_3,undefined *param_4,
            undefined *param_5,int param_6)

{
  undefined *puVar1;
  
  puVar1 = param_4;
  while (param_6 != 0) {
    *puVar1 = *param_5;
    puVar1 = puVar1 + 1;
    param_5 = param_5 + 1;
    param_6 = param_6 + -1;
  }
  return param_4;
}



void FUN_0040b990(undefined param_1,undefined param_2,undefined param_3,undefined4 *param_4)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  puVar1 = &DAT_00427a24;
  do {
    puVar2 = puVar1;
    puVar1 = (undefined4 *)*puVar2;
    if (puVar1 == (undefined4 *)0x0) break;
  } while (param_4 != puVar1);
  if (param_4 == (undefined4 *)*puVar2) {
    *puVar2 = *param_4;
  }
  return;
}



int FUN_0040b9b4(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  return param_4 + 0x400000;
}



int FUN_0040b9c4(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  return param_4 + 0x400000;
}



undefined4
FUN_0040ba28(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined4 param_6)

{
  undefined4 in_stack_00000000;
  
  thunk_FUN_0040b40c(param_1,param_2,param_3,&ImgDelayDescr_004310a0,in_stack_00000000);
  LOCK();
  UNLOCK();
  return param_6;
}



BOOL __stdcall
AllocateAndInitializeSid
          (PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,BYTE nSubAuthorityCount,
          DWORD nSubAuthority0,DWORD nSubAuthority1,DWORD nSubAuthority2,DWORD nSubAuthority3,
          DWORD nSubAuthority4,DWORD nSubAuthority5,DWORD nSubAuthority6,DWORD nSubAuthority7,
          PSID *pSid)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040ba38. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = AllocateAndInitializeSid
                    (pIdentifierAuthority,nSubAuthorityCount,nSubAuthority0,nSubAuthority1,
                     nSubAuthority2,nSubAuthority3,nSubAuthority4,nSubAuthority5,nSubAuthority6,
                     nSubAuthority7,pSid);
  return BVar1;
}



undefined4
FUN_0040ba40(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined4 param_6)

{
  undefined4 in_stack_00000000;
  
  thunk_FUN_0040b40c(param_1,param_2,param_3,&ImgDelayDescr_00431080,in_stack_00000000);
  LOCK();
  UNLOCK();
  return param_6;
}



void DelayLoad_EqualSid(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba28((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall EqualSid(PSID pSid1,PSID pSid2)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040ba60. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = EqualSid(pSid1,pSid2);
  return BVar1;
}



void DelayLoad_FreeSid(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba28((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



PVOID __stdcall FreeSid(PSID pSid)

{
  PVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040ba78. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = FreeSid(pSid);
  return pvVar1;
}



void DelayLoad_GetTokenInformation(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba28((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
GetTokenInformation(HANDLE TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass,
                   LPVOID TokenInformation,DWORD TokenInformationLength,PDWORD ReturnLength)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040ba90. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetTokenInformation(TokenHandle,TokenInformationClass,TokenInformation,
                              TokenInformationLength,ReturnLength);
  return BVar1;
}



void DelayLoad_LookupPrivilegeValueW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba28((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall LookupPrivilegeValueW(LPCWSTR lpSystemName,LPCWSTR lpName,PLUID lpLuid)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040baa8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = LookupPrivilegeValueW(lpSystemName,lpName,lpLuid);
  return BVar1;
}



void DelayLoad_OpenProcessToken(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba28((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall OpenProcessToken(HANDLE ProcessHandle,DWORD DesiredAccess,PHANDLE TokenHandle)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bac0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = OpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
  return BVar1;
}



void DelayLoad_OpenThreadToken(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba28((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
OpenThreadToken(HANDLE ThreadHandle,DWORD DesiredAccess,BOOL OpenAsSelf,PHANDLE TokenHandle)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bad8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = OpenThreadToken(ThreadHandle,DesiredAccess,OpenAsSelf,TokenHandle);
  return BVar1;
}



void DelayLoad_RegCloseKey(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba28((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LSTATUS __stdcall RegCloseKey(HKEY hKey)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040baf0. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegCloseKey(hKey);
  return LVar1;
}



void DelayLoad_RegOpenKeyExW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba28((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LSTATUS __stdcall
RegOpenKeyExW(HKEY hKey,LPCWSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bb08. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegOpenKeyExW(hKey,lpSubKey,ulOptions,samDesired,phkResult);
  return LVar1;
}



void DelayLoad_RegQueryValueExW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba28((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LSTATUS __stdcall
RegQueryValueExW(HKEY hKey,LPCWSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,
                LPDWORD lpcbData)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bb20. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegQueryValueExW(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
  return LVar1;
}



void DelayLoad_CloseHandle(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall CloseHandle(HANDLE hObject)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bb38. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CloseHandle(hObject);
  return BVar1;
}



void DelayLoad_CompareStringW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



int __stdcall
CompareStringW(LCID Locale,DWORD dwCmpFlags,PCNZWCH lpString1,int cchCount1,PCNZWCH lpString2,
              int cchCount2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bb50. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = CompareStringW(Locale,dwCmpFlags,lpString1,cchCount1,lpString2,cchCount2);
  return iVar1;
}



void DelayLoad_CreateDirectoryW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall CreateDirectoryW(LPCWSTR lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bb68. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CreateDirectoryW(lpPathName,lpSecurityAttributes);
  return BVar1;
}



void DelayLoad_CreateEventW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



HANDLE __stdcall
CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes,BOOL bManualReset,BOOL bInitialState,
            LPCWSTR lpName)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bb80. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateEventW(lpEventAttributes,bManualReset,bInitialState,lpName);
  return pvVar1;
}



void DelayLoad_CreateFileW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



HANDLE __stdcall
CreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,
           LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,
           DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bb98. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateFileW(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
                       dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
  return pvVar1;
}



void DelayLoad_CreateProcessW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
CreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,
              LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
              BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
              LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,
              LPPROCESS_INFORMATION lpProcessInformation)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bbb0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CreateProcessW(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
                         bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,
                         lpStartupInfo,lpProcessInformation);
  return BVar1;
}



void DelayLoad_DeleteFileW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall DeleteFileW(LPCWSTR lpFileName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bbc8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = DeleteFileW(lpFileName);
  return BVar1;
}



void DelayLoad_EnumCalendarInfoW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
EnumCalendarInfoW(CALINFO_ENUMPROCW lpCalInfoEnumProc,LCID Locale,CALID Calendar,CALTYPE CalType)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bbe0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = EnumCalendarInfoW(lpCalInfoEnumProc,Locale,Calendar,CalType);
  return BVar1;
}



void DelayLoad_EnumSystemLocalesW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void DelayLoad_FindResourceW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



HRSRC __stdcall FindResourceW(HMODULE hModule,LPCWSTR lpName,LPCWSTR lpType)

{
  HRSRC pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bc10. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = FindResourceW(hModule,lpName,lpType);
  return pHVar1;
}



void DelayLoad_FormatMessageW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall
FormatMessageW(DWORD dwFlags,LPCVOID lpSource,DWORD dwMessageId,DWORD dwLanguageId,LPWSTR lpBuffer,
              DWORD nSize,va_list *Arguments)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bc28. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = FormatMessageW(dwFlags,lpSource,dwMessageId,dwLanguageId,lpBuffer,nSize,Arguments);
  return DVar1;
}



void DelayLoad_FreeLibrary(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall FreeLibrary(HMODULE hLibModule)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bc40. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FreeLibrary(hLibModule);
  return BVar1;
}



void DelayLoad_GetCPInfo(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void DelayLoad_GetCommandLineW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LPWSTR __stdcall GetCommandLineW(void)

{
  LPWSTR pWVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bc70. Too many branches
                    // WARNING: Treating indirect jump as call
  pWVar1 = GetCommandLineW();
  return pWVar1;
}



void DelayLoad_GetCurrentProcess(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



HANDLE __stdcall GetCurrentProcess(void)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bc88. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GetCurrentProcess();
  return pvVar1;
}



void DelayLoad_GetCurrentThread(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



HANDLE __stdcall GetCurrentThread(void)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bca0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GetCurrentThread();
  return pvVar1;
}



void DelayLoad_GetDiskFreeSpaceW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
GetDiskFreeSpaceW(LPCWSTR lpRootPathName,LPDWORD lpSectorsPerCluster,LPDWORD lpBytesPerSector,
                 LPDWORD lpNumberOfFreeClusters,LPDWORD lpTotalNumberOfClusters)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bcb8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetDiskFreeSpaceW(lpRootPathName,lpSectorsPerCluster,lpBytesPerSector,
                            lpNumberOfFreeClusters,lpTotalNumberOfClusters);
  return BVar1;
}



DWORD __stdcall GetEnvironmentVariableW(LPCWSTR lpName,LPWSTR lpBuffer,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bcc0. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetEnvironmentVariableW(lpName,lpBuffer,nSize);
  return DVar1;
}



void DelayLoad_GetExitCodeProcess(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall GetExitCodeProcess(HANDLE hProcess,LPDWORD lpExitCode)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bcd8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetExitCodeProcess(hProcess,lpExitCode);
  return BVar1;
}



void DelayLoad_GetFileAttributesW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall GetFileAttributesW(LPCWSTR lpFileName)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bcf0. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileAttributesW(lpFileName);
  return DVar1;
}



void DelayLoad_GetFileSize(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall GetFileSize(HANDLE hFile,LPDWORD lpFileSizeHigh)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bd08. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileSize(hFile,lpFileSizeHigh);
  return DVar1;
}



void DelayLoad_GetFullPathNameW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall
GetFullPathNameW(LPCWSTR lpFileName,DWORD nBufferLength,LPWSTR lpBuffer,LPWSTR *lpFilePart)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bd20. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFullPathNameW(lpFileName,nBufferLength,lpBuffer,lpFilePart);
  return DVar1;
}



void DelayLoad_GetLastError(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bd38. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetLastError();
  return DVar1;
}



void DelayLoad_GetLocalTime(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void DelayLoad_GetLocaleInfoW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



int __stdcall GetLocaleInfoW(LCID Locale,LCTYPE LCType,LPWSTR lpLCData,int cchData)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bd68. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetLocaleInfoW(Locale,LCType,lpLCData,cchData);
  return iVar1;
}



void DelayLoad_GetModuleFileNameW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall GetModuleFileNameW(HMODULE hModule,LPWSTR lpFilename,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bd88. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetModuleFileNameW(hModule,lpFilename,nSize);
  return DVar1;
}



void DelayLoad_GetModuleHandleW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



HMODULE __stdcall GetModuleHandleW(LPCWSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bda0. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetModuleHandleW(lpModuleName);
  return pHVar1;
}



void DelayLoad_GetProcAddress(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



FARPROC __stdcall GetProcAddress(HMODULE hModule,LPCSTR lpProcName)

{
  FARPROC pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bdb8. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = GetProcAddress(hModule,lpProcName);
  return pFVar1;
}



void FUN_0040bdc0(undefined param_1,undefined param_2,undefined param_3,HMODULE param_4,
                 LPCWSTR param_5)

{
  LPCSTR lpProcName;
  undefined4 *in_FS_OFFSET;
  undefined *puVar1;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  longlong *local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_1c = &LAB_0040be5e;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  if ((uint)param_5 >> 0x10 == 0) {
    puStack_18 = &stack0xfffffffc;
    GetProcAddress(param_4,(LPCSTR)param_5);
    *in_FS_OFFSET = uStack_20;
    puStack_18 = &LAB_0040be65;
    puStack_1c = (undefined *)0x40be5d;
    FUN_00406b4c((int *)&local_8);
    return;
  }
  puVar1 = &LAB_0040be41;
  *in_FS_OFFSET = &stack0xffffffd4;
  FUN_00406b4c((int *)&local_8);
  FUN_00407068(&local_8,param_5,0);
  lpProcName = (LPCSTR)FUN_004070e0((int)local_8);
  GetProcAddress(param_4,lpProcName);
  *in_FS_OFFSET = puVar1;
  uStack_20 = 0x40be48;
  FUN_00406b4c((int *)&local_8);
  return;
}



void DelayLoad_GetStdHandle(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



HANDLE __stdcall GetStdHandle(DWORD nStdHandle)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040be80. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GetStdHandle(nStdHandle);
  return pvVar1;
}



void DelayLoad_GetSystemDirectoryW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



UINT __stdcall GetSystemDirectoryW(LPWSTR lpBuffer,UINT uSize)

{
  UINT UVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040be98. Too many branches
                    // WARNING: Treating indirect jump as call
  UVar1 = GetSystemDirectoryW(lpBuffer,uSize);
  return UVar1;
}



void DelayLoad_GetNativeSystemInfo(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void __stdcall GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo)

{
                    // WARNING: Could not recover jumptable at 0x0040beb0. Too many branches
                    // WARNING: Treating indirect jump as call
  GetNativeSystemInfo(lpSystemInfo);
  return;
}



void DelayLoad_GetSystemInfo(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void __stdcall GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)

{
                    // WARNING: Could not recover jumptable at 0x0040bec8. Too many branches
                    // WARNING: Treating indirect jump as call
  GetSystemInfo(lpSystemInfo);
  return;
}



void DelayLoad_GetThreadLocale(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LCID __stdcall GetThreadLocale(void)

{
  LCID LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bee0. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = GetThreadLocale();
  return LVar1;
}



void DelayLoad_GetUserDefaultLangID(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LANGID __stdcall GetUserDefaultLangID(void)

{
  LANGID LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bef8. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = GetUserDefaultLangID();
  return LVar1;
}



void DelayLoad_LocaleNameToLCID(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void DelayLoad_GetVersion(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall GetVersion(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bf28. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetVersion();
  return DVar1;
}



void DelayLoad_GetVersionExW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall GetVersionExW(LPOSVERSIONINFOW lpVersionInformation)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bf40. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetVersionExW(lpVersionInformation);
  return BVar1;
}



BOOL __stdcall GetVersionExW(LPOSVERSIONINFOW lpVersionInformation)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bf48. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetVersionExW(lpVersionInformation);
  return BVar1;
}



void DelayLoad_GetWindowsDirectoryW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



UINT __stdcall GetWindowsDirectoryW(LPWSTR lpBuffer,UINT uSize)

{
  UINT UVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bf60. Too many branches
                    // WARNING: Treating indirect jump as call
  UVar1 = GetWindowsDirectoryW(lpBuffer,uSize);
  return UVar1;
}



void DelayLoad_IsValidLocale(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void DelayLoad_LoadLibraryW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



HMODULE __stdcall LoadLibraryW(LPCWSTR lpLibFileName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bf90. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = LoadLibraryW(lpLibFileName);
  return pHVar1;
}



void DelayLoad_LoadResource(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



HGLOBAL __stdcall LoadResource(HMODULE hModule,HRSRC hResInfo)

{
  HGLOBAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bfa8. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = LoadResource(hModule,hResInfo);
  return pvVar1;
}



void DelayLoad_LockResource(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LPVOID __stdcall LockResource(HGLOBAL hResData)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bfc0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = LockResource(hResData);
  return pvVar1;
}



void DelayLoad_ReadFile(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
ReadFile(HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bfd8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ReadFile(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
  return BVar1;
}



void DelayLoad_RemoveDirectoryW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall RemoveDirectoryW(LPCWSTR lpPathName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040bff0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = RemoveDirectoryW(lpPathName);
  return BVar1;
}



void DelayLoad_ResetEvent(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall ResetEvent(HANDLE hEvent)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c008. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ResetEvent(hEvent);
  return BVar1;
}



void DelayLoad_SetEndOfFile(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall SetEndOfFile(HANDLE hFile)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c020. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetEndOfFile(hFile);
  return BVar1;
}



void DelayLoad_SetErrorMode(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



UINT __stdcall SetErrorMode(UINT uMode)

{
  UINT UVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c038. Too many branches
                    // WARNING: Treating indirect jump as call
  UVar1 = SetErrorMode(uMode);
  return UVar1;
}



void DelayLoad_SetEvent(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall SetEvent(HANDLE hEvent)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c050. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetEvent(hEvent);
  return BVar1;
}



void DelayLoad_SetFilePointer(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall
SetFilePointer(HANDLE hFile,LONG lDistanceToMove,PLONG lpDistanceToMoveHigh,DWORD dwMoveMethod)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c068. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = SetFilePointer(hFile,lDistanceToMove,lpDistanceToMoveHigh,dwMoveMethod);
  return DVar1;
}



void DelayLoad_SetLastError(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void __stdcall SetLastError(DWORD dwErrCode)

{
                    // WARNING: Could not recover jumptable at 0x0040c080. Too many branches
                    // WARNING: Treating indirect jump as call
  SetLastError(dwErrCode);
  return;
}



void DelayLoad_SizeofResource(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall SizeofResource(HMODULE hModule,HRSRC hResInfo)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c098. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = SizeofResource(hModule,hResInfo);
  return DVar1;
}



void DelayLoad_VerifyVersionInfoW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
VerifyVersionInfoW(LPOSVERSIONINFOEXW lpVersionInformation,DWORD dwTypeMask,
                  DWORDLONG dwlConditionMask)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c0b0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = VerifyVersionInfoW(lpVersionInformation,dwTypeMask,dwlConditionMask);
  return BVar1;
}



void DelayLoad_VerSetConditionMask(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void VerSetConditionMask(void)

{
                    // WARNING: Could not recover jumptable at 0x0040c0c8. Too many branches
                    // WARNING: Treating indirect jump as call
  VerSetConditionMask();
  return;
}



void DelayLoad_VirtualAlloc(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LPVOID __stdcall VirtualAlloc(LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c0e0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = VirtualAlloc(lpAddress,dwSize,flAllocationType,flProtect);
  return pvVar1;
}



void DelayLoad_VirtualFree(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall VirtualFree(LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c0f8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = VirtualFree(lpAddress,dwSize,dwFreeType);
  return BVar1;
}



BOOL __stdcall
VirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c100. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = VirtualProtect(lpAddress,dwSize,flNewProtect,lpflOldProtect);
  return BVar1;
}



void DelayLoad_VirtualQuery(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



SIZE_T __stdcall VirtualQuery(LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength)

{
  SIZE_T SVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c118. Too many branches
                    // WARNING: Treating indirect jump as call
  SVar1 = VirtualQuery(lpAddress,lpBuffer,dwLength);
  return SVar1;
}



void DelayLoad_WaitForSingleObject(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall WaitForSingleObject(HANDLE hHandle,DWORD dwMilliseconds)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c130. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = WaitForSingleObject(hHandle,dwMilliseconds);
  return DVar1;
}



void DelayLoad_WideCharToMultiByte(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



int __stdcall
WideCharToMultiByte(UINT CodePage,DWORD dwFlags,LPCWSTR lpWideCharStr,int cchWideChar,
                   LPSTR lpMultiByteStr,int cbMultiByte,LPCSTR lpDefaultChar,
                   LPBOOL lpUsedDefaultChar)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c148. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = WideCharToMultiByte(CodePage,dwFlags,lpWideCharStr,cchWideChar,lpMultiByteStr,cbMultiByte,
                              lpDefaultChar,lpUsedDefaultChar);
  return iVar1;
}



void DelayLoad_WriteFile(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040ba40((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,
         LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c160. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = WriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
  return BVar1;
}



undefined4
FUN_0040c168(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined4 param_6)

{
  undefined4 in_stack_00000000;
  
  thunk_FUN_0040b40c(param_1,param_2,param_3,&ImgDelayDescr_00431060,in_stack_00000000);
  LOCK();
  UNLOCK();
  return param_6;
}



void DelayLoad_GetFileVersionInfoW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c168((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall GetFileVersionInfoW(LPCWSTR lptstrFilename,DWORD dwHandle,DWORD dwLen,LPVOID lpData)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c188. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetFileVersionInfoW(lptstrFilename,dwHandle,dwLen,lpData);
  return BVar1;
}



void DelayLoad_GetFileVersionInfoSizeW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c168((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall GetFileVersionInfoSizeW(LPCWSTR lptstrFilename,LPDWORD lpdwHandle)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c1a0. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileVersionInfoSizeW(lptstrFilename,lpdwHandle);
  return DVar1;
}



void DelayLoad_VerQueryValueW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c168((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall VerQueryValueW(LPCVOID pBlock,LPCWSTR lpSubBlock,LPVOID *lplpBuffer,PUINT puLen)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c1b8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = VerQueryValueW(pBlock,lpSubBlock,lplpBuffer,puLen);
  return BVar1;
}



undefined4
FUN_0040c1c0(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined4 param_6)

{
  undefined4 in_stack_00000000;
  
  thunk_FUN_0040b40c(param_1,param_2,param_3,&ImgDelayDescr_00431040,in_stack_00000000);
  LOCK();
  UNLOCK();
  return param_6;
}



void DelayLoad_CallWindowProcW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LRESULT __stdcall
CallWindowProcW(WNDPROC lpPrevWndFunc,HWND hWnd,UINT Msg,WPARAM wParam,LPARAM lParam)

{
  LRESULT LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c1e0. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = CallWindowProcW(lpPrevWndFunc,hWnd,Msg,wParam,lParam);
  return LVar1;
}



void DelayLoad_CharLowerBuffW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall CharLowerBuffW(LPWSTR lpsz,DWORD cchLength)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c1f8. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = CharLowerBuffW(lpsz,cchLength);
  return DVar1;
}



void DelayLoad_CharUpperW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void DelayLoad_CharUpperBuffW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void DelayLoad_DestroyWindow(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall DestroyWindow(HWND hWnd)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c240. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = DestroyWindow(hWnd);
  return BVar1;
}



void DelayLoad_DispatchMessageW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LRESULT __stdcall DispatchMessageW(MSG *lpMsg)

{
  LRESULT LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c258. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = DispatchMessageW(lpMsg);
  return LVar1;
}



void DelayLoad_ExitWindowsEx(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall ExitWindowsEx(UINT uFlags,DWORD dwReason)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c270. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ExitWindowsEx(uFlags,dwReason);
  return BVar1;
}



void DelayLoad_GetSystemMetrics(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



int __stdcall GetSystemMetrics(int nIndex)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c288. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetSystemMetrics(nIndex);
  return iVar1;
}



void DelayLoad_LoadStringW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



int __stdcall LoadStringW(HINSTANCE hInstance,UINT uID,LPWSTR lpBuffer,int cchBufferMax)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c2a0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = LoadStringW(hInstance,uID,lpBuffer,cchBufferMax);
  return iVar1;
}



void DelayLoad_MessageBoxW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



int __stdcall MessageBoxW(HWND hWnd,LPCWSTR lpText,LPCWSTR lpCaption,UINT uType)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c2b8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MessageBoxW(hWnd,lpText,lpCaption,uType);
  return iVar1;
}



void DelayLoad_MsgWaitForMultipleObjects(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



DWORD __stdcall
MsgWaitForMultipleObjects
          (DWORD nCount,HANDLE *pHandles,BOOL fWaitAll,DWORD dwMilliseconds,DWORD dwWakeMask)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c2d0. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = MsgWaitForMultipleObjects(nCount,pHandles,fWaitAll,dwMilliseconds,dwWakeMask);
  return DVar1;
}



void DelayLoad_PeekMessageW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall
PeekMessageW(LPMSG lpMsg,HWND hWnd,UINT wMsgFilterMin,UINT wMsgFilterMax,UINT wRemoveMsg)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c2e8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = PeekMessageW(lpMsg,hWnd,wMsgFilterMin,wMsgFilterMax,wRemoveMsg);
  return BVar1;
}



void DelayLoad_TranslateMessage(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



BOOL __stdcall TranslateMessage(MSG *lpMsg)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c300. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = TranslateMessage(lpMsg);
  return BVar1;
}



HWND __stdcall
CreateWindowExW(DWORD dwExStyle,LPCWSTR lpClassName,LPCWSTR lpWindowName,DWORD dwStyle,int X,int Y,
               int nWidth,int nHeight,HWND hWndParent,HMENU hMenu,HINSTANCE hInstance,LPVOID lpParam
               )

{
  HWND pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c308. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = CreateWindowExW(dwExStyle,lpClassName,lpWindowName,dwStyle,X,Y,nWidth,nHeight,hWndParent,
                           hMenu,hInstance,lpParam);
  return pHVar1;
}



HWND FUN_0040c310(DWORD param_1,LPCWSTR param_2,LPCWSTR param_3,LPVOID param_4,HINSTANCE param_5,
                 HMENU param_6,HWND param_7,int param_8,int param_9,int param_10,int param_11,
                 DWORD param_12)

{
  undefined2 uVar1;
  HWND pHVar2;
  
  uVar1 = FUN_004047e8();
  pHVar2 = CreateWindowExW(param_1,param_2,param_3,param_12,param_11,param_10,param_9,param_8,
                           param_7,param_6,param_5,param_4);
  FUN_004047d8(uVar1);
  return pHVar2;
}



void DelayLoad_SetWindowLongW(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_0040c1c0((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



LONG __stdcall SetWindowLongW(HWND hWnd,int nIndex,LONG dwNewLong)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c378. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = SetWindowLongW(hWnd,nIndex,dwNewLong);
  return LVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040c380(void)

{
  BOOL BVar1;
  _OSVERSIONINFOW local_114;
  
  local_114.dwOSVersionInfoSize = 0x114;
  BVar1 = GetVersionExW(&local_114);
  if (BVar1 != 0) {
    _DAT_00427a80 = local_114.dwPlatformId;
    _DAT_00427a78 = local_114.dwMajorVersion;
    _DAT_00427a7c = local_114.dwMinorVersion;
  }
  return;
}



void FUN_0040c3dc(longlong *param_1,longlong **param_2)

{
  FUN_0040723c(param_2,param_1);
  return;
}



void FUN_0040c3f0(longlong **param_1)

{
  longlong local_20c [65];
  
  GetSystemDirectoryW((LPWSTR)local_20c,0x104);
  FUN_0040c3dc(local_20c,param_1);
  return;
}



void FUN_0040c41c(int param_1)

{
  LPCWSTR lpLibFileName;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_2c;
  undefined *puStack_28;
  undefined *puStack_24;
  undefined4 uStack_20;
  undefined *puStack_1c;
  
  puStack_24 = &stack0xfffffffc;
  puStack_1c = (undefined *)0x40c42f;
  SetErrorMode(0x8000);
  puStack_1c = &LAB_0040c492;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  puStack_28 = &LAB_0040c474;
  uStack_2c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_2c;
  lpLibFileName = (LPCWSTR)FUN_004071e4(param_1);
  LoadLibraryW(lpLibFileName);
  *in_FS_OFFSET = uStack_2c;
  return;
}



void __stdcall InitCommonControls(void)

{
                    // WARNING: Could not recover jumptable at 0x0040c4e0. Too many branches
                    // WARNING: Treating indirect jump as call
  InitCommonControls();
  return;
}



undefined * FUN_0040c88c(void)

{
  return &DAT_0040c892;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004124e0(void)

{
  DAT_0042c5c8 = (int *)FUN_0040c88c();
  DAT_0042c5cc = *DAT_0042c5c8 + (int)DAT_0042c5c8;
  DAT_0042c5d0 = DAT_0042c5c8[1] + (int)DAT_0042c5c8;
  DAT_0042c5d4 = DAT_0042c5c8[2] + (int)DAT_0042c5c8;
  _DAT_0042c5d8 = DAT_0042c5c8[3] + (int)DAT_0042c5c8;
  _DAT_0042c5dc = DAT_0042c5c8[4] + (int)DAT_0042c5c8;
  _DAT_0042c5e0 = DAT_0042c5c8[5] + (int)DAT_0042c5c8;
  _DAT_0042c5e4 = DAT_0042c5c8[6] + (int)DAT_0042c5c8;
  return;
}



undefined FUN_00412540(uint param_1)

{
  if (0x10ffff < param_1) {
    return 2;
  }
  return *(undefined *)
          (DAT_0042c5d4 +
          (uint)*(ushort *)
                 (DAT_0042c5d0 +
                 ((uint)*(byte *)(DAT_0042c5cc + (param_1 >> 8)) * 0x10 + (param_1 >> 4 & 0xf)) * 2)
          + (param_1 & 0xf));
}



bool FUN_00412580(ushort *param_1)

{
  char cVar1;
  uint uVar2;
  bool bVar3;
  
  uVar2 = (uint)*param_1;
  if (uVar2 < 0x80) {
    if ((0x60 < (uVar2 | 0x20)) && ((uVar2 | 0x20) < 0x7b)) {
      return true;
    }
    bVar3 = false;
  }
  else if (uVar2 < 0x100) {
    bVar3 = (byte)(*(char *)(DAT_0042c5d4 + uVar2) - 5U) < 5;
  }
  else {
    cVar1 = FUN_00412540(uVar2);
    bVar3 = (byte)(cVar1 - 5U) < 5;
  }
  return bVar3;
}



bool FUN_004125c8(ushort *param_1)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = (uint)*param_1;
  if (uVar2 < 0x80) {
    return uVar2 - 0x30 < 10;
  }
  if (uVar2 < 0x100) {
    cVar1 = *(char *)(DAT_0042c5d4 + uVar2);
  }
  else {
    cVar1 = FUN_00412540(uVar2);
  }
  return (byte)(cVar1 - 0xdU) < 3;
}



void FUN_00415134(undefined4 param_1)

{
  int *piVar1;
  
  piVar1 = FUN_00418bfc((int *)&PTR_LAB_00414184,'\x01',param_1);
  FUN_004062cc((int)piVar1);
  return;
}



void FUN_0041514c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  
  iVar1 = FUN_00418ccc((int)&PTR_LAB_00414184,'\x01',param_1,param_3,param_2);
  FUN_004062cc(iVar1);
  return;
}



uint FUN_004151dc(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  
  if (param_1 == 0) {
    uVar2 = 0;
    if (param_2 != 0) {
      uVar2 = -*(int *)(param_2 + -4);
    }
    return uVar2;
  }
  if (param_2 == 0) {
    return *(uint *)(param_1 + -4);
  }
  uVar2 = *(uint *)(param_2 + -4);
  uVar6 = *(uint *)(param_1 + -4) - uVar2;
  iVar3 = (-(uint)(*(uint *)(param_1 + -4) < uVar2) & uVar6) + uVar2;
  iVar1 = param_1 + iVar3 * 2;
  iVar4 = param_2 + iVar3 * 2;
  iVar3 = -iVar3;
  if (iVar3 != 0) {
    do {
      uVar2 = *(uint *)(iVar1 + iVar3 * 2);
      uVar5 = *(uint *)(iVar4 + iVar3 * 2);
      if (uVar2 != uVar5) {
        if ((short)uVar2 != (short)uVar5) {
          uVar2 = uVar2 & 0xffff;
          uVar5 = uVar5 & 0xffff;
          if ((0x60 < uVar2) && (uVar2 < 0x7b)) {
            uVar2 = uVar2 - 0x20;
          }
          if ((0x60 < uVar5) && (uVar5 < 0x7b)) {
            uVar5 = uVar5 - 0x20;
          }
          if (uVar2 - uVar5 != 0) {
            return uVar2 - uVar5;
          }
          uVar2 = *(uint *)(iVar1 + iVar3 * 2) & 0xffff0000;
          uVar5 = *(uint *)(iVar4 + iVar3 * 2) & 0xffff0000;
          if (uVar2 == uVar5) goto LAB_0041527f;
        }
        uVar2 = uVar2 >> 0x10;
        uVar5 = uVar5 >> 0x10;
        if ((0x60 < uVar2) && (uVar2 < 0x7b)) {
          uVar2 = uVar2 - 0x20;
        }
        if ((0x60 < uVar5) && (uVar5 < 0x7b)) {
          uVar5 = uVar5 - 0x20;
        }
        if (uVar2 - uVar5 != 0) {
          return uVar2 - uVar5;
        }
      }
LAB_0041527f:
      bVar7 = SCARRY4(iVar3,2);
      iVar3 = iVar3 + 2;
    } while (bVar7 != iVar3 < 0);
  }
  return uVar6;
}



void FUN_004152d0(DWORD param_1,longlong **param_2)

{
  DWORD cchLength;
  longlong *plVar1;
  LPWSTR lpsz;
  
  cchLength = param_1;
  if (param_1 != 0) {
    cchLength = *(DWORD *)(param_1 - 4);
  }
  plVar1 = (longlong *)FUN_004071e4(param_1);
  FUN_00406c80(param_2,plVar1,cchLength);
  if (0 < (int)cchLength) {
    lpsz = (LPWSTR)FUN_004071e4((int)*param_2);
    CharLowerBuffW(lpsz,cchLength);
  }
  return;
}



void FUN_0041530c(uint param_1,uint param_2,longlong **param_3)

{
  undefined2 *puVar1;
  undefined4 *puVar2;
  uint uVar3;
  uint uVar4;
  
  if (param_1 < 10000) {
    if (param_1 < 100) {
      uVar3 = (9 < param_1) + 1;
    }
    else {
      uVar3 = (999 < param_1) + 3;
    }
  }
  else if (param_1 < 1000000) {
    uVar3 = (99999 < param_1) + 5;
  }
  else if (param_1 < 100000000) {
    uVar3 = (9999999 < param_1) + 7;
  }
  else {
    uVar3 = (999999999 < param_1) + 9;
  }
  FUN_004072d0(param_3,(param_2 & 0xff) + uVar3);
  puVar1 = (undefined2 *)FUN_004071e4((int)*param_3);
  *puVar1 = 0x2d;
  puVar2 = (undefined4 *)(puVar1 + (param_2 & 0xff));
  uVar4 = param_1;
  if (2 < uVar3) {
    do {
      param_1 = uVar4 / 100;
      uVar3 = uVar3 - 2;
      *(undefined4 *)(uVar3 * 2 + (int)puVar2) = *(undefined4 *)(&DAT_00427c0c + (uVar4 % 100) * 4);
      uVar4 = param_1;
    } while (2 < (int)uVar3);
  }
  if (uVar3 == 2) {
    *puVar2 = *(undefined4 *)(&DAT_00427c0c + param_1 * 4);
  }
  else {
    *(ushort *)puVar2 = (ushort)param_1 | 0x30;
  }
  return;
}



void FUN_00415408(byte param_1,longlong **param_2,undefined4 param_3,uint param_4,uint param_5)

{
  ulonglong uVar1;
  undefined2 *puVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_EDX;
  byte bVar7;
  uint uVar8;
  undefined4 *puVar9;
  bool bVar10;
  uint local_14;
  uint local_10;
  
  if (((param_1 != 0) &&
      (param_5 == 0 && param_4 < 0x7fffffff || param_5 == 0 && param_4 == 0x7fffffff)) ||
     ((param_1 == 0 &&
      (param_5 == 0 && param_4 != 0xffffffff || param_5 == 0 && param_4 == 0xffffffff)))) {
    FUN_0041530c(param_4,(uint)param_1,param_2);
  }
  else {
    local_14 = param_4;
    local_10 = param_5;
    bVar10 = param_5 < 0x5af3;
    if (param_5 == 0x5af3) {
      bVar10 = param_4 < 0x107a4000;
    }
    if (bVar10) {
      bVar10 = param_5 < 0xe8;
      if (param_5 == 0xe8) {
        bVar10 = param_4 < 0xd4a51000;
      }
      if (bVar10) {
        bVar10 = param_5 < 2;
        if (param_5 == 2) {
          bVar10 = param_4 < 0x540be400;
        }
        if (bVar10) {
          uVar8 = 10;
        }
        else {
          bVar10 = param_5 < 0x17;
          if (param_5 == 0x17) {
            bVar10 = param_4 < 0x4876e800;
          }
          uVar8 = (uint)(byte)(!bVar10 + 0xb);
        }
      }
      else {
        bVar10 = param_5 < 0x918;
        if (param_5 == 0x918) {
          bVar10 = param_4 < 0x4e72a000;
        }
        uVar8 = (uint)(byte)(!bVar10 + 0xd);
      }
    }
    else {
      bVar10 = param_5 < 0x2386f2;
      if (param_5 == 0x2386f2) {
        bVar10 = param_4 < 0x6fc10000;
      }
      if (bVar10) {
        bVar10 = param_5 < 0x38d7e;
        if (param_5 == 0x38d7e) {
          bVar10 = param_4 < 0xa4c68000;
        }
        uVar8 = (uint)(byte)(!bVar10 + 0xf);
      }
      else {
        bVar10 = param_5 < 0xde0b6b3;
        if (param_5 == 0xde0b6b3) {
          bVar10 = param_4 < 0xa7640000;
        }
        if (bVar10) {
          bVar10 = param_5 < 0x1634578;
          if (param_5 == 0x1634578) {
            bVar10 = param_4 < 0x5d8a0000;
          }
          uVar8 = (uint)(byte)(!bVar10 + 0x11);
        }
        else {
          bVar10 = param_5 < 0x8ac72304;
          if (param_5 == 0x8ac72304) {
            bVar10 = param_4 < 0x89e80000;
          }
          if (bVar10) {
            uVar8 = 0x13;
          }
          else {
            uVar8 = 0x14;
          }
        }
      }
    }
    FUN_004072d0(param_2,uVar8 + param_1);
    puVar2 = (undefined2 *)FUN_004071e4((int)*param_2);
    *puVar2 = 0x2d;
    puVar9 = (undefined4 *)(puVar2 + param_1);
    if ((char)uVar8 == '\x14') {
      *(short *)puVar9 = 0x31;
      puVar9 = (undefined4 *)((int)puVar9 + 2);
      local_14 = param_4 + 0x76180000;
      local_10 = (param_5 + 0x7538dcfc) - (uint)(param_4 < 0x89e80000);
      uVar8 = uVar8 - 1;
    }
    if (0x11 < (byte)uVar8) {
      if ((byte)uVar8 == 0x13) {
        *(short *)puVar9 = 0x30;
        while( true ) {
          bVar10 = local_10 < 0xde0b6b3;
          if (local_10 == 0xde0b6b3) {
            bVar10 = local_14 < 0xa7640000;
          }
          if (bVar10) break;
          bVar10 = local_14 < 0xa7640000;
          local_14 = local_14 + 0x589c0000;
          local_10 = (local_10 + 0xf21f494d) - (uint)bVar10;
          *(short *)puVar9 = *(short *)puVar9 + 1;
        }
        puVar9 = (undefined4 *)((int)puVar9 + 2);
      }
      *(short *)puVar9 = 0x30;
      while( true ) {
        bVar10 = local_10 < 0x1634578;
        if (local_10 == 0x1634578) {
          bVar10 = local_14 < 0x5d8a0000;
        }
        if (bVar10) break;
        bVar10 = local_14 < 0x5d8a0000;
        local_14 = local_14 + 0xa2760000;
        local_10 = (local_10 + 0xfe9cba88) - (uint)bVar10;
        *(short *)puVar9 = *(short *)puVar9 + 1;
      }
      puVar9 = (undefined4 *)((int)puVar9 + 2);
      uVar8 = 0x11;
    }
    uVar3 = FUN_004083b0(local_14,local_10,extraout_ECX,100000000,0);
    iVar4 = FUN_0040838c(uVar3,extraout_EDX,extraout_ECX_00,100000000);
    uVar5 = (local_14 - iVar4) / 100;
    *(undefined4 *)((int)puVar9 + (uVar8 & 0xff) * 2 + -4) =
         *(undefined4 *)(&DAT_00427c0c + ((local_14 - iVar4) % 100) * 4);
    uVar1 = (ulonglong)uVar5 / 100;
    iVar4 = (int)uVar1;
    *(undefined4 *)((int)puVar9 + (uVar8 & 0xff) * 2 + -8) =
         *(undefined4 *)(&DAT_00427c0c + (uVar5 + iVar4 * -100) * 4);
    iVar6 = (int)(uVar1 / 100);
    *(undefined4 *)((int)puVar9 + (uVar8 & 0xff) * 2 + -0xc) =
         *(undefined4 *)(&DAT_00427c0c + (iVar4 + iVar6 * -100) * 4);
    *(undefined4 *)((int)puVar9 + (uVar8 & 0xff) * 2 + -0x10) =
         *(undefined4 *)(&DAT_00427c0c + iVar6 * 4);
    bVar7 = (char)uVar8 - 8;
    while (2 < bVar7) {
      bVar7 = bVar7 - 2;
      *(undefined4 *)((uint)bVar7 * 2 + (int)puVar9) =
           *(undefined4 *)(&DAT_00427c0c + (uVar3 % 100) * 4);
      uVar3 = uVar3 / 100;
    }
    if (bVar7 == 2) {
      *puVar9 = *(undefined4 *)(&DAT_00427c0c + uVar3 * 4);
    }
    else {
      *(ushort *)puVar9 = (ushort)uVar3 | 0x30;
    }
  }
  return;
}



void FUN_00415718(uint param_1,longlong **param_2)

{
  if ((int)param_1 < 0) {
    FUN_0041530c(-param_1,CONCAT31((int3)((uint)param_2 >> 8),1),param_2);
    return;
  }
  FUN_0041530c(param_1,0,param_2);
  return;
}



// WARNING: Removing unreachable block (ram,0x00415752)

void FUN_00415740(longlong **param_1,undefined4 param_2,undefined4 param_3,uint param_4,uint param_5
                 )

{
  if ((param_5 == 0) || (-1 < (int)param_5)) {
    FUN_00415408(0,param_1,param_3,param_4,param_5);
  }
  else {
    FUN_00415408(1,param_1,param_3,-param_4,-(param_5 + (param_4 != 0)));
  }
  return;
}



void FUN_00415784(uint param_1,longlong **param_2)

{
  FUN_0041530c(param_1,0,param_2);
  return;
}



void FUN_00415798(longlong **param_1,undefined4 param_2,undefined4 param_3,uint param_4,uint param_5
                 )

{
  FUN_00415408(0,param_1,param_3,param_4,param_5);
  return;
}



void FUN_004157b4(uint param_1,int param_2,int param_3,longlong **param_4,undefined2 param_5)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  longlong *plVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  longlong *local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_20 = &LAB_004158a9;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  if (param_3 < param_2) {
    puStack_1c = &stack0xfffffffc;
    FUN_004087a4(&local_8,(int)&DAT_004024c8,1);
    iVar1 = param_2 - param_3;
    if (-1 < iVar1 + -1) {
      iVar3 = 0;
      do {
        *(undefined2 *)((int)local_8 + iVar3 * 2) = param_5;
        iVar3 = iVar3 + 1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
    iVar1 = param_2 - param_3;
  }
  else {
    FUN_004087a4(&local_8,(int)&DAT_004024c8,1);
    iVar1 = 0;
  }
  puVar2 = (undefined4 *)((int)local_8 + (param_3 + iVar1) * 2);
  if (1 < param_3) {
    do {
      param_3 = param_3 + -2;
      puVar2 = puVar2 + -1;
      *puVar2 = *(undefined4 *)(&DAT_00427d9c + (param_1 & 0xff) * 4);
      param_1 = param_1 >> 8;
    } while (1 < param_3);
  }
  if (param_3 == 1) {
    *(undefined2 *)((int)local_8 + iVar1 * 2) = *(undefined2 *)(&DAT_0042819c + (param_1 & 0xf) * 2)
    ;
  }
  plVar4 = local_8;
  if (local_8 != (longlong *)0x0) {
    plVar4 = *(longlong **)((int)local_8 + -4);
  }
  FUN_0041b314(local_8,(int)plVar4 + -1,param_4);
  *in_FS_OFFSET = uStack_24;
  puStack_1c = &LAB_004158b0;
  puStack_20 = (undefined *)0x4158a8;
  FUN_004088c8((int *)&local_8,(int)&DAT_004024c8);
  return;
}



void FUN_004158bc(int param_1,int param_2,undefined2 param_3,longlong **param_4,uint param_5,
                 uint param_6)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  longlong *plVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  longlong *local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_20 = &LAB_004159cc;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  if (param_2 < param_1) {
    puStack_1c = &stack0xfffffffc;
    FUN_004087a4(&local_8,(int)&DAT_004024c8,1);
    iVar1 = param_1 - param_2;
    if (-1 < iVar1 + -1) {
      iVar3 = 0;
      do {
        *(undefined2 *)((int)local_8 + iVar3 * 2) = param_3;
        iVar3 = iVar3 + 1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
    iVar1 = param_1 - param_2;
  }
  else {
    FUN_004087a4(&local_8,(int)&DAT_004024c8,1);
    iVar1 = 0;
  }
  puVar2 = (undefined4 *)((int)local_8 + (param_2 + iVar1) * 2);
  if (1 < param_2) {
    do {
      param_2 = param_2 + -2;
      puVar2 = puVar2 + -1;
      *puVar2 = *(undefined4 *)(&DAT_00427d9c + (param_5 & 0xff) * 4);
      param_5 = param_5 >> 8 | param_6 << 0x18;
      param_6 = param_6 >> 8;
    } while (1 < param_2);
  }
  if (param_2 == 1) {
    *(undefined2 *)((int)local_8 + iVar1 * 2) = *(undefined2 *)(&DAT_0042819c + (param_5 & 0xf) * 2)
    ;
  }
  plVar4 = local_8;
  if (local_8 != (longlong *)0x0) {
    plVar4 = *(longlong **)((int)local_8 + -4);
  }
  FUN_0041b314(local_8,(int)plVar4 + -1,param_4);
  *in_FS_OFFSET = uStack_24;
  puStack_1c = &LAB_004159d3;
  puStack_20 = (undefined *)0x4159cb;
  FUN_004088c8((int *)&local_8,(int)&DAT_004024c8);
  return;
}



void FUN_004159dc(uint param_1,int param_2,longlong **param_3)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = 1;
  for (uVar1 = param_1 >> 4; uVar1 != 0; uVar1 = uVar1 >> 4) {
    iVar2 = iVar2 + 1;
  }
  FUN_004157b4(param_1,param_2,iVar2,param_3,0x30);
  return;
}



void FUN_00415a14(int param_1,longlong **param_2,undefined4 param_3,uint param_4,uint param_5)

{
  int iVar1;
  uint local_c;
  uint local_8;
  
  iVar1 = 1;
  local_c = param_4 >> 4 | param_5 << 0x1c;
  for (local_8 = param_5 >> 4; local_8 != 0 || local_c != 0; local_8 = local_8 >> 4) {
    iVar1 = iVar1 + 1;
    local_c = local_c >> 4 | local_8 << 0x1c;
  }
  FUN_004158bc(param_1,iVar1,0x30,param_2,param_4,param_5);
  return;
}



void FUN_00415a78(uint param_1,int param_2,longlong **param_3)

{
  FUN_004159dc(param_1,param_2,param_3);
  return;
}



void FUN_00415a90(int param_1,longlong **param_2,undefined4 param_3,uint param_4,uint param_5)

{
  FUN_00415a14(param_1,param_2,param_3,param_4,param_5);
  return;
}



ushort * FUN_00415aec(ushort *param_1,ushort *param_2,uint param_3)

{
  ushort *puVar1;
  uint local_8;
  
  local_8 = param_3;
  puVar1 = FUN_00404994(param_1,&local_8);
  if (local_8 != 0) {
    puVar1 = param_2;
  }
  return puVar1;
}



bool FUN_00415b04(ushort *param_1,ushort **param_2,uint param_3)

{
  ushort *puVar1;
  uint local_c;
  
  local_c = param_3;
  puVar1 = FUN_00404994(param_1,&local_c);
  *param_2 = puVar1;
  return local_c == 0;
}



void FUN_00415bac(undefined4 param_1,longlong **param_2)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  undefined4 local_c;
  longlong *local_8;
  
  puStack_18 = (undefined *)0x415bc6;
  FUN_00407764((int)&local_c,"\x0e\bTStrData\b");
  puStack_1c = &LAB_00415c12;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  puStack_18 = &stack0xfffffffc;
  local_c = param_1;
  FUN_00406b28((int *)&local_8);
  FUN_004093d8(&LAB_00415b6c,&local_c);
  FUN_00406dfc(param_2,local_8);
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_00415c19;
  puStack_1c = (undefined *)0x415c11;
  FUN_004078e0((int)&local_c,"\x0e\bTStrData\b");
  return;
}



void FUN_00415c20(undefined4 param_1,longlong **param_2)

{
  FUN_00415bac(param_1,param_2);
  return;
}



void FUN_00415c34(int param_1,longlong **param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  int local_c;
  longlong *local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_20 = &LAB_00415cd4;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  puStack_28 = (undefined *)0x415c62;
  local_c = param_1;
  iVar1 = FUN_0041b344(&local_c,(int)&LAB_00415cf0);
  puStack_2c = &LAB_00415cb7;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  puStack_28 = &stack0xfffffffc;
  FUN_00406b28((int *)&local_8);
  iVar2 = local_c;
  if (local_c != 0) {
    iVar2 = *(int *)(local_c + -4);
  }
  FUN_004074e0(local_c,iVar1 + 2,iVar2,&local_8);
  FUN_00406dfc(param_2,local_8);
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_00415cbe;
  puStack_2c = (undefined *)0x415cb6;
  FUN_00406b28((int *)&local_8);
  return;
}



short * FUN_00415d6c(short *param_1)

{
  short *psVar1;
  short *psVar2;
  
  if (*param_1 != 0) {
    psVar1 = param_1 + 1;
    do {
      psVar2 = psVar1;
      psVar1 = psVar2 + 1;
    } while (*psVar2 != 0);
    return psVar2;
  }
  return param_1;
}



longlong * FUN_00415d88(longlong *param_1,longlong *param_2,int param_3)

{
  FUN_0040465c(param_2,param_1,param_3 * 2);
  return param_1;
}



longlong * FUN_00415d98(longlong *param_1,longlong *param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = FUN_00406f00((int)param_2);
  if (param_3 < uVar1) {
    uVar1 = param_3;
  }
  FUN_0040465c(param_2,param_1,uVar1 * 2);
  *(undefined2 *)((int)param_1 + uVar1 * 2) = 0;
  return param_1;
}



short * thunk_FUN_00415dde(short *param_1,short param_2)

{
  while( true ) {
    if (*param_1 == 0) {
      if (param_2 != 0) {
        param_1 = (short *)0x0;
      }
      return param_1;
    }
    if (param_2 == *param_1) break;
    param_1 = param_1 + 1;
  }
  return param_1;
}



short * FUN_00415dde(short *param_1,short param_2)

{
  while( true ) {
    if (*param_1 == 0) {
      if (param_2 != 0) {
        param_1 = (short *)0x0;
      }
      return param_1;
    }
    if (param_2 == *param_1) break;
    param_1 = param_1 + 1;
  }
  return param_1;
}



short * FUN_00415df0(short *param_1,short param_2)

{
  short *psVar1;
  short *psVar2;
  
  if (param_2 == 0) {
    psVar1 = FUN_00415d6c(param_1);
  }
  else {
    psVar1 = (short *)0x0;
    while( true ) {
      while (psVar2 = param_1, param_2 == *psVar2) {
        psVar1 = psVar2;
        param_1 = psVar2 + 1;
      }
      if (*psVar2 == 0) break;
      param_1 = psVar2 + 1;
    }
  }
  return psVar1;
}



short * FUN_00415e20(short *param_1,short *param_2)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  short *psVar8;
  bool bVar9;
  
  if ((param_1 != (short *)0x0) && (param_2 != (short *)0x0)) {
    uVar2 = 0xffffffff;
    psVar7 = param_2;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      sVar1 = *psVar7;
      psVar7 = psVar7 + 1;
    } while (sVar1 != 0);
    uVar3 = ~uVar2 - 1;
    if (uVar3 != 0) {
      uVar4 = 0xffffffff;
      psVar7 = param_1;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        sVar1 = *psVar7;
        psVar7 = psVar7 + 1;
      } while (sVar1 != 0);
      iVar5 = ~uVar4 - uVar3;
      bVar9 = iVar5 == 0;
      if (uVar3 <= ~uVar4 && !bVar9) {
        do {
          psVar7 = param_2 + 1;
          psVar8 = param_1;
          do {
            param_1 = psVar8;
            if (iVar5 == 0) break;
            iVar5 = iVar5 + -1;
            param_1 = psVar8 + 1;
            bVar9 = *param_2 == *psVar8;
            psVar8 = param_1;
          } while (!bVar9);
          iVar6 = ~uVar2 - 2;
          psVar8 = param_1;
          if (!bVar9) {
            return (short *)0x0;
          }
          do {
            if (iVar6 == 0) break;
            bVar9 = *psVar7 == *psVar8;
            iVar6 = iVar6 + -1;
            psVar8 = psVar8 + 1;
            psVar7 = psVar7 + 1;
          } while (bVar9);
          if (bVar9) {
            return param_1 + -1;
          }
        } while( true );
      }
    }
  }
  return (short *)0x0;
}



void FUN_00415e78(longlong *param_1,longlong **param_2)

{
  FUN_0040723c(param_2,param_1);
  return;
}



void FUN_00415e8c(int param_1,longlong *param_2,uint param_3)

{
  undefined4 uVar1;
  undefined2 uStack_56;
  longlong alStack_54 [8];
  longlong *local_14;
  undefined local_10;
  
  local_14 = alStack_54;
  if (0x1f < param_3) {
    param_3 = 0x1f;
  }
  uVar1 = FUN_00419d04((int)param_2,param_3 - 1);
  if ((char)uVar1 == '\x01') {
    param_3 = param_3 - 1;
  }
  FUN_00415d88(alStack_54,param_2,param_3);
  *(undefined2 *)((int)alStack_54 + param_3 * 2) = 0;
  local_10 = 10;
  FUN_0041514c((&PTR_PTR_DAT_004281bc)[param_1],&local_14,0);
  return;
}



void FUN_00415ee8(ushort *param_1,uint param_2,longlong *param_3,undefined4 *param_4,int param_5,
                 int param_6,uint param_7)

{
  FUN_004162e8(param_1,param_2,param_3,param_4,param_5,param_6,param_7);
  return;
}



void FUN_00415f08(ushort *param_1,uint param_2,longlong *param_3,int param_4,int param_5)

{
  FUN_00415f24(param_1,param_2,param_3,(undefined4 *)&DAT_0042c610,param_4,param_5);
  return;
}



ushort * FUN_00415f24(ushort *param_1,uint param_2,longlong *param_3,undefined4 *param_4,int param_5
                     ,int param_6)

{
  uint uVar1;
  int iVar2;
  
  if ((param_1 == (ushort *)0x0) || (param_3 == (longlong *)0x0)) {
    param_1 = (ushort *)0x0;
  }
  else {
    uVar1 = FUN_00406f00((int)param_3);
    iVar2 = FUN_004162e8(param_1,param_2,param_3,param_4,param_5,param_6,uVar1);
    param_1[iVar2] = 0;
  }
  return param_1;
}



void FUN_00415f70(longlong *param_1,int param_2,int param_3,undefined4 param_4)

{
  FUN_00415f98(param_1,param_2,param_3,param_4,(undefined4 *)&DAT_0042c610);
  return;
}



void FUN_00415f98(longlong *param_1,int param_2,int param_3,undefined4 param_4,undefined4 *param_5)

{
  FUN_00415fb0(param_4,param_1,param_2,param_5,param_3);
  return;
}



void FUN_00415fb0(undefined4 param_1,longlong *param_2,int param_3,undefined4 *param_4,int param_5)

{
  longlong **pplVar1;
  longlong **pplVar2;
  longlong *plVar3;
  ushort *puVar4;
  longlong *plVar5;
  longlong local_2010 [508];
  undefined4 uStackY_1030;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  longlong *local_10;
  
  pplVar1 = (longlong **)0x2;
  do {
    pplVar2 = pplVar1;
    pplVar1 = (longlong **)((int)pplVar2 + -1);
  } while ((longlong **)((int)pplVar2 + -1) != (longlong **)0x0);
  plVar3 = param_2;
  if (param_2 != (longlong *)0x0) {
    plVar3 = *(longlong **)((int)param_2 + -4);
  }
  if ((int)plVar3 < 0xc00) {
    plVar3 = param_2;
    if (param_2 != (longlong *)0x0) {
      plVar3 = *(longlong **)((int)param_2 + -4);
    }
    uStackY_1030 = 0x416019;
    local_10 = (longlong *)
               FUN_00415ee8((ushort *)local_2010,0xfff,param_2,param_4,param_5,param_3,(uint)plVar3)
    ;
    plVar3 = (longlong *)0x1000;
  }
  else {
    plVar3 = param_2;
    local_10 = param_2;
    if (param_2 != (longlong *)0x0) {
      plVar3 = *(longlong **)((int)param_2 + -4);
      local_10 = plVar3;
    }
  }
  if ((int)local_10 < (int)plVar3 + -1) {
    FUN_00406c80(pplVar2,local_2010,(int)local_10);
  }
  else {
    while ((int)plVar3 + -1 <= (int)local_10) {
      plVar3 = (longlong *)((int)plVar3 * 2);
      FUN_00406b28((int *)pplVar2);
      FUN_004072d0(pplVar2,(int)plVar3);
      plVar5 = param_2;
      if (param_2 != (longlong *)0x0) {
        plVar5 = *(longlong **)((int)param_2 + -4);
      }
      uStackY_1030 = 0x41606a;
      puVar6 = param_4;
      iVar7 = param_5;
      iVar8 = param_3;
      puVar4 = (ushort *)FUN_004071e4((int)*pplVar2);
      uStackY_1030 = 0x416075;
      local_10 = (longlong *)
                 FUN_00415ee8(puVar4,(int)plVar3 - 1,param_2,puVar6,iVar7,iVar8,(uint)plVar5);
    }
    FUN_004072d0(pplVar2,(int)local_10);
  }
  return;
}



undefined4 FUN_004160a8(int param_1,int param_2,undefined4 param_3,int param_4)

{
  int iVar1;
  
  if ((param_1 < *(int *)(param_4 + -4)) && (*(short *)(param_4 + -6) != 0x53)) {
    param_1 = *(int *)(param_4 + -4);
  }
  if (((*(int *)(param_4 + -0xc) != -1) && (param_2 + param_1 < *(int *)(param_4 + -0xc))) &&
     (iVar1 = param_2 + 1 + param_1, iVar1 <= *(int *)(param_4 + -0xc))) {
    iVar1 = (*(int *)(param_4 + -0xc) - iVar1) + 1;
    do {
      if (*(int *)(param_4 + -0x10) == 0) {
        return 1;
      }
      **(undefined2 **)(param_4 + -0x14) = 0x20;
      *(int *)(param_4 + -0x14) = *(int *)(param_4 + -0x14) + 2;
      *(int *)(param_4 + -0x10) = *(int *)(param_4 + -0x10) + -2;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return 0;
}



uint FUN_0041611c(longlong *param_1,int param_2,int param_3,int param_4)

{
  int iVar1;
  int extraout_ECX;
  int extraout_ECX_00;
  int iVar2;
  undefined3 uVar3;
  bool bVar4;
  int local_14;
  longlong *local_10;
  uint local_c;
  
  if (param_1 == (longlong *)0x0) {
    iVar1 = 0;
  }
  else {
    iVar1 = param_3;
    if (param_3 == -1) {
      iVar1 = FUN_00406f00((int)param_1);
      param_3 = extraout_ECX;
    }
  }
  if ((-1 < param_2) && (param_2 < iVar1)) {
    iVar1 = param_2;
  }
  local_c = iVar1 * 2;
  if (((param_1 == (longlong *)0x0) || (*(short *)param_1 != 0x2d)) ||
     (*(short *)(param_4 + -6) == 0x53)) {
    local_14 = 0;
  }
  else {
    local_c = local_c - 2;
    iVar1 = iVar1 + -1;
    local_14 = 1;
  }
  if ((*(char *)(param_4 + -0x15) != '\0') ||
     (iVar2 = param_4, param_2 = FUN_004160a8(iVar1,local_14,param_3,param_4), param_3 = iVar2,
     (char)param_2 == '\0')) {
    uVar3 = (undefined3)((uint)param_2 >> 8);
    local_10 = param_1;
    if (local_14 == 1) {
      if (*(int *)(param_4 + -0x10) == 0) {
        return CONCAT31(uVar3,1);
      }
      local_10 = (longlong *)((int)param_1 + 2);
      **(undefined2 **)(param_4 + -0x14) = 0x2d;
      *(int *)(param_4 + -0x14) = *(int *)(param_4 + -0x14) + 2;
      *(int *)(param_4 + -0x10) = *(int *)(param_4 + -0x10) + -2;
    }
    if (((*(int *)(param_4 + -4) != -1) && (iVar1 < *(int *)(param_4 + -4))) &&
       ((*(short *)(param_4 + -6) != 0x53 && (iVar1 + 1 <= *(int *)(param_4 + -4))))) {
      iVar2 = (*(int *)(param_4 + -4) - (iVar1 + 1)) + 1;
      do {
        if (*(int *)(param_4 + -0x10) == 0) {
          return CONCAT31(uVar3,1);
        }
        **(undefined2 **)(param_4 + -0x14) = 0x30;
        *(int *)(param_4 + -0x14) = *(int *)(param_4 + -0x14) + 2;
        *(int *)(param_4 + -0x10) = *(int *)(param_4 + -0x10) + -2;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    if (param_1 == (longlong *)0x0) {
      param_2 = 0;
    }
    else {
      bVar4 = *(uint *)(param_4 + -0x10) < local_c;
      param_2 = CONCAT31(uVar3,bVar4);
      if (bVar4) {
        local_c = *(uint *)(param_4 + -0x10);
      }
      FUN_0040465c(local_10,*(longlong **)(param_4 + -0x14),local_c);
      *(uint *)(param_4 + -0x14) = *(int *)(param_4 + -0x14) + local_c;
      *(int *)(param_4 + -0x10) = *(int *)(param_4 + -0x10) - local_c;
      param_3 = extraout_ECX_00;
    }
    if (*(char *)(param_4 + -0x15) != '\0') {
      param_2 = FUN_004160a8(iVar1,local_14,param_3,param_4);
    }
  }
  return param_2;
}



void FUN_0041629c(undefined4 *param_1,int *param_2)

{
  undefined4 local_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  undefined4 uStack_8;
  
  local_14 = *param_1;
  uStack_10 = param_1[1];
  uStack_c = param_1[2];
  uStack_8 = param_1[3];
  FUN_00406b28(param_2);
  if ((short)local_14 != 1) {
    if (*(int *)PTR_DAT_00428464 == 0) {
      FUN_004045f4(0x10);
    }
    else {
      (**(code **)PTR_DAT_00428464)(param_2,&local_14);
    }
  }
  return;
}



void FUN_004162e8(ushort *param_1,uint param_2,longlong *param_3,undefined4 *param_4,int param_5,
                 int param_6,uint param_7)

{
  char cVar1;
  uint *puVar2;
  uint *puVar3;
  longlong *plVar4;
  bool bVar5;
  uint uVar6;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 extraout_ECX_05;
  undefined4 extraout_ECX_06;
  undefined4 extraout_ECX_07;
  undefined4 uVar7;
  undefined4 extraout_ECX_08;
  undefined4 extraout_ECX_09;
  longlong *plVar8;
  longlong *plVar9;
  longlong *plVar10;
  ushort *puVar11;
  undefined4 *in_FS_OFFSET;
  undefined *puVar12;
  undefined4 uStack_10c;
  undefined *puStack_108;
  undefined *puStack_104;
  int local_f4;
  longlong *local_f0;
  longlong *local_ec;
  longlong *local_e8;
  longlong *local_e4;
  longlong *local_e0;
  longlong local_da [16];
  longlong *local_58;
  longlong *local_54;
  longlong *local_50;
  undefined local_49;
  longlong *local_48;
  uint local_44;
  ushort *local_40;
  int local_3c;
  char local_35;
  int local_34;
  longlong *local_30;
  longlong *local_2c;
  uint local_28;
  ushort *local_24;
  longlong *local_20;
  byte local_19;
  ushort *local_18;
  uint local_14;
  ushort *local_10;
  ushort local_a;
  ushort *local_8;
  
  puStack_104 = &stack0xfffffffc;
  local_f4 = 0;
  local_f0 = (longlong *)0x0;
  local_ec = (longlong *)0x0;
  local_e8 = (longlong *)0x0;
  local_e4 = (longlong *)0x0;
  local_e0 = (longlong *)0x0;
  local_20 = (longlong *)0x0;
  puStack_108 = &LAB_00416d27;
  uStack_10c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10c;
  local_2c = param_3;
  local_28 = param_2;
  local_24 = param_1;
  if ((param_1 != (ushort *)0x0) && (param_3 != (longlong *)0x0)) {
    puVar11 = (ushort *)0xffffffff;
    local_34 = param_5 + 1;
    local_14 = param_2;
    if (param_2 < 0x7fffffff) {
      local_14 = param_2 * 2;
    }
    plVar10 = (longlong *)(param_7 * 2 + (int)param_3);
    local_18 = param_1;
    if (param_3 < plVar10) {
      do {
        if (*(ushort *)param_3 == 0x25) {
          plVar8 = (longlong *)((int)param_3 + 2);
          if (plVar10 <= plVar8) break;
          if (*(short *)plVar8 == 0x25) {
            if (local_14 == 0) {
              FUN_00415e8c(0,local_2c,param_7);
            }
            *local_18 = *(ushort *)plVar8;
            param_3 = (longlong *)((int)param_3 + 4);
            local_18 = local_18 + 1;
            local_14 = local_14 - 2;
          }
          else {
            local_10 = (ushort *)0xffffffff;
            puVar11 = (ushort *)((int)puVar11 + 1);
            bVar5 = FUN_004125c8((ushort *)plVar8);
            local_30 = plVar8;
            if (bVar5) {
              while ((plVar8 < plVar10 && (bVar5 = FUN_004125c8((ushort *)plVar8), bVar5))) {
                plVar8 = (longlong *)((int)plVar8 + 2);
              }
              if (plVar8 != local_30) {
                uVar6 = (int)plVar8 - (int)local_30 >> 1;
                if ((int)uVar6 < 0) {
                  uVar6 = uVar6 + (((int)plVar8 - (int)local_30 & 1U) != 0);
                }
                FUN_00415d98(local_da,local_30,uVar6);
                FUN_00407278(&local_e0,local_da,0x41);
                bVar5 = FUN_00415b04((ushort *)local_e0,&local_40,extraout_ECX);
                if (!bVar5) {
                  FUN_00415e8c(0,local_2c,param_7);
                }
                if (*(short *)plVar8 == 0x3a) {
                  plVar8 = (longlong *)((int)plVar8 + 2);
                  puVar11 = local_40;
                }
                else {
                  local_10 = local_40;
                }
              }
            }
            else if (*(short *)plVar8 == 0x3a) {
              puVar11 = (ushort *)0x0;
              plVar8 = (longlong *)((int)param_3 + 4);
            }
            local_19 = *(ushort *)plVar8 == 0x2d;
            if ((bool)local_19) {
              plVar8 = (longlong *)((int)plVar8 + 2);
            }
            local_30 = plVar8;
            if (*(short *)plVar8 == 0x2a) {
              local_10 = (ushort *)0xfffffffe;
              plVar8 = (longlong *)((int)plVar8 + 2);
            }
            else {
              bVar5 = FUN_004125c8((ushort *)plVar8);
              if (bVar5) {
                while ((plVar8 < plVar10 && (bVar5 = FUN_004125c8((ushort *)plVar8), bVar5))) {
                  plVar8 = (longlong *)((int)plVar8 + 2);
                }
                if (plVar8 != local_30) {
                  uVar6 = (int)plVar8 - (int)local_30 >> 1;
                  if ((int)uVar6 < 0) {
                    uVar6 = uVar6 + (((int)plVar8 - (int)local_30 & 1U) != 0);
                  }
                  FUN_00415d98(local_da,local_30,uVar6);
                  FUN_00407278(&local_e4,local_da,0x41);
                  bVar5 = FUN_00415b04((ushort *)local_e4,&local_10,extraout_ECX_00);
                  if (!bVar5) {
                    FUN_00415e8c(0,local_2c,param_7);
                  }
                }
              }
            }
            if (*(short *)plVar8 == 0x2e) {
              plVar9 = (longlong *)((int)plVar8 + 2);
              if (plVar10 <= plVar9) break;
              plVar4 = plVar9;
              if (*(ushort *)plVar9 == 0x2a) {
                local_8 = (ushort *)0xfffffffe;
                plVar8 = (longlong *)((int)plVar8 + 4);
              }
              else {
                while ((local_30 = plVar4, plVar9 < plVar10 &&
                       (bVar5 = FUN_004125c8((ushort *)plVar9), bVar5))) {
                  plVar9 = (longlong *)((int)plVar9 + 2);
                  plVar4 = local_30;
                }
                uVar6 = (int)plVar9 - (int)local_30 >> 1;
                if ((int)uVar6 < 0) {
                  uVar6 = uVar6 + (((int)plVar9 - (int)local_30 & 1U) != 0);
                }
                FUN_00415d98(local_da,local_30,uVar6);
                FUN_00407278(&local_e8,local_da,0x41);
                bVar5 = FUN_00415b04((ushort *)local_e8,&local_8,extraout_ECX_01);
                plVar8 = plVar9;
                if (!bVar5) {
                  local_8 = (ushort *)0xffffffff;
                }
              }
            }
            else {
              local_8 = (ushort *)0xffffffff;
            }
            bVar5 = FUN_00412580((ushort *)plVar8);
            if (!bVar5) break;
            if ((ushort)(*(short *)plVar8 - 0x61U) < 0x1a) {
              local_a = *(ushort *)plVar8 ^ 0x20;
            }
            else {
              local_a = *(ushort *)plVar8;
            }
            param_3 = (longlong *)((int)plVar8 + 2);
            uVar7 = extraout_ECX_02;
            if (local_10 == (ushort *)0xfffffffe) {
              if (local_34 <= (int)puVar11) {
                FUN_00415e8c(1,local_2c,param_7);
                uVar7 = extraout_ECX_03;
              }
              cVar1 = *(char *)(param_6 + 4 + (int)puVar11 * 8);
              if ((cVar1 == '\0') || (cVar1 == '\x10')) {
                if (*(char *)(param_6 + 4 + (int)puVar11 * 8) == '\0') {
                  local_10 = *(ushort **)(param_6 + (int)puVar11 * 8);
                }
                else {
                  puVar2 = *(uint **)(param_6 + (int)puVar11 * 8);
                  uVar6 = puVar2[1];
                  if (uVar6 == 0) {
                    if (0x7fffffff < *puVar2) goto LAB_00416638;
LAB_00416620:
                    puVar3 = *(uint **)(param_6 + (int)puVar11 * 8);
                    puVar2 = puVar3 + 1;
                    if (*puVar2 == 0xffffffff) {
                      if (*puVar3 < 0x80000000) goto LAB_00416638;
                    }
                    else if ((int)*puVar2 < -1) goto LAB_00416638;
                  }
                  else {
                    if ((int)uVar6 < 1) goto LAB_00416620;
LAB_00416638:
                    FUN_00415e8c(0,local_2c,param_7);
                    uVar7 = extraout_ECX_04;
                  }
                  local_10 = **(ushort ***)(param_6 + (int)puVar11 * 8);
                }
                if ((int)local_10 < 0) {
                  local_19 = local_19 ^ 1;
                  local_10 = (ushort *)-(int)local_10;
                }
                puVar11 = (ushort *)((int)puVar11 + 1);
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
                uVar7 = extraout_ECX_05;
              }
            }
            if (local_8 == (ushort *)0xfffffffe) {
              if (local_34 <= (int)puVar11) {
                FUN_00415e8c(1,local_2c,param_7);
                uVar7 = extraout_ECX_06;
              }
              cVar1 = *(char *)(param_6 + 4 + (int)puVar11 * 8);
              if ((cVar1 == '\0') || (cVar1 == '\x10')) {
                if (*(char *)(param_6 + 4 + (int)puVar11 * 8) == '\0') {
                  local_8 = *(ushort **)(param_6 + (int)puVar11 * 8);
                }
                else {
                  puVar2 = *(uint **)(param_6 + (int)puVar11 * 8);
                  uVar6 = puVar2[1];
                  if (uVar6 == 0) {
                    if (0x7fffffff < *puVar2) goto LAB_004166e6;
LAB_004166ce:
                    puVar3 = *(uint **)(param_6 + (int)puVar11 * 8);
                    puVar2 = puVar3 + 1;
                    if (*puVar2 == 0xffffffff) {
                      if (*puVar3 < 0x80000000) goto LAB_004166e6;
                    }
                    else if ((int)*puVar2 < -1) goto LAB_004166e6;
                  }
                  else {
                    if ((int)uVar6 < 1) goto LAB_004166ce;
LAB_004166e6:
                    FUN_00415e8c(0,local_2c,param_7);
                    uVar7 = extraout_ECX_07;
                  }
                  local_8 = **(ushort ***)(param_6 + (int)puVar11 * 8);
                }
                puVar11 = (ushort *)((int)puVar11 + 1);
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
                uVar7 = extraout_ECX_08;
              }
            }
            if (local_34 <= (int)puVar11) {
              FUN_00415e8c(1,local_2c,param_7);
              uVar7 = extraout_ECX_09;
            }
            local_48 = *(longlong **)(param_6 + (int)puVar11 * 8);
            local_44 = *(uint *)(param_6 + 4 + (int)puVar11 * 8);
            local_35 = '\0';
            switch(local_44 & 0xff) {
            case 0:
              if ((0x10 < (int)local_8) || (local_8 == (ushort *)0xffffffff)) {
                local_8 = (ushort *)0x0;
              }
              if (local_a == 0x44) {
                FUN_00415718((uint)local_48,&local_20);
              }
              else if (local_a == 0x55) {
                FUN_00415784((uint)local_48,&local_20);
              }
              else if (local_a == 0x58) {
                FUN_00415a78((uint)local_48,0,&local_20);
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              puVar12 = &stack0xfffffffc;
              plVar8 = (longlong *)FUN_004071e4((int)local_20);
              uVar6 = FUN_0041611c(plVar8,-1,-1,(int)puVar12);
              local_35 = (char)uVar6;
              break;
            case 1:
            case 7:
            case 8:
            case 0xe:
              FUN_00415e8c(0,local_2c,param_7);
              break;
            case 2:
            case 9:
              if (local_a == 0x53) {
                if ((char)local_44 == '\x02') {
                  FUN_004071fc(&local_20,(uint)local_48 & 0xff);
                }
                else {
                  FUN_004071fc(&local_20,(uint)local_48 & 0xffff);
                }
                puVar12 = &stack0xfffffffc;
                plVar8 = (longlong *)FUN_004071e4((int)local_20);
                uVar6 = FUN_0041611c(plVar8,(int)local_8,-1,(int)puVar12);
                local_35 = (char)uVar6;
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              break;
            case 3:
            case 0xc:
              local_49 = (char)local_44 != '\x03';
              local_3c = 0;
              if ((local_a == 0x47) || (local_a == 0x45)) {
                if ((ushort *)0x12 < local_8) {
                  local_8 = (ushort *)0xf;
                }
              }
              else if (((ushort *)0x12 < local_8) && (local_8 = (ushort *)0x2, local_a == 0x4d)) {
                local_8 = (ushort *)(uint)*(byte *)((int)param_4 + 5);
              }
              switch(local_a) {
              case 0x45:
                local_3c = FUN_00416da0((undefined2 *)local_da,local_48,local_49,param_4,3,
                                        (int)local_8,1);
                break;
              case 0x46:
                local_3c = FUN_00416da0((undefined2 *)local_da,local_48,local_49,param_4,local_8,
                                        0x12,2);
                break;
              case 0x47:
                local_3c = FUN_00416da0((undefined2 *)local_da,local_48,local_49,param_4,3,
                                        (int)local_8,0);
                break;
              default:
                FUN_00415e8c(0,local_2c,param_7);
                break;
              case 0x4d:
                local_3c = FUN_00416da0((undefined2 *)local_da,local_48,local_49,param_4,local_8,
                                        0x12,4);
                break;
              case 0x4e:
                local_3c = FUN_00416da0((undefined2 *)local_da,local_48,local_49,param_4,local_8,
                                        0x12,3);
              }
              *(undefined2 *)((int)local_da + local_3c * 2) = 0;
              local_8 = (ushort *)0x0;
              uVar6 = FUN_0041611c(local_da,-1,-1,(int)&stack0xfffffffc);
              local_35 = (char)uVar6;
              break;
            case 4:
              if (local_a == 0x53) {
                puVar12 = &stack0xfffffffc;
                FUN_004072c4(&local_f0,(byte *)local_48);
                plVar8 = (longlong *)FUN_004071e4((int)local_f0);
                uVar6 = FUN_0041611c(plVar8,(int)local_8,-1,(int)puVar12);
                local_35 = (char)uVar6;
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              break;
            case 5:
              if (local_a == 0x50) {
                FUN_00415a78((uint)local_48,8,&local_20);
                puVar12 = &stack0xfffffffc;
                plVar8 = (longlong *)FUN_004071e4((int)local_20);
                uVar6 = FUN_0041611c(plVar8,-1,-1,(int)puVar12);
                local_35 = (char)uVar6;
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              break;
            case 6:
              if (local_a == 0x53) {
                puVar12 = &stack0xfffffffc;
                FUN_0040720c(&local_ec,(LPCSTR)local_48);
                plVar8 = (longlong *)FUN_004071e4((int)local_ec);
                uVar6 = FUN_0041611c(plVar8,(int)local_8,-1,(int)puVar12);
                local_35 = (char)uVar6;
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              break;
            case 10:
              if (local_a == 0x53) {
                uVar6 = FUN_0041611c(local_48,(int)local_8,-1,(int)&stack0xfffffffc);
                local_35 = (char)uVar6;
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              break;
            case 0xb:
              if (local_a == 0x53) {
                FUN_00407294(&local_20,(LPCSTR)local_48);
                local_54 = local_20;
                if (local_20 != (longlong *)0x0) {
                  local_54 = *(longlong **)((int)local_20 + -4);
                }
                puVar12 = &stack0xfffffffc;
                plVar8 = (longlong *)FUN_004071e4((int)local_20);
                uVar6 = FUN_0041611c(plVar8,(int)local_8,(int)local_54,(int)puVar12);
                local_35 = (char)uVar6;
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              break;
            case 0xd:
              if (local_a == 0x53) {
                puVar12 = &stack0xfffffffc;
                FUN_0041629c((undefined4 *)local_48,&local_f4);
                plVar8 = (longlong *)FUN_004071e4(local_f4);
                uVar6 = FUN_0041611c(plVar8,(int)local_8,-1,(int)puVar12);
                local_35 = (char)uVar6;
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              break;
            case 0xf:
              if (local_a == 0x53) {
                local_50 = local_48;
                if (local_48 != (longlong *)0x0) {
                  local_50 = (longlong *)(*(uint *)((int)local_48 + -4) >> 1);
                }
                uVar6 = FUN_0041611c(local_48,(int)local_8,(int)local_50,(int)&stack0xfffffffc);
                local_35 = (char)uVar6;
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              break;
            case 0x10:
              if ((0x20 < (int)local_8) || (local_8 == (ushort *)0xffffffff)) {
                local_8 = (ushort *)0x0;
              }
              if (local_a == 0x44) {
                FUN_00415740(&local_20,local_44,uVar7,*(uint *)local_48,*(uint *)((int)local_48 + 4)
                            );
              }
              else if (local_a == 0x55) {
                FUN_00415798(&local_20,local_44,uVar7,*(uint *)local_48,*(uint *)((int)local_48 + 4)
                            );
              }
              else if (local_a == 0x58) {
                FUN_00415a90(0,&local_20,uVar7,*(uint *)local_48,*(uint *)((int)local_48 + 4));
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
              puVar12 = &stack0xfffffffc;
              plVar8 = (longlong *)FUN_004071e4((int)local_20);
              uVar6 = FUN_0041611c(plVar8,-1,-1,(int)puVar12);
              local_35 = (char)uVar6;
              break;
            case 0x11:
              if (local_a == 0x53) {
                local_58 = local_48;
                if (local_48 != (longlong *)0x0) {
                  local_58 = *(longlong **)((int)local_48 + -4);
                }
                uVar6 = FUN_0041611c(local_48,(int)local_8,(int)local_58,(int)&stack0xfffffffc);
                local_35 = (char)uVar6;
              }
              else {
                FUN_00415e8c(0,local_2c,param_7);
              }
            }
            if (local_35 != '\0') break;
          }
        }
        else {
          if (local_14 == 0) break;
          *local_18 = *(ushort *)param_3;
          param_3 = (longlong *)((int)param_3 + 2);
          local_18 = local_18 + 1;
          local_14 = local_14 - 2;
        }
      } while (param_3 < plVar10);
    }
  }
  *in_FS_OFFSET = uStack_10c;
  puStack_104 = &LAB_00416d2e;
  puStack_108 = (undefined *)0x416d1e;
  FUN_00406b88(&local_f4,6);
  puStack_108 = (undefined *)0x416d26;
  FUN_00406b28((int *)&local_20);
  return;
}



uint FUN_00416d3c(uint param_1,uint param_2,int param_3)

{
  char cVar2;
  uint uVar1;
  char cVar4;
  undefined4 unaff_EBX;
  char *pcVar3;
  undefined *unaff_EDI;
  char *pcVar5;
  char *pcVar6;
  char local_14 [4];
  char *pcStack_10;
  uint uStack_8;
  
  *unaff_EDI = (char)param_1;
  cVar4 = (char)((uint)unaff_EBX >> 8);
  pcVar3 = unaff_EDI + 1;
  if (cVar4 != '\0') {
    param_1 = param_1 & 0xffffff00;
    pcVar3 = unaff_EDI + 2;
    unaff_EDI[1] = '\0';
  }
  if ((char)unaff_EBX == '\0') {
    param_2 = 0;
LAB_00416d5a:
    cVar2 = (char)(param_1 >> 8);
    pcVar5 = pcVar3;
    if (cVar2 == '\0') goto LAB_00416d69;
  }
  else {
    if (-1 < (int)param_2) goto LAB_00416d5a;
    cVar2 = '-';
    param_2 = -param_2;
  }
  *pcVar3 = cVar2;
  pcVar5 = pcVar3 + 1;
  if (cVar4 != '\0') {
    pcVar5 = pcVar3 + 2;
    pcVar3[1] = '\0';
  }
LAB_00416d69:
  pcVar3 = local_14;
  pcStack_10 = pcVar3;
  uStack_8 = param_2;
  do {
    do {
      uVar1 = param_2 / DAT_004281dc;
      *pcVar3 = (char)(param_2 % DAT_004281dc) + '0';
      pcVar3 = pcVar3 + 1;
      param_3 = param_3 + -1;
      param_2 = uVar1;
    } while (uVar1 != 0);
  } while (0 < param_3);
  do {
    pcVar3 = pcVar3 + -1;
    *pcVar5 = *pcVar3;
    pcVar6 = pcVar5 + 1;
    if ((char)((uint)unaff_EBX >> 8) != '\0') {
      pcVar6 = pcVar5 + 2;
      pcVar5[1] = '\0';
    }
    pcVar5 = pcVar6;
  } while (pcVar3 != pcStack_10);
  return uStack_8;
}



void FUN_00416da0(undefined2 *param_1,undefined4 param_2,char param_3,undefined4 *param_4,
                 undefined4 param_5,int param_6,byte param_7)

{
  int iVar1;
  int extraout_ECX;
  uint uVar2;
  undefined2 *puVar3;
  undefined2 *puVar4;
  byte bVar5;
  ushort local_2e [12];
  undefined local_16;
  undefined local_15;
  undefined2 local_14;
  undefined2 local_12;
  undefined4 local_10;
  int local_c;
  undefined2 *local_8;
  
  bVar5 = 0;
  local_c = 0;
  local_10 = *param_4;
  local_12 = *(undefined2 *)((int)param_4 + 0xc2);
  local_14 = *(undefined2 *)(param_4 + 0x30);
  local_15 = *(undefined *)(param_4 + 1);
  local_16 = *(undefined *)((int)param_4 + 0xc6);
  iVar1 = 0x13;
  if (param_3 == '\0') {
    iVar1 = param_6;
    if (param_6 < 2) {
      iVar1 = 2;
    }
    if (0x12 < iVar1) {
      iVar1 = 0x12;
    }
  }
  local_8 = param_1;
  FUN_004170c0(local_2e,param_2,param_3);
  puVar4 = local_8;
  if (local_2e[0] - 0x7fff < 2) {
    FUN_00416ebd();
    puVar3 = (undefined2 *)(&DAT_00416ea6 + local_c + extraout_ECX * 6);
    for (iVar1 = 3; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + (uint)bVar5 * -2 + 1;
      puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
    }
  }
  else {
    uVar2 = (uint)param_7;
    if ((param_7 != 1) && ((4 < param_7 || (iVar1 < (short)local_2e[0])))) {
      uVar2 = 0;
    }
    (*(code *)(*(int *)((int)&PTR_LAB_00416e92 + local_c + uVar2 * 4) + local_c))();
  }
  FUN_004170ba();
  return;
}



char FUN_00416eb2(void)

{
  char cVar1;
  char *unaff_ESI;
  
  cVar1 = *unaff_ESI;
  if (cVar1 == '\0') {
    cVar1 = '0';
  }
  return cVar1;
}



void FUN_00416ebd(void)

{
  int unaff_EBP;
  undefined2 *unaff_EDI;
  
  if (*(char *)(unaff_EBP + -0x28) != '\0') {
    *unaff_EDI = 0x2d;
  }
  return;
}



void FUN_00416f7c(void)

{
  char cVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar2;
  int extraout_ECX;
  uint uVar3;
  uint extraout_EDX;
  int extraout_EDX_00;
  int iVar4;
  int unaff_EBP;
  short *unaff_EDI;
  short *psVar5;
  short *psVar6;
  byte bVar7;
  
  bVar7 = 0;
  uVar3 = *(uint *)(unaff_EBP + 0xc);
  if (0x11 < uVar3) {
    uVar3 = 0x12;
  }
  iVar2 = (int)*(short *)(unaff_EBP + -0x2a);
  if (iVar2 < 1) {
    psVar5 = unaff_EDI + 1;
    *unaff_EDI = 0x30;
  }
  else {
    iVar4 = 0;
    if (*(char *)(unaff_EBP + 0x14) != '\x02') {
      iVar4 = (byte)((ushort)(*(short *)(unaff_EBP + -0x2a) - 1U) % 3) + 1;
    }
    while( true ) {
      cVar1 = FUN_00416eb2();
      psVar5 = unaff_EDI + (uint)bVar7 * -2 + 1;
      *unaff_EDI = (short)CONCAT31(extraout_var,cVar1);
      iVar2 = extraout_ECX + -1;
      uVar3 = extraout_EDX;
      if (iVar2 == 0) break;
      iVar4 = iVar4 + -1;
      unaff_EDI = psVar5;
      if ((iVar4 == 0) && (*(short *)(unaff_EBP + -0x10) != 0)) {
        unaff_EDI = psVar5 + (uint)bVar7 * -2 + 1;
        *psVar5 = *(short *)(unaff_EBP + -0x10);
        iVar4 = 3;
      }
    }
  }
  if (uVar3 != 0) {
    psVar6 = psVar5;
    if (*(short *)(unaff_EBP + -0xe) != 0) {
      psVar6 = psVar5 + (uint)bVar7 * -2 + 1;
      *psVar5 = *(short *)(unaff_EBP + -0xe);
    }
    for (; iVar2 != 0; iVar2 = iVar2 + 1) {
      *psVar6 = 0x30;
      uVar3 = uVar3 - 1;
      if (uVar3 == 0) {
        return;
      }
      psVar6 = psVar6 + (uint)bVar7 * -2 + 1;
    }
    do {
      cVar1 = FUN_00416eb2();
      *psVar6 = (short)CONCAT31(extraout_var_00,cVar1);
      psVar6 = psVar6 + (uint)bVar7 * -2 + 1;
    } while (extraout_EDX_00 != 1);
  }
  return;
}



void FUN_00417046(void)

{
  int iVar1;
  int unaff_EBP;
  undefined2 *puVar2;
  undefined2 *unaff_EDI;
  
  puVar2 = *(undefined2 **)(unaff_EBP + -0xc);
  if (puVar2 != (undefined2 *)0x0) {
    iVar1 = *(int *)(puVar2 + -2);
    for (; iVar1 != 0; iVar1 = iVar1 + -1) {
      *unaff_EDI = *puVar2;
      puVar2 = puVar2 + 1;
      unaff_EDI = unaff_EDI + 1;
    }
  }
  return;
}



void FUN_004170ba(void)

{
  return;
}



void FUN_004170c0(undefined4 param_1,undefined4 param_2,char param_3)

{
  if (param_3 != '\0') {
    FUN_0041720f();
    FUN_004172e3();
    return;
  }
  FUN_004170ed();
  FUN_004172e3();
  return;
}



void FUN_004170ed(void)

{
  char *pcVar1;
  unkbyte10 Var2;
  byte bVar3;
  undefined2 uVar4;
  uint uVar5;
  ushort uVar6;
  int iVar7;
  undefined2 *unaff_EBX;
  int unaff_EBP;
  float10 *unaff_ESI;
  short *psVar8;
  short *psVar9;
  byte bVar10;
  float10 fVar11;
  
  bVar10 = 0;
  uVar6 = *(ushort *)((int)unaff_ESI + 8);
  uVar5 = uVar6 & 0x7fff;
  if ((uVar6 & 0x7fff) == 0) {
LAB_00417118:
    uVar6 = 0;
  }
  else {
    if (uVar5 != 0x7fff) {
      fVar11 = *unaff_ESI;
      *(int *)(unaff_EBP + -8) = ((int)((uVar5 - 0x3fff) * 0x4d10) >> 0x10) + 1;
      fVar11 = ABS(fVar11);
      thunk_FUN_00404aa0();
      fVar11 = ROUND(fVar11);
      *(ushort *)(unaff_EBP + -10) =
           (ushort)(*(float10 *)(&DAT_004281d0 + *(int *)(unaff_EBP + -4)) < fVar11) << 8 |
           (ushort)(*(float10 *)(&DAT_004281d0 + *(int *)(unaff_EBP + -4)) == fVar11) << 0xe;
      if ((*(ushort *)(unaff_EBP + -10) & 0x4100) != 0) {
        fVar11 = fVar11 / (float10)*(int *)((int)&DAT_004281dc + *(int *)(unaff_EBP + -4));
        *(int *)(unaff_EBP + -8) = *(int *)(unaff_EBP + -8) + 1;
      }
      Var2 = convert_bcd(fVar11);
      *(unkbyte10 *)(unaff_EBP + -0x14) = Var2;
      iVar7 = 9;
      psVar8 = (short *)((int)unaff_EBX + 3);
      do {
        bVar3 = *(byte *)(iVar7 + -0x15 + unaff_EBP);
        psVar9 = psVar8 + (uint)bVar10 * -2 + 1;
        *psVar8 = (CONCAT11(bVar3,bVar3 >> 4) & 0xfff) + 0x3030;
        iVar7 = iVar7 + -1;
        psVar8 = psVar9;
      } while (iVar7 != 0);
      *(undefined *)psVar9 = 0;
      uVar5 = *(int *)(unaff_EBP + -8) + *(int *)(unaff_EBP + 8);
      if ((int)uVar5 < 0) {
        uVar5 = 0;
        goto LAB_00417118;
      }
      if (*(uint *)(unaff_EBP + 0xc) <= uVar5) {
        uVar5 = *(uint *)(unaff_EBP + 0xc);
      }
      if (uVar5 < 0x12) {
        if (*(byte *)((int)unaff_EBX + uVar5 + 3) < 0x35) goto LAB_004171da;
        do {
          *(undefined *)((int)unaff_EBX + uVar5 + 3) = 0;
          if ((int)(uVar5 - 1) < 0) {
            *(undefined2 *)((int)unaff_EBX + 3) = 0x31;
            *(int *)(unaff_EBP + -8) = *(int *)(unaff_EBP + -8) + 1;
            break;
          }
          pcVar1 = (char *)((int)unaff_EBX + uVar5 + 2);
          *pcVar1 = *pcVar1 + '\x01';
          iVar7 = uVar5 + 2;
          uVar5 = uVar5 - 1;
        } while (0x39 < *(byte *)((int)unaff_EBX + iVar7));
      }
      else {
        uVar5 = 0x12;
LAB_004171da:
        do {
          *(undefined *)((int)unaff_EBX + uVar5 + 3) = 0;
          if ((int)(uVar5 - 1) < 0) {
            bVar10 = 0;
            goto LAB_004171ed;
          }
          iVar7 = uVar5 + 2;
          uVar5 = uVar5 - 1;
        } while (*(char *)((int)unaff_EBX + iVar7) == '0');
      }
      bVar10 = (byte)((ushort)*(undefined2 *)((int)unaff_ESI + 8) >> 8);
LAB_004171ed:
      uVar4 = (undefined2)*(undefined4 *)(unaff_EBP + -8);
      goto LAB_004171f0;
    }
    if (((*(ushort *)((int)unaff_ESI + 6) & 0x8000) != 0) &&
       ((*(int *)unaff_ESI != 0 || (*(int *)((int)unaff_ESI + 4) != -0x80000000)))) {
      uVar5 = 0x8000;
      goto LAB_00417118;
    }
  }
  bVar10 = (byte)(uVar6 >> 8);
  uVar4 = (undefined2)uVar5;
  *(undefined *)((int)unaff_EBX + 3) = 0;
LAB_004171f0:
  *unaff_EBX = uVar4;
  *(byte *)(unaff_EBX + 1) = bVar10 >> 7;
  return;
}



void FUN_0041720f(void)

{
  unkbyte10 Var1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  byte bVar5;
  short sVar6;
  uint uVar7;
  int iVar8;
  byte bVar9;
  uint uVar10;
  short *unaff_EBX;
  int unaff_EBP;
  uint *unaff_ESI;
  int iVar11;
  short *psVar12;
  short *psVar13;
  bool bVar14;
  float10 fVar15;
  
  uVar7 = *unaff_ESI;
  uVar10 = unaff_ESI[1];
  if ((uVar7 | uVar10) != 0) {
    if ((int)uVar10 < 0) {
      bVar14 = uVar7 != 0;
      uVar7 = -uVar7;
      uVar10 = -(uint)bVar14 - uVar10;
    }
    iVar8 = 0;
    iVar11 = *(int *)(unaff_EBP + 8);
    if (iVar11 < 0) {
      iVar11 = 0;
    }
    if (3 < iVar11) {
      iVar11 = 4;
      uVar3 = uVar7;
      iVar4 = iVar8;
      do {
        iVar8 = iVar4;
        uVar7 = uVar3;
        bVar14 = 0xde0b6b2 < uVar10;
        uVar2 = uVar10 + 0xf21f494d;
        uVar10 = uVar2 - (uVar7 < 0xa7640000);
        uVar3 = uVar7 + 0x589c0000;
        iVar4 = iVar8 + 1;
      } while (bVar14 && (uVar7 < 0xa7640000) <= uVar2);
      uVar10 = uVar10 + 0xde0b6b3 + (uint)(0x589bffff < uVar7 + 0x589c0000);
    }
    *(uint *)(unaff_EBP + -0x20) = uVar7;
    *(uint *)(unaff_EBP + -0x1c) = uVar10;
    fVar15 = (float10)*(longlong *)(unaff_EBP + -0x20);
    if (4 - iVar11 != 0) {
      fVar15 = fVar15 / (float10)*(int *)(*(int *)(unaff_EBP + -4) + 0x4171fb + (4 - iVar11) * 4);
    }
    Var1 = convert_bcd(fVar15);
    *(unkbyte10 *)(unaff_EBP + -0x14) = Var1;
    psVar12 = (short *)((int)unaff_EBX + 3);
    if (iVar8 != 0) {
      psVar13 = unaff_EBX + 2;
      *(char *)psVar12 = (char)iVar8 + '0';
      iVar8 = 9;
      goto LAB_004172a6;
    }
    iVar8 = 9;
    do {
      bVar9 = *(byte *)(iVar8 + -0x15 + unaff_EBP);
      bVar5 = bVar9 >> 4;
      psVar13 = psVar12;
      if (bVar5 != 0) goto LAB_004172af;
      if ((bVar9 & 0xf) != 0) goto LAB_004172b6;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
  }
  sVar6 = 0;
  bVar9 = 0;
  *(undefined *)((int)unaff_EBX + 3) = 0;
LAB_004172dc:
  *unaff_EBX = sVar6;
  *(byte *)(unaff_EBX + 1) = bVar9;
  return;
LAB_004172b6:
  while( true ) {
    psVar13 = (short *)((int)psVar12 + 1);
    *(byte *)psVar12 = (bVar9 & 0xf) + 0x30;
    iVar8 = iVar8 + -1;
    if (iVar8 == 0) break;
LAB_004172a6:
    bVar9 = *(byte *)(iVar8 + -0x15 + unaff_EBP);
    bVar5 = bVar9 >> 4;
LAB_004172af:
    psVar12 = (short *)((int)psVar13 + 1);
    *(byte *)psVar13 = bVar5 + 0x30;
  }
  sVar6 = (short)psVar13 - ((short)unaff_EBX + 3 + (short)iVar11);
  do {
    *(char *)psVar13 = '\0';
    psVar13 = (short *)((int)psVar13 + -1);
  } while (*(char *)psVar13 == '0');
  bVar9 = (byte)(unaff_ESI[1] >> 0x1f);
  goto LAB_004172dc;
}



void FUN_004172e3(void)

{
  return;
}



undefined4 FUN_00417428(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  if ((param_1 & 3) == 0) {
    uVar2 = param_1 & 0xffff;
    uVar1 = 100;
    if ((uVar2 % 100 != 0) || (uVar1 = 400, uVar2 % 400 == 0)) {
      return CONCAT31((int3)(uVar2 / uVar1 >> 8),1);
    }
  }
  return 0;
}



undefined FUN_00417464(ushort param_1,ushort param_2,ushort param_3,double *param_4)

{
  ushort *puVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined local_7;
  
  local_7 = 0;
  uVar2 = FUN_00417428((uint)param_1);
  iVar5 = (uVar2 & 0x7f) * 0x18;
  if ((((param_1 != 0) && (param_1 < 10000)) && (param_2 != 0)) &&
     (((param_2 < 0xd && (param_3 != 0)) &&
      (puVar1 = (ushort *)(iVar5 + 0x427bb2 + (uint)param_2 * 2),
      param_3 < *puVar1 || param_3 == *puVar1)))) {
    iVar3 = param_2 - 1;
    if (0 < iVar3) {
      iVar4 = 1;
      do {
        param_3 = param_3 + *(short *)(iVar5 + 0x427bb2 + iVar4 * 2);
        iVar4 = iVar4 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    iVar3 = param_1 - 1;
    iVar5 = iVar3;
    if (iVar3 < 0) {
      iVar5 = param_1 + 2;
    }
    *param_4 = (double)(((iVar3 * 0x16d + (iVar5 >> 2)) - iVar3 / 100) + iVar3 / 400 + (uint)param_3
                       + -0xa955a);
    local_7 = 1;
  }
  return local_7;
}



void FUN_00417530(ushort param_1,ushort param_2,ushort param_3)

{
  char cVar1;
  double local_14;
  
  cVar1 = FUN_00417464(param_1,param_2,param_3,&local_14);
  if (cVar1 == '\0') {
    FUN_00415134(PTR_PTR_DAT_00428590);
  }
  return;
}



void FUN_004175b0(LCID param_1,LCTYPE param_2,longlong *param_3,longlong **param_4)

{
  int iVar1;
  longlong local_204 [64];
  
  iVar1 = GetLocaleInfoW(param_1,param_2,(LPWSTR)local_204,0x100);
  if (iVar1 < 1) {
    FUN_00406dfc(param_4,param_3);
  }
  else {
    FUN_00406c80(param_4,local_204,iVar1 + -1);
  }
  return;
}



void FUN_00417d04(LCID param_1,int param_2)

{
  int iVar1;
  longlong **pplVar2;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_2c;
  undefined *puStack_28;
  undefined *puStack_24;
  longlong *local_14;
  longlong *local_10;
  int local_c;
  LCID local_8;
  
  puStack_24 = &stack0xfffffffc;
  local_14 = (longlong *)0x0;
  local_10 = (longlong *)0x0;
  puStack_28 = &LAB_00417daf;
  uStack_2c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_2c;
  iVar3 = 1;
  pplVar2 = (longlong **)(param_2 + 0x84);
  local_c = param_2;
  local_8 = param_1;
  do {
    iVar1 = (iVar3 + 5) % 7;
    FUN_004182fc(local_8,iVar1 + 0x31,iVar3 + -1,&local_10,6,(int)&PTR_PTR_DAT_00428248);
    FUN_00406dfc(pplVar2,local_10);
    FUN_004182fc(local_8,iVar1 + 0x2a,iVar3 + -1,&local_14,6,(int)&PTR_PTR_DAT_00428264);
    FUN_00406dfc(pplVar2 + 7,local_14);
    iVar3 = iVar3 + 1;
    pplVar2 = pplVar2 + 1;
  } while (iVar3 != 8);
  *in_FS_OFFSET = uStack_2c;
  puStack_24 = &LAB_00417db6;
  puStack_28 = (undefined *)0x417dae;
  FUN_00406b88((int *)&local_14,2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00418030(LCID param_1,int param_2)

{
  undefined *puVar1;
  int **ppiVar2;
  ushort *Calendar;
  LCID LVar3;
  undefined4 uVar4;
  uint extraout_ECX;
  undefined4 extraout_EDX;
  int iVar5;
  int iVar6;
  longlong *plVar7;
  undefined4 *in_FS_OFFSET;
  ushort *puVar8;
  CALTYPE CVar9;
  undefined4 uStack_38;
  undefined *puStack_34;
  undefined *puStack_30;
  undefined4 uStack_2c;
  undefined *puStack_28;
  undefined *puStack_24;
  longlong *local_c;
  int local_8;
  
  puStack_24 = &stack0xfffffffc;
  local_c = (longlong *)0x0;
  puStack_28 = &LAB_004182c5;
  uStack_2c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_2c;
  puVar1 = &stack0xfffffffc;
  local_8 = param_2;
  if (*(int *)PTR_DAT_00428504 == 0) {
    puStack_30 = (undefined *)0x418062;
    FUN_004045f4(0x1a);
    puVar1 = puStack_24;
  }
  puStack_24 = puVar1;
  puStack_30 = (undefined *)0x41806c;
  ppiVar2 = FUN_00405aa4(DAT_0042c718);
  puStack_30 = (undefined *)0x418074;
  FUN_00405820((uint *)ppiVar2,0xffffffff);
  puStack_34 = &LAB_004182a8;
  uStack_38 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_38;
  _DAT_0042c710 = (longlong *)0x0;
  puStack_30 = &stack0xfffffffc;
  FUN_004087a4(&DAT_0042c714,(int)&DAT_00417e68,1);
  FUN_004175b0(param_1,0x100b,(longlong *)&DAT_004182e0,&local_c);
  Calendar = FUN_00415aec((ushort *)local_c,(ushort *)0x1,extraout_ECX);
  if ((int)Calendar - 3U < 3) {
    CVar9 = 4;
    puVar8 = Calendar;
    LVar3 = GetThreadLocale();
    EnumCalendarInfoW((CALINFO_ENUMPROCW)&lpCalInfoEnumProc_00417f08,LVar3,(CALID)puVar8,CVar9);
    plVar7 = DAT_0042c714;
    if (DAT_0042c714 != (longlong *)0x0) {
      plVar7 = *(longlong **)((int)DAT_0042c714 + -4);
    }
    if (-1 < (int)plVar7 + -1) {
      iVar5 = 0;
      do {
        *(undefined4 *)((int)DAT_0042c714 + iVar5 * 0x18 + 4) = 0xffffffff;
        iVar5 = iVar5 + 1;
        plVar7 = (longlong *)((int)plVar7 + -1);
      } while (plVar7 != (longlong *)0x0);
    }
    CVar9 = 3;
    LVar3 = GetThreadLocale();
    EnumCalendarInfoW((CALINFO_ENUMPROCW)&lpCalInfoEnumProc_00417fa0,LVar3,(CALID)Calendar,CVar9);
  }
  else if ((int)Calendar - 1U < 2) {
    _DAT_0042c710 = (longlong *)0x1;
    FUN_004087a4(&DAT_0042c714,(int)&DAT_00417e68,1);
    FUN_00406dfc((longlong **)DAT_0042c714,(longlong *)L"B.C.");
    *(undefined4 *)((int)DAT_0042c714 + 4) = 0;
    plVar7 = DAT_0042c714;
    *(undefined4 *)(DAT_0042c714 + 1) = 0xffc00000;
    *(undefined4 *)((int)plVar7 + 0xc) = 0xc1dfffff;
    FUN_00417530(1,1,1);
    uVar4 = FUN_00404804();
    DAT_0042c714[2] = (longlong)(double)CONCAT44(extraout_EDX,uVar4);
    CVar9 = 4;
    puVar8 = Calendar;
    LVar3 = GetThreadLocale();
    EnumCalendarInfoW((CALINFO_ENUMPROCW)&lpCalInfoEnumProc_00417f08,LVar3,(CALID)puVar8,CVar9);
    plVar7 = DAT_0042c714;
    if (DAT_0042c714 != (longlong *)0x0) {
      plVar7 = *(longlong **)((int)DAT_0042c714 + -4);
    }
    iVar5 = (int)plVar7 + -1;
    if (0 < iVar5) {
      iVar6 = 1;
      do {
        *(undefined4 *)((int)DAT_0042c714 + iVar6 * 0x18 + 4) = 0xffffffff;
        iVar6 = iVar6 + 1;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
    CVar9 = 3;
    LVar3 = GetThreadLocale();
    EnumCalendarInfoW((CALINFO_ENUMPROCW)&lpCalInfoEnumProc_00417fa0,LVar3,(CALID)Calendar,CVar9);
  }
  FUN_004087a4((longlong **)(local_8 + 0xbc),(int)&DAT_00414cfc,1);
  plVar7 = DAT_0042c714;
  if (DAT_0042c714 != (longlong *)0x0) {
    plVar7 = *(longlong **)((int)DAT_0042c714 + -4);
  }
  if (-1 < (int)plVar7 + -1) {
    iVar5 = 0;
    do {
      FUN_00407abc(*(int *)(local_8 + 0xbc) + iVar5 * 0x18,(int)(DAT_0042c714 + iVar5 * 3),
                   "\x0e\x18TFormatSettings.TEraInfo\x18");
      iVar5 = iVar5 + 1;
      plVar7 = (longlong *)((int)plVar7 + -1);
    } while (plVar7 != (longlong *)0x0);
  }
  FUN_004088c8((int *)&DAT_0042c714,(int)&DAT_00417e68);
  _DAT_0042c710 = DAT_0042c714;
  if (DAT_0042c714 != (longlong *)0x0) {
    _DAT_0042c710 = *(longlong **)((int)DAT_0042c714 + -4);
  }
  *in_FS_OFFSET = uStack_38;
  puStack_30 = &LAB_004182af;
  puStack_34 = (undefined *)0x4182a7;
  FUN_00405a00(DAT_0042c718);
  return;
}



void FUN_004182fc(LCID param_1,LCTYPE param_2,int param_3,longlong **param_4,undefined4 param_5,
                 int param_6)

{
  FUN_004175b0(param_1,param_2,(longlong *)0x0,param_4);
  if (*param_4 == (longlong *)0x0) {
    FUN_0040ab3c(*(undefined4 *)(param_6 + param_3 * 4),param_4);
  }
  return;
}



void FUN_00418338(int *param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  bool bVar1;
  short *psVar2;
  
  bVar1 = false;
  psVar2 = (short *)FUN_004071e4(*param_1);
  if (psVar2 != (short *)0x0) {
    for (; *psVar2 != 0; psVar2 = psVar2 + 1) {
      if (*psVar2 == 0x27) {
        bVar1 = (bool)(bVar1 ^ 1);
      }
      if ((*psVar2 == *(short *)(param_4 + 0xc)) && (!bVar1)) {
        *psVar2 = 0x2f;
      }
    }
  }
  return;
}



void FUN_0041837c(LCID param_1,LCTYPE param_2,longlong *param_3,longlong **param_4)

{
  ushort uVar1;
  short sVar2;
  bool bVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  uint extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 extraout_ECX_05;
  undefined4 extraout_ECX_06;
  undefined4 extraout_ECX_07;
  undefined4 uVar7;
  int extraout_EDX;
  int extraout_EDX_00;
  int extraout_EDX_01;
  int extraout_EDX_02;
  int extraout_EDX_03;
  int extraout_EDX_04;
  int extraout_EDX_05;
  int extraout_EDX_06;
  longlong *plVar8;
  int iVar9;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_38;
  undefined *puStack_34;
  undefined *puStack_30;
  longlong *local_20;
  longlong *local_1c;
  longlong *local_18;
  int local_14;
  int local_10;
  longlong *local_c;
  longlong *local_8;
  
  puStack_30 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  local_c = (longlong *)0x0;
  local_14 = 0;
  local_18 = (longlong *)0x0;
  local_1c = (longlong *)0x0;
  local_20 = (longlong *)0x0;
  puStack_34 = &LAB_00418623;
  uStack_38 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_38;
  local_10 = 1;
  FUN_00406b28((int *)param_4);
  FUN_004175b0(param_1,param_2,param_3,&local_8);
  FUN_004175b0(param_1,0x1009,(longlong *)&DAT_00418640,&local_18);
  puVar4 = FUN_00415aec((ushort *)local_18,(ushort *)0x1,extraout_ECX);
  uVar7 = extraout_ECX_00;
  iVar6 = extraout_EDX;
  if ((int)puVar4 - 3U < 3) {
    while( true ) {
      plVar8 = local_8;
      if (local_8 != (longlong *)0x0) {
        plVar8 = *(longlong **)((int)local_8 + -4);
      }
      if ((int)plVar8 < local_10) break;
      uVar1 = *(ushort *)((int)local_8 + local_10 * 2 + -2);
      if ((0xd7ff < uVar1) && (uVar1 < 0xe000)) {
        uVar5 = FUN_00419d6c((int)local_8,local_10);
        local_14 = (int)uVar5 >> 1;
        if (local_14 < 0) {
          local_14 = local_14 + (uint)((uVar5 & 1) != 0);
        }
        uVar7 = *in_FS_OFFSET;
        *in_FS_OFFSET = &stack0xffffffbc;
        FUN_00406b28((int *)&local_c);
        FUN_004074e0((int)local_8,local_10,local_14,&local_c);
        FUN_00407350(param_4,local_c);
        *in_FS_OFFSET = uVar7;
        FUN_00406b28((int *)&local_c);
        return;
      }
      iVar9 = local_10 + -1;
      iVar6 = FUN_0041b174((int)local_8,iVar9,(int)&DAT_00418650,'\x01',2,0);
      if (iVar6 == 0) {
        FUN_00407350(param_4,(longlong *)&DAT_00418664);
        local_10 = local_10 + 1;
        uVar7 = extraout_ECX_03;
        iVar6 = extraout_EDX_02;
      }
      else {
        iVar6 = FUN_0041b174((int)local_8,iVar9,(int)L"yyyy",'\x01',4,0);
        if (iVar6 == 0) {
          FUN_00407350(param_4,(longlong *)L"eeee");
          local_10 = local_10 + 3;
          uVar7 = extraout_ECX_04;
          iVar6 = extraout_EDX_03;
        }
        else {
          iVar6 = FUN_0041b174((int)local_8,iVar9,(int)&DAT_004186a8,'\x01',2,0);
          if (iVar6 == 0) {
            FUN_00407350(param_4,(longlong *)&DAT_004186bc);
            local_10 = local_10 + 1;
            uVar7 = extraout_ECX_05;
            iVar6 = extraout_EDX_04;
          }
          else {
            sVar2 = *(short *)((int)local_8 + local_10 * 2 + -2);
            if ((sVar2 == 0x59) || (sVar2 == 0x79)) {
              FUN_00407350(param_4,(longlong *)&LAB_004186d0);
              uVar7 = extraout_ECX_06;
              iVar6 = extraout_EDX_05;
            }
            else {
              FUN_004071fc(&local_20,(uint)*(ushort *)((int)local_8 + local_10 * 2 + -2));
              FUN_00407350(param_4,local_20);
              uVar7 = extraout_ECX_07;
              iVar6 = extraout_EDX_06;
            }
          }
        }
      }
      local_10 = local_10 + 1;
    }
    FUN_00418338((int *)param_4,iVar6,uVar7,(int)&stack0xfffffffc);
  }
  else {
    if ((DAT_0042c604 == 4) || (DAT_0042c604 - 0x11U < 2)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    if (bVar3) {
      while( true ) {
        plVar8 = local_8;
        if (local_8 != (longlong *)0x0) {
          plVar8 = *(longlong **)((int)local_8 + -4);
        }
        if ((int)plVar8 < local_10) break;
        uVar1 = *(ushort *)((int)local_8 + local_10 * 2 + -2);
        iVar6 = local_10;
        if ((uVar1 != 0x47) && (uVar1 != 0x67)) {
          FUN_004071fc(&local_1c,(uint)uVar1);
          FUN_00407350(param_4,local_1c);
          uVar7 = extraout_ECX_01;
          iVar6 = extraout_EDX_00;
        }
        local_10 = local_10 + 1;
      }
    }
    else {
      FUN_00406dfc(param_4,local_8);
      uVar7 = extraout_ECX_02;
      iVar6 = extraout_EDX_01;
    }
    FUN_00418338((int *)param_4,iVar6,uVar7,(int)&stack0xfffffffc);
  }
  *in_FS_OFFSET = uStack_38;
  puStack_30 = &LAB_0041862a;
  puStack_34 = (undefined *)0x418615;
  FUN_00406b88((int *)&local_20,3);
  puStack_34 = (undefined *)0x418622;
  FUN_00406b88((int *)&local_c,2);
  return;
}



int FUN_00418754(int param_1)

{
  if (param_1 != 0) {
    param_1 = param_1 + -0x1000;
  }
  return param_1;
}



void FUN_00418760(int *param_1,LPCVOID param_2,ushort *param_3,uint param_4)

{
  DWORD DVar1;
  int iVar2;
  undefined4 uVar3;
  HINSTANCE hInstance;
  undefined4 *in_FS_OFFSET;
  UINT uID;
  longlong *lpBuffer;
  undefined4 uStack_680;
  undefined *puStack_67c;
  undefined *puStack_678;
  longlong *local_668;
  longlong *local_664;
  undefined local_660;
  longlong *local_65c;
  undefined local_658;
  int local_654;
  undefined local_650;
  undefined *local_64c;
  undefined local_648;
  undefined *local_644;
  undefined local_640;
  _MEMORY_BASIC_INFORMATION local_63c;
  longlong local_620 [64];
  WCHAR local_420 [261];
  longlong local_216 [65];
  int local_c;
  ushort *local_8;
  
  puStack_678 = &stack0xfffffffc;
  local_668 = (longlong *)0x0;
  puStack_67c = &LAB_0041890c;
  uStack_680 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_680;
  local_8 = param_3;
  VirtualQuery(param_2,&local_63c,0x1c);
  if (local_63c.State == 0x1000) {
    DVar1 = GetModuleFileNameW((HMODULE)local_63c.AllocationBase,local_420,0x105);
    if (DVar1 != 0) {
      local_c = (int)param_2 - (int)local_63c.AllocationBase;
      goto LAB_004187ec;
    }
  }
  GetModuleFileNameW(DAT_0042c584,local_420,0x105);
  local_c = FUN_00418754((int)param_2);
LAB_004187ec:
  iVar2 = FUN_00419eac(local_420,0x5c);
  FUN_00415d98(local_216,(longlong *)(iVar2 + 2),0x104);
  local_64c = &DAT_00418920;
  local_644 = &DAT_00418920;
  uVar3 = FUN_00405108(param_1,(int)&PTR_LAB_00412e58);
  if ((char)uVar3 != '\0') {
    local_64c = (undefined *)FUN_004071e4(param_1[1]);
    iVar2 = FUN_00406f00((int)local_64c);
    if ((iVar2 != 0) && (*(short *)(local_64c + iVar2 * 2 + -2) != 0x2e)) {
      local_644 = &DAT_00418924;
    }
  }
  iVar2 = 0x100;
  lpBuffer = local_620;
  uID = *(UINT *)(PTR_PTR_DAT_00428604 + 4);
  hInstance = (HINSTANCE)FUN_00408990((int)DAT_0042c584);
  LoadStringW(hInstance,uID,(LPWSTR)lpBuffer,iVar2);
  FUN_00404c5c(*param_1,&local_668);
  local_664 = local_668;
  local_660 = 0x11;
  local_65c = local_216;
  local_658 = 10;
  local_654 = local_c;
  local_650 = 5;
  local_648 = 10;
  local_640 = 10;
  FUN_00415f08(local_8,param_4,local_620,4,(int)&local_664);
  FUN_00406f00((int)local_8);
  *in_FS_OFFSET = uStack_680;
  puStack_678 = &LAB_00418913;
  puStack_67c = (undefined *)0x41890b;
  FUN_00406b28((int *)&local_668);
  return;
}



void FUN_00418958(int *param_1,LPCVOID param_2)

{
  int iVar1;
  DWORD DVar2;
  HANDLE pvVar3;
  HINSTANCE hInstance;
  undefined4 *in_FS_OFFSET;
  longlong *lpBuffer;
  LPCVOID *lpBuffer_00;
  UINT uID;
  DWORD *pDVar4;
  WCHAR *lpBuffer_01;
  LPOVERLAPPED p_Var5;
  undefined4 uVar6;
  undefined4 uStack_8a0;
  undefined *puStack_89c;
  undefined *puStack_898;
  WCHAR local_88c [1024];
  WCHAR local_8c [64];
  DWORD local_c;
  longlong *local_8;
  
  puStack_898 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_89c = &LAB_00418a7d;
  uStack_8a0 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_8a0;
  uVar6 = 0x400;
  iVar1 = FUN_00418760(param_1,param_2,(ushort *)local_88c,0x400);
  if (*PTR_DAT_004285ac == '\0') {
    iVar1 = 0x40;
    lpBuffer_01 = local_8c;
    uID = *(UINT *)(PTR_PTR_DAT_0042848c + 4);
    hInstance = (HINSTANCE)FUN_00408990(DAT_0042c584);
    LoadStringW(hInstance,uID,lpBuffer_01,iVar1);
    MessageBoxW((HWND)0x0,local_88c,local_8c,0x2010);
  }
  else {
    FUN_00404894(PTR_DAT_004284b4);
    FUN_0040460c();
    DVar2 = WideCharToMultiByte(1,0,local_88c,iVar1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
    FUN_004087a4(&local_8,(int)&DAT_0041892c,1);
    WideCharToMultiByte(1,0,local_88c,iVar1,(LPSTR)local_8,DVar2,(LPCSTR)0x0,(LPBOOL)0x0);
    p_Var5 = (LPOVERLAPPED)0x0;
    pDVar4 = &local_c;
    lpBuffer = local_8;
    pvVar3 = GetStdHandle(0xfffffff4);
    WriteFile(pvVar3,lpBuffer,DVar2,pDVar4,p_Var5);
    p_Var5 = (LPOVERLAPPED)0x0;
    pDVar4 = &local_c;
    DVar2 = 2;
    lpBuffer_00 = &lpBuffer_00418a98;
    pvVar3 = GetStdHandle(0xfffffff4);
    WriteFile(pvVar3,lpBuffer_00,DVar2,pDVar4,p_Var5);
  }
  *in_FS_OFFSET = uVar6;
  puStack_89c = &LAB_00418a84;
  uStack_8a0 = 0x418a7c;
  FUN_004088c8((int *)&local_8,(int)&DAT_0041892c);
  return;
}



void FUN_00418a9c(void)

{
  int *piVar1;
  
  piVar1 = FUN_00418bfc((int *)&PTR_LAB_004135c0,'\x01',PTR_PTR_DAT_0042850c);
  FUN_004062cc((int)piVar1);
  return;
}



void FUN_00418abc(void)

{
  FUN_004062cc(DAT_0042c71c);
  return;
}



int * FUN_00418ac8(int *param_1,char param_2,longlong *param_3)

{
  longlong *extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00405424((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00406dfc((longlong **)(param_1 + 1),param_3);
  if (param_2 != '\0') {
    FUN_0040547c(param_1);
    *in_FS_OFFSET = in_stack_ffffffe4;
  }
  return param_1;
}



void FUN_00418b04(int param_1,char param_2,longlong *param_3,int param_4,int param_5)

{
  longlong *extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  undefined4 in_stack_ffffffdc;
  undefined4 in_stack_ffffffe0;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  longlong *local_8;
  
  local_8 = (longlong *)0x0;
  if (param_2 != '\0') {
    puStack_28 = (undefined *)0x418b18;
    param_1 = FUN_00405424(param_1,param_2,param_3,in_stack_ffffffdc,in_stack_ffffffe0,
                           in_stack_ffffffe4,in_stack_ffffffe8);
    param_3 = extraout_ECX;
  }
  puStack_2c = &LAB_00418b5e;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  puStack_28 = &stack0xfffffffc;
  FUN_00415f70(param_3,param_5,param_4,&local_8);
  FUN_00406dfc((longlong **)(param_1 + 4),local_8);
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_00418b65;
  puStack_2c = (undefined *)0x418b5d;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_00418b84(int param_1,char param_2,undefined4 param_3)

{
  undefined4 extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStackY_30;
  undefined *puStackY_2c;
  undefined *puStackY_28;
  undefined4 in_stack_ffffffdc;
  undefined4 in_stack_ffffffe0;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  longlong *local_8;
  
  local_8 = (longlong *)0x0;
  if (param_2 != '\0') {
    puStackY_28 = (undefined *)0x418b98;
    param_1 = FUN_00405424(param_1,param_2,param_3,in_stack_ffffffdc,in_stack_ffffffe0,
                           in_stack_ffffffe4,in_stack_ffffffe8);
    param_3 = extraout_ECX;
  }
  puStackY_2c = &LAB_00418bd7;
  uStackY_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStackY_30;
  puStackY_28 = &stack0xfffffffc;
  FUN_00415c20(param_3,&local_8);
  FUN_00406dfc((longlong **)(param_1 + 4),local_8);
  *in_FS_OFFSET = uStackY_30;
  puStackY_28 = &LAB_00418bde;
  puStackY_2c = (undefined *)0x418bd6;
  FUN_00406b28((int *)&local_8);
  return;
}



int * FUN_00418bfc(int *param_1,char param_2,undefined4 param_3)

{
  undefined4 extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00405424((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_0040ab3c(param_3,(longlong **)(param_1 + 1));
  if (param_2 != '\0') {
    FUN_0040547c(param_1);
    *in_FS_OFFSET = in_stack_ffffffe4;
  }
  return param_1;
}



void FUN_00418ccc(int param_1,char param_2,undefined4 param_3,int param_4,int param_5)

{
  undefined4 extraout_ECX;
  undefined4 *in_FS_OFFSET;
  longlong **pplVar1;
  undefined4 uStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  undefined4 in_stack_ffffffd8;
  undefined4 in_stack_ffffffdc;
  undefined4 in_stack_ffffffe0;
  undefined4 in_stack_ffffffe4;
  longlong *local_c;
  longlong *local_8;
  
  local_8 = (longlong *)0x0;
  local_c = (longlong *)0x0;
  if (param_2 != '\0') {
    puStack_2c = (undefined *)0x418ce2;
    param_1 = FUN_00405424(param_1,param_2,param_3,in_stack_ffffffd8,in_stack_ffffffdc,
                           in_stack_ffffffe0,in_stack_ffffffe4);
    param_3 = extraout_ECX;
  }
  puStack_30 = &LAB_00418d38;
  uStack_34 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_34;
  pplVar1 = &local_8;
  puStack_2c = &stack0xfffffffc;
  FUN_0040ab3c(param_3,&local_c);
  FUN_00415f70(local_c,param_5,param_4,pplVar1);
  FUN_00406dfc((longlong **)(param_1 + 4),local_8);
  *in_FS_OFFSET = uStack_34;
  puStack_2c = &LAB_00418d3f;
  puStack_30 = (undefined *)0x418d37;
  FUN_00406b88((int *)&local_c,2);
  return;
}



int * FUN_00418d60(int *param_1,char param_2,longlong *param_3,int param_4)

{
  longlong *extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe0;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00405424((int)param_1,param_2,param_3,in_stack_ffffffe0,in_stack_ffffffe4,
                                  in_stack_ffffffe8,in_stack_ffffffec);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00406dfc((longlong **)(param_1 + 1),param_3);
  param_1[2] = param_4;
  if (param_2 != '\0') {
    FUN_0040547c(param_1);
    *in_FS_OFFSET = in_stack_ffffffe0;
  }
  return param_1;
}



int * FUN_00418eb0(int *param_1,char param_2,undefined4 param_3,int param_4)

{
  undefined4 extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe0;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00405424((int)param_1,param_2,param_3,in_stack_ffffffe0,in_stack_ffffffe4,
                                  in_stack_ffffffe8,in_stack_ffffffec);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_0040ab3c(param_3,(longlong **)(param_1 + 1));
  param_1[2] = param_4;
  if (param_2 != '\0') {
    FUN_0040547c(param_1);
    *in_FS_OFFSET = in_stack_ffffffe0;
  }
  return param_1;
}



void FUN_004190fc(int param_1)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(char *)(param_1 + 0x14) != '\0') {
    piVar1 = (int *)FUN_0040453c();
    uVar2 = FUN_00405108(piVar1,(int)&PTR_LAB_00412e58);
    if ((char)uVar2 != '\0') {
      uVar2 = FUN_0040455c();
      *(undefined4 *)(param_1 + 0xc) = uVar2;
    }
  }
  return;
}



void FUN_00419124(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x10) = param_2;
  return;
}



void FUN_00419194(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int local_10;
  undefined local_c;
  
  iVar1 = FUN_0040463c();
  for (iVar3 = 0; (iVar3 < 7 && (iVar1 != (&DAT_00428280)[iVar3 * 2])); iVar3 = iVar3 + 1) {
  }
  if (iVar3 < 7) {
    piVar2 = FUN_00418ac8((int *)&PTR_LAB_00413808,'\x01',(longlong *)(&DAT_00428284)[iVar3 * 2]);
  }
  else {
    local_c = 0;
    local_10 = iVar1;
    piVar2 = (int *)FUN_00418ccc((int)&PTR_LAB_00413808,'\x01',PTR_PTR_DAT_00428488,0,&local_10);
  }
  piVar2[6] = iVar1;
  return;
}



undefined4 FUN_00419364(int *param_1)

{
  int iVar1;
  undefined3 uVar3;
  int iVar2;
  
  iVar1 = *param_1;
  uVar3 = (undefined3)((uint)iVar1 >> 8);
  if (iVar1 < -0x3fffff6d) {
    iVar2 = iVar1;
    if (iVar1 == -0x3fffff6e) {
LAB_004193c8:
      return CONCAT31((int3)((uint)iVar2 >> 8),6);
    }
    if (iVar1 < -0x3fffff71) {
      if (iVar1 == -0x3fffff72) {
        return CONCAT31(uVar3,7);
      }
      if (iVar1 == -0x3ffffffb) {
        return 0xb;
      }
      if (iVar1 == -0x3fffff74) {
        return 4;
      }
      iVar2 = iVar1 + 0x3fffff73;
      if (iVar2 == 0) goto LAB_004193d1;
    }
    else {
      iVar2 = iVar1 + 0x3fffff6f;
      if (iVar1 + 0x3fffff71U < 2) goto LAB_004193c8;
      if (iVar2 == 0) {
        return 8;
      }
    }
  }
  else if (iVar1 < -0x3fffff69) {
    if (iVar1 == -0x3fffff6a) {
      return CONCAT31(uVar3,0xc);
    }
    iVar2 = iVar1 + 0x3fffff6d;
    if (iVar2 == 0) {
LAB_004193d1:
      return CONCAT31((int3)((uint)iVar2 >> 8),9);
    }
    if (iVar1 == -0x3fffff6c) {
      return 3;
    }
    iVar2 = iVar1 + 0x3fffff6b;
    if (iVar2 == 0) {
      return 5;
    }
  }
  else {
    if (iVar1 == -0x3fffff03) {
      return 0xe;
    }
    iVar2 = iVar1 + 0x3ffffec6;
    if (iVar2 == 0) {
      return 0xd;
    }
  }
  return CONCAT31((int3)((uint)iVar2 >> 8),0x16);
}



undefined4 FUN_004193e4(int *param_1)

{
  uint uVar1;
  
  uVar1 = FUN_00419364(param_1);
  return *(undefined4 *)
          (PTR_PTR_004284a4 + (uint)(byte)PTR_DAT_004285e0[(uVar1 & 0xff) * 8 + -0x18] * 4);
}



void FUN_00419408(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  undefined4 uVar1;
  DWORD DVar2;
  int *in_FS_OFFSET;
  int iVar3;
  undefined4 *puVar4;
  undefined *puStack_28c;
  undefined *puStack_288;
  undefined *puStack_284;
  longlong *local_278;
  undefined4 local_274;
  undefined local_270;
  longlong *local_26c;
  undefined local_268;
  undefined4 local_264;
  undefined local_260;
  longlong *local_25c;
  longlong *local_258;
  longlong *local_254;
  undefined4 local_250;
  undefined local_24c;
  longlong *local_248;
  undefined local_244;
  longlong *local_240;
  undefined local_23c;
  undefined4 local_238;
  undefined local_234;
  longlong local_22e [65];
  _MEMORY_BASIC_INFORMATION local_24;
  longlong *local_8;
  
  puStack_284 = &stack0xfffffffc;
  local_278 = (longlong *)0x0;
  local_254 = (longlong *)0x0;
  local_25c = (longlong *)0x0;
  local_258 = (longlong *)0x0;
  local_8 = (longlong *)0x0;
  puStack_288 = &LAB_0041960e;
  puStack_28c = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = (int)&puStack_28c;
  iVar3 = *(int *)(*(int *)(param_4 + -4) + 0x14);
  if (iVar3 == 0) {
    FUN_0040ab3c(PTR_PTR_DAT_0042861c,&local_8);
  }
  else if (iVar3 == 1) {
    puStack_284 = &stack0xfffffffc;
    FUN_0040ab3c(PTR_PTR_DAT_0042857c,&local_8);
  }
  else if (iVar3 == 8) {
    puStack_284 = &stack0xfffffffc;
    FUN_0040ab3c(PTR_PTR_DAT_00428470,&local_8);
  }
  else {
    puStack_284 = &stack0xfffffffc;
    FUN_0040ab3c(PTR_PTR_DAT_0042851c,&local_8);
  }
  uVar1 = *(undefined4 *)(*(int *)(param_4 + -4) + 0x18);
  VirtualQuery(*(LPCVOID *)(*(int *)(param_4 + -4) + 0xc),&local_24,0x1c);
  if ((local_24.State == 0x1000) || (local_24.State == 0x10000)) {
    DVar2 = GetModuleFileNameW((HMODULE)local_24.AllocationBase,(LPWSTR)local_22e,0x105);
    if (DVar2 != 0) {
      local_250 = *(undefined4 *)(*(int *)(param_4 + -4) + 0xc);
      local_24c = 5;
      FUN_00407278(&local_258,local_22e,0x105);
      FUN_00415c34((int)local_258,&local_254);
      local_248 = local_254;
      local_244 = 0x11;
      local_240 = local_8;
      local_23c = 0x11;
      local_234 = 5;
      puVar4 = &local_250;
      iVar3 = 3;
      local_238 = uVar1;
      FUN_0040ab3c(PTR_PTR_DAT_004285b8,&local_25c);
      FUN_00418b04((int)&PTR_LAB_00414230,'\x01',local_25c,iVar3,(int)puVar4);
      goto LAB_004195dd;
    }
  }
  local_274 = *(undefined4 *)(*(int *)(param_4 + -4) + 0xc);
  local_270 = 5;
  local_26c = local_8;
  local_268 = 0x11;
  local_260 = 5;
  puVar4 = &local_274;
  iVar3 = 2;
  local_264 = uVar1;
  FUN_0040ab3c(PTR_PTR_DAT_00428584,&local_278);
  FUN_00418b04((int)&PTR_LAB_00414230,'\x01',local_278,iVar3,(int)puVar4);
LAB_004195dd:
  *in_FS_OFFSET = iVar3;
  puStack_28c = &LAB_00419615;
  FUN_00406b28((int *)&local_278);
  FUN_00406b88((int *)&local_25c,3);
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_00419704(int param_1)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x18);
  uVar2 = FUN_00405108(piVar1,(int)&PTR_LAB_00412e58);
  if ((char)uVar2 != '\0') {
    (**(code **)*piVar1)(piVar1,param_1);
  }
  return;
}



void FUN_00419738(void)

{
  DAT_0042c71c = FUN_00418bfc((int *)&DAT_00413760,'\x01',PTR_PTR_DAT_00428490);
  DAT_0042c720 = FUN_00418bfc((int *)&DAT_0041402c,'\x01',PTR_PTR_DAT_00428558);
  *(undefined **)PTR_DAT_00428458 = &LAB_004191f4;
  *(undefined **)PTR_DAT_004284c8 = &LAB_00419728;
  *(undefined ***)PTR_DAT_00428484 = &PTR_LAB_00412e58;
  *(code **)PTR_DAT_004284bc = FUN_004193e4;
  *(undefined **)PTR_DAT_004284cc = &LAB_00419620;
  *(code **)PTR_DAT_004284d8 = FUN_00419704;
  *(undefined **)PTR_DAT_00428574 = &LAB_00419264;
  *(undefined **)PTR_DAT_00428448 = &LAB_0041934c;
  return;
}



void FUN_004197c8(void)

{
  if (DAT_0042c71c != (int *)0x0) {
    *(undefined *)(DAT_0042c71c + 6) = 1;
    (**(code **)(*DAT_0042c71c + -8))();
    DAT_0042c71c = (int *)0x0;
  }
  if (DAT_0042c720 != (int *)0x0) {
    *(undefined *)(DAT_0042c720 + 6) = 1;
    FUN_00404df4(DAT_0042c720);
    DAT_0042c720 = (int *)0x0;
  }
  *(undefined4 *)PTR_DAT_00428458 = 0;
  *(undefined4 *)PTR_DAT_004284c8 = 0;
  *(undefined4 *)PTR_DAT_00428484 = 0;
  *(undefined4 *)PTR_DAT_004284bc = 0;
  *(undefined4 *)PTR_DAT_004284cc = 0;
  *(undefined4 *)PTR_DAT_00428574 = 0;
  return;
}



void FUN_00419858(HANDLE param_1,DWORD param_2)

{
  WaitForSingleObject(param_1,param_2);
  return;
}



void FUN_00419860(int **param_1,int *param_2)

{
  int *piVar1;
  int *piVar2;
  
  do {
    piVar1 = *param_1;
    *param_2 = (int)piVar1;
    LOCK();
    if (piVar1 == *param_1) {
      *param_1 = param_2;
      piVar2 = piVar1;
    }
    else {
      piVar2 = *param_1;
    }
    UNLOCK();
  } while (piVar1 != piVar2);
  return;
}



int ** FUN_00419874(int **param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  
  do {
    ppiVar1 = (int **)*param_1;
    if (ppiVar1 == (int **)0x0) {
      return (int **)0x0;
    }
    LOCK();
    if (ppiVar1 == (int **)*param_1) {
      *param_1 = *ppiVar1;
      ppiVar2 = ppiVar1;
    }
    else {
      ppiVar2 = (int **)*param_1;
    }
    UNLOCK();
  } while (ppiVar1 != ppiVar2);
  return ppiVar1;
}



undefined4
FUN_00419a84(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined4 param_6)

{
  undefined4 in_stack_00000000;
  
  thunk_FUN_0040b40c(param_1,param_2,param_3,&ImgDelayDescr_004310c0,in_stack_00000000);
  LOCK();
  UNLOCK();
  return param_6;
}



void DelayLoad_NetWkstaGetInfo(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_00419a84((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void NetWkstaGetInfo(void)

{
                    // WARNING: Could not recover jumptable at 0x00419aa4. Too many branches
                    // WARNING: Treating indirect jump as call
  NetWkstaGetInfo();
  return;
}



void DelayLoad_NetApiBufferFree(void)

{
  undefined4 in_EAX;
  undefined in_CL;
  undefined in_DL;
  
  FUN_00419a84((char)in_EAX,in_DL,in_CL,in_CL,in_DL,in_EAX);
  return;
}



void NetApiBufferFree(void)

{
                    // WARNING: Could not recover jumptable at 0x00419abc. Too many branches
                    // WARNING: Treating indirect jump as call
  NetApiBufferFree();
  return;
}



// WARNING: Removing unreachable block (ram,0x00419b04)

bool FUN_00419ac4(undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = NetWkstaGetInfo();
  if (iVar1 == 0) {
    *param_1 = uRam0000000c;
    *param_2 = uRam00000010;
  }
  else {
    *param_1 = 0;
    *param_2 = 0;
  }
  return iVar1 == 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00419b14(void)

{
  BOOL BVar1;
  _OSVERSIONINFOW local_114;
  
  _DAT_0042c834 = DAT_0042c6ec;
  _DAT_0042c838 = DAT_0042c6f0;
  _DAT_0042c83c = DAT_0042c6e8;
  local_114.dwOSVersionInfoSize = 0x114;
  BVar1 = GetVersionExW(&local_114);
  if (BVar1 != 0) {
    DAT_0042c830 = local_114.dwPlatformId;
    FUN_00407278((longlong **)&DAT_0042c840,(longlong *)local_114.szCSDVersion,0x80);
  }
  DAT_004282cc = 1;
  return;
}



void FUN_00419b74(void)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_10;
  undefined *puStack_c;
  undefined *puStack_8;
  
  puStack_8 = (undefined *)0x419b84;
  FUN_00405778(DAT_0042c82c,0xffffffff);
  puStack_c = &LAB_00419bb8;
  uStack_10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10;
  if (DAT_004282cc == '\0') {
    puStack_8 = &stack0xfffffffc;
    FUN_00419b14();
  }
  *in_FS_OFFSET = uStack_10;
  puStack_8 = &LAB_00419bbf;
  puStack_c = (undefined *)0x419bb7;
  FUN_00405a00(DAT_0042c82c);
  return;
}



undefined4 FUN_00419bc4(void)

{
  if (DAT_004282cc == '\0') {
    FUN_00419b74();
  }
  return DAT_0042c830;
}



void FUN_00419bec(int param_1,uint *param_2,uint *param_3,uint *param_4)

{
  LPCWSTR pWVar1;
  DWORD dwLen;
  LPVOID lpData;
  BOOL BVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_40;
  DWORD *lpdwHandle;
  undefined4 uStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  uint local_1c;
  LPVOID local_18;
  LPVOID local_14;
  DWORD local_10;
  undefined local_9;
  longlong *local_8;
  
  puStack_2c = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_30 = &LAB_00419cec;
  uStack_34 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_34;
  local_9 = 0;
  FUN_00406e44((int *)&local_8,param_1);
  thunk_FUN_00406f14(&local_8);
  lpdwHandle = &local_10;
  pWVar1 = (LPCWSTR)FUN_004071e4((int)local_8);
  uStack_40 = 0x419c36;
  dwLen = GetFileVersionInfoSizeW(pWVar1,lpdwHandle);
  if (dwLen != 0) {
    lpData = (LPVOID)FUN_004044b8(dwLen);
    uStack_40 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_40;
    local_14 = lpData;
    pWVar1 = (LPCWSTR)FUN_004071e4((int)local_8);
    BVar2 = GetFileVersionInfoW(pWVar1,local_10,dwLen,lpData);
    if (BVar2 != 0) {
      BVar2 = VerQueryValueW(local_14,(LPCWSTR)&lpSubBlock_00419d00,&local_18,&local_1c);
      if (BVar2 != 0) {
        *param_2 = *(uint *)((int)local_18 + 0x10) >> 0x10;
        *param_3 = (uint)*(ushort *)((int)local_18 + 0x10);
        *param_4 = *(uint *)((int)local_18 + 0x14) >> 0x10;
        local_9 = 1;
      }
    }
    *in_FS_OFFSET = uStack_40;
    FUN_004044d4((int)local_14);
    return;
  }
  *in_FS_OFFSET = uStack_34;
  puStack_2c = &LAB_00419cf3;
  puStack_30 = (undefined *)0x419ceb;
  FUN_00406b28((int *)&local_8);
  return;
}



undefined4 FUN_00419d04(int param_1,int param_2)

{
  ushort uVar1;
  undefined4 uVar2;
  uint3 uVar3;
  
  uVar2 = 0;
  uVar1 = *(ushort *)(param_1 + -2 + param_2 * 2);
  if ((0xd7ff < uVar1) && (uVar1 < 0xe000)) {
    uVar1 = *(ushort *)(param_1 + -2 + param_2 * 2);
    uVar3 = (uint3)(byte)(uVar1 >> 8);
    if ((uVar1 < 0xd800) || (0xdbff < uVar1)) {
      uVar2 = CONCAT31(uVar3,2);
    }
    else {
      uVar2 = CONCAT31(uVar3,1);
    }
  }
  return uVar2;
}



undefined4 FUN_00419d3c(ushort *param_1)

{
  if ((((0xd7ff < *param_1) && (*param_1 < 0xdc00)) && (0xdbff < param_1[1])) &&
     (param_1[1] < 0xe000)) {
    return 4;
  }
  return 2;
}



undefined4 FUN_00419d6c(int param_1,int param_2)

{
  ushort uVar1;
  bool bVar2;
  int iVar3;
  undefined4 uVar4;
  
  uVar4 = 2;
  if (param_2 < 1) {
    bVar2 = false;
  }
  else {
    iVar3 = param_1;
    if (param_1 != 0) {
      iVar3 = *(int *)(param_1 + -4);
    }
    bVar2 = param_2 <= iVar3;
  }
  if (!bVar2) {
    FUN_00406a58(L"Assertion failure",
                 L"C:\\Users\\k2kwm\\Desktop\\Inno\\issrc-is-5_5_9\\Projects\\System.SysUtils.pas",
                 0x5f65);
  }
  uVar1 = *(ushort *)(param_1 + -2 + param_2 * 2);
  if ((0xd7ff < uVar1) && (uVar1 < 0xe000)) {
    iVar3 = FUN_004071e4(param_1);
    uVar4 = FUN_00419d3c((ushort *)(iVar3 + param_2 * 2 + -2));
  }
  return uVar4;
}



void FUN_00419ea4(short *param_1,short *param_2)

{
  FUN_00415e20(param_1,param_2);
  return;
}



void FUN_00419eac(short *param_1,short param_2)

{
  FUN_00415df0(param_1,param_2);
  return;
}



void __stdcall Sleep(DWORD dwMilliseconds)

{
                    // WARNING: Could not recover jumptable at 0x0041aa1c. Too many branches
                    // WARNING: Treating indirect jump as call
  Sleep(dwMilliseconds);
  return;
}



void FUN_0041ab44(int **param_1)

{
  int *piVar1;
  
  piVar1 = *param_1;
  *param_1 = (int *)0x0;
  FUN_00404df4(piVar1);
  return;
}



void FUN_0041ae1c(int param_1,int param_2,longlong **param_3)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  longlong *local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_1c = &LAB_0041ae7a;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  FUN_00415a90(8,&local_8,param_3,*(uint *)(*(int *)(param_1 + 4) + 4 + param_2 * 0x10),0);
  FUN_004073a8(param_3,(longlong *)PTR_LAB_00427c04,local_8);
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_0041ae81;
  puStack_1c = (undefined *)0x41ae79;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_0041aeb4(int param_1,int param_2,longlong **param_3)

{
  FUN_00406dfc(param_3,*(longlong **)(*(int *)(param_1 + 4) + param_2 * 0x10));
  return;
}



void FUN_0041b0f0(int param_1,UINT param_2)

{
  LPCWSTR lpLibFileName;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_2c;
  undefined *puStack_28;
  undefined *puStack_24;
  undefined4 uStack_20;
  undefined *puStack_1c;
  
  puStack_24 = &stack0xfffffffc;
  puStack_1c = (undefined *)0x41b0ff;
  SetErrorMode(param_2);
  puStack_1c = &LAB_0041b162;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  puStack_28 = &LAB_0041b144;
  uStack_2c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_2c;
  lpLibFileName = (LPCWSTR)FUN_004071e4(param_1);
  LoadLibraryW(lpLibFileName);
  *in_FS_OFFSET = uStack_2c;
  return;
}



void FUN_0041b174(int param_1,int param_2,int param_3,char param_4,int param_5,int param_6)

{
  FUN_0041b2f0(param_1,param_2,param_3,DAT_0042c600,param_4,param_5,param_6);
  return;
}



void FUN_0041b198(int param_1,int param_2,int param_3,LCID param_4,char param_5,int param_6,
                 int param_7,int param_8)

{
  if (param_5 == '\0') {
    FUN_0041b24c(param_1,param_2,param_3,param_4,0,param_6,param_7,param_8);
  }
  else {
    FUN_0041b24c(param_1,param_2,param_3,param_4,4,param_6,param_7,param_8);
  }
  return;
}



uint FUN_0041b1ec(undefined2 param_1,undefined4 param_2,undefined4 param_3)

{
  byte bVar1;
  undefined4 uVar2;
  ushort uVar3;
  uint *puVar4;
  uint uVar5;
  bool bVar6;
  byte abStack_1010 [4096];
  undefined4 local_10;
  
  local_10 = CONCAT22((short)((uint)param_3 >> 0x10),param_1);
  uVar5 = 0;
  uVar3 = 0;
  puVar4 = &DAT_004282d4;
  do {
    bVar1 = (byte)uVar3;
    bVar6 = bVar1 < 0xf;
    if (bVar1 < 0x10) {
      bVar6 = (*(byte *)((int)&local_10 + ((int)(short)(uVar3 & 0x7f) >> 3)) >> (uVar3 & 7) & 1) !=
              0;
    }
    if (bVar6) {
      if (bVar1 == 0) {
        uVar2 = FUN_0041b480(6,0);
        if ((char)uVar2 == '\0') goto LAB_0041b23b;
      }
      if (bVar1 == 8) {
        uVar2 = FUN_0041b480(6,1);
        if ((char)uVar2 == '\0') goto LAB_0041b23b;
      }
      uVar5 = uVar5 | *puVar4;
    }
LAB_0041b23b:
    uVar3 = uVar3 + 1;
    puVar4 = puVar4 + 1;
    if ((char)uVar3 == '\n') {
      return uVar5;
    }
  } while( true );
}



int FUN_0041b24c(int param_1,int param_2,int param_3,LCID param_4,undefined2 param_5,int param_6,
                int param_7,int param_8)

{
  int iVar1;
  uint dwCmpFlags;
  bool bVar2;
  
  iVar1 = param_1;
  if (param_1 != 0) {
    iVar1 = *(int *)(param_1 + -4);
  }
  if (iVar1 == 0) {
    bVar2 = true;
  }
  else {
    iVar1 = param_3;
    if (param_3 != 0) {
      iVar1 = *(int *)(param_3 + -4);
    }
    bVar2 = iVar1 == 0;
  }
  if (bVar2) {
    if (param_1 != 0) {
      param_1 = *(int *)(param_1 + -4);
    }
    if (param_1 < 1) {
      if (param_3 != 0) {
        param_3 = *(int *)(param_3 + -4);
      }
      if (param_3 < 1) {
        iVar1 = 0;
      }
      else {
        iVar1 = -1;
      }
    }
    else {
      iVar1 = 1;
    }
  }
  else {
    dwCmpFlags = FUN_0041b1ec(param_5,param_1,param_3);
    iVar1 = CompareStringW(param_4,dwCmpFlags,(PCNZWCH)(param_1 + param_2 * 2),param_7,
                           (PCNZWCH)(param_3 + param_8 * 2),param_6);
    iVar1 = iVar1 + -2;
  }
  return iVar1;
}



void FUN_0041b2f0(int param_1,int param_2,int param_3,LCID param_4,char param_5,int param_6,
                 int param_7)

{
  FUN_0041b198(param_1,param_2,param_3,param_4,param_5,param_6,param_6,param_7);
  return;
}



void FUN_0041b314(longlong *param_1,int param_2,longlong **param_3)

{
  longlong *plVar1;
  
  FUN_004072d0(param_3,param_2 + 1);
  plVar1 = (longlong *)FUN_004071e4((int)*param_3);
  FUN_0040465c(param_1,plVar1,(param_2 + 1) * 2);
  return;
}



int FUN_0041b344(int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *param_1;
  if (iVar1 != 0) {
    iVar1 = *(int *)(iVar1 + -4);
  }
  do {
    do {
      iVar1 = iVar1 + -1;
      if (iVar1 < 0) {
        return -1;
      }
      iVar2 = param_2;
      if (param_2 != 0) {
        iVar2 = *(int *)(param_2 + -4);
      }
    } while (iVar2 + -1 < 0);
    iVar3 = 0;
    do {
      if (*(short *)(param_2 + iVar3 * 2) == *(short *)(*param_1 + iVar1 * 2)) {
        return iVar1;
      }
      iVar3 = iVar3 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  } while( true );
}



bool FUN_0041b424(void)

{
  BOOL BVar1;
  undefined4 extraout_EDX;
  _OSVERSIONINFOEXW local_128;
  undefined4 local_c;
  
  FUN_004048f8((double *)&local_128,0x11c,0);
  local_128.wProductType = '\x01';
  local_c = VerSetConditionMask();
  BVar1 = VerifyVersionInfoW(&local_128,0x80,(DWORDLONG)CONCAT44(extraout_EDX,local_c));
  return BVar1 == 0;
}



undefined4 FUN_0041b480(int param_1,int param_2)

{
  if ((DAT_0042c6ec <= param_1) && ((param_1 != DAT_0042c6ec || (DAT_0042c6f0 < param_2)))) {
    return 0;
  }
  return CONCAT31((int3)((uint)param_1 >> 8),1);
}



undefined4 FUN_0041b850(uint *param_1,uint *param_2)

{
  uint uVar1;
  bool bVar2;
  
  uVar1 = param_1[1];
  bVar2 = param_2[1] <= uVar1;
  if (bVar2 && uVar1 != param_2[1]) {
    return 1;
  }
  if (bVar2) {
    uVar1 = *param_1;
    if (*param_2 <= uVar1 && uVar1 != *param_2) {
      return 1;
    }
    if (*param_2 <= uVar1) {
      return 0;
    }
  }
  return 0xffffffff;
}



bool FUN_0041b870(uint *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *param_1;
  *param_1 = *param_1 + param_2;
  uVar2 = param_1[1];
  param_1[1] = uVar2 + CARRY4(uVar1,param_2);
  return !CARRY4(uVar2,(uint)CARRY4(uVar1,param_2));
}



void FUN_0041b87c(longlong *param_1,longlong **param_2)

{
  short *psVar1;
  undefined4 uVar2;
  
  if (param_1 != (longlong *)0x0) {
    psVar1 = (short *)FUN_0041bb98((uint)param_1);
    uVar2 = FUN_0041b8d0(*psVar1);
    if ((char)uVar2 == '\0') {
      FUN_004073a8(param_2,param_1,(longlong *)&DAT_0041b8c4);
      return;
    }
  }
  FUN_00406dfc(param_2,param_1);
  return;
}



undefined4 FUN_0041b8c8(void)

{
  return 1;
}



undefined4 FUN_0041b8d0(short param_1)

{
  undefined2 in_register_00000002;
  
  if ((param_1 != 0x5c) && (param_1 != 0x2f)) {
    return 0;
  }
  return CONCAT31((int3)(CONCAT22(in_register_00000002,param_1) >> 8),1);
}



void FUN_0041b8e4(longlong *param_1,longlong *param_2,longlong **param_3)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  longlong *local_c;
  longlong **local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_c = (longlong *)0x0;
  puStack_20 = &LAB_0041b958;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  local_8 = param_3;
  iVar1 = FUN_0041bb28((short *)param_1);
  if (iVar1 == 0) {
    FUN_004073a8(local_8,param_1,param_2);
  }
  else {
    FUN_004074e0((int)param_1,1,iVar1 + -1,&local_c);
    FUN_004073a8(local_8,local_c,param_2);
  }
  *in_FS_OFFSET = uStack_24;
  puStack_1c = &LAB_0041b95f;
  puStack_20 = (undefined *)0x41b957;
  FUN_00406b28((int *)&local_c);
  return;
}



int FUN_0041b968(short *param_1,char param_2)

{
  short *psVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  psVar1 = param_1;
  if (param_1 != (short *)0x0) {
    psVar1 = *(short **)(param_1 + -2);
  }
  if ((((int)psVar1 < 2) || (uVar2 = FUN_0041b8d0(*param_1), (char)uVar2 == '\0')) ||
     (uVar2 = FUN_0041b8d0(param_1[1]), (char)uVar2 == '\0')) {
    if (((int)psVar1 < 1) || (uVar2 = FUN_0041b8d0(*param_1), (char)uVar2 == '\0')) {
      if (0 < (int)psVar1) {
        iVar4 = FUN_0041b8c8();
        iVar5 = iVar4 + 1;
        if ((iVar5 <= (int)psVar1) && (param_1[iVar4] == 0x3a)) {
          if (param_2 == '\0') {
            return iVar5;
          }
          if ((int)psVar1 <= iVar5) {
            return iVar5;
          }
          uVar2 = FUN_0041b8d0(param_1[iVar5]);
          if ((char)uVar2 == '\0') {
            return iVar5;
          }
          return iVar4 + 2;
        }
      }
      iVar4 = 0;
    }
    else if (param_2 == '\0') {
      iVar4 = 0;
    }
    else {
      iVar4 = 1;
    }
  }
  else {
    iVar4 = 3;
    iVar5 = 0;
    if (2 < (int)psVar1) {
      do {
        uVar2 = FUN_0041b8d0(param_1[iVar4 + -1]);
        if ((char)uVar2 == '\0') {
          iVar3 = FUN_0041b8c8();
          iVar4 = iVar4 + iVar3;
        }
        else {
          iVar5 = iVar5 + 1;
          iVar3 = iVar4;
          if (1 < iVar5) break;
          do {
            iVar4 = iVar3 + 1;
            if ((int)psVar1 < iVar4) break;
            uVar2 = FUN_0041b8d0(param_1[iVar3]);
            iVar3 = iVar4;
          } while ((char)uVar2 != '\0');
        }
      } while (iVar4 <= (int)psVar1);
    }
    iVar4 = iVar4 + -1;
  }
  return iVar4;
}



int FUN_0041ba50(short *param_1,char param_2)

{
  int iVar1;
  short *psVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  
  iVar1 = FUN_0041b968(param_1,'\x01');
  psVar2 = param_1;
  if (param_1 != (short *)0x0) {
    psVar2 = *(short **)(param_1 + -2);
  }
  iVar5 = iVar1 + 1;
  iVar4 = iVar1;
  while (iVar5 <= (int)psVar2) {
    uVar3 = FUN_0041b8d0(param_1[iVar5 + -1]);
    if ((char)uVar3 == '\0') {
      iVar4 = FUN_0041b8c8();
      iVar5 = iVar5 + iVar4;
      iVar4 = iVar5 + -1;
    }
    else {
      iVar1 = iVar4;
      if (param_2 != '\0') {
        iVar1 = iVar5;
      }
      iVar5 = iVar5 + 1;
    }
  }
  return iVar1;
}



void FUN_0041bac0(undefined4 param_1,longlong **param_2)

{
  LPWSTR pWVar1;
  LPCWSTR lpFileName;
  longlong *in_stack_00000ff0;
  DWORD DVar2;
  longlong *lpBuffer;
  LPWSTR *lpFilePart;
  longlong local_100c [511];
  LPWSTR pWStack_10;
  
  pWVar1 = (LPWSTR)0x2;
  do {
    pWStack_10 = pWVar1;
    lpFilePart = &pWStack_10;
    pWVar1 = (LPWSTR)((int)pWStack_10 + -1);
  } while ((LPWSTR)((int)pWStack_10 + -1) != (LPWSTR)0x0);
  lpBuffer = local_100c;
  DVar2 = 0x1000;
  lpFileName = (LPCWSTR)FUN_004071e4((int)in_stack_00000ff0);
  DVar2 = GetFullPathNameW(lpFileName,DVar2,(LPWSTR)lpBuffer,lpFilePart);
  if (((int)DVar2 < 1) || (0xfff < (int)DVar2)) {
    FUN_00406dfc(param_2,in_stack_00000ff0);
  }
  else {
    FUN_00406c80(param_2,local_100c,DVar2);
  }
  return;
}



int FUN_0041bb28(short *param_1)

{
  int iVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  
  psVar2 = param_1;
  if (param_1 != (short *)0x0) {
    psVar2 = *(short **)(param_1 + -2);
  }
  iVar3 = FUN_0041ba50(param_1,'\x01');
  iVar1 = 0;
  iVar3 = iVar3 + 1;
  while (iVar3 <= (int)psVar2) {
    if (param_1[iVar3 + -1] == 0x2e) {
      iVar1 = iVar3;
      iVar3 = iVar3 + 1;
    }
    else {
      iVar4 = FUN_0041b8c8();
      iVar3 = iVar3 + iVar4;
    }
  }
  return iVar1;
}



void FUN_0041bb70(short *param_1,longlong **param_2)

{
  int iVar1;
  
  iVar1 = FUN_0041ba50(param_1,'\x01');
  FUN_004074e0((int)param_1,iVar1 + 1,0x7fffffff,param_2);
  return;
}



uint FUN_0041bb98(uint param_1)

{
  uint uVar1;
  
  if (param_1 == 0) {
    return 0;
  }
  uVar1 = param_1;
  if (param_1 != 0) {
    uVar1 = *(uint *)(param_1 - 4);
  }
  uVar1 = FUN_0041bbbc(param_1,param_1 + uVar1 * 2);
  return uVar1;
}



uint FUN_0041bbbc(uint param_1,uint param_2)

{
  if (param_1 < param_2) {
    param_2 = param_2 - 2;
  }
  return param_2;
}



void FUN_0041bbc8(longlong *param_1,longlong **param_2)

{
  int iVar1;
  short *psVar2;
  undefined4 uVar3;
  longlong *plVar4;
  longlong *plVar5;
  
  iVar1 = FUN_0041b968((short *)param_1,'\x01');
  plVar5 = param_1;
  if (param_1 != (longlong *)0x0) {
    plVar5 = *(longlong **)((int)param_1 + -4);
  }
  for (; iVar1 < (int)plVar5; plVar5 = (longlong *)((int)plVar5 + -1)) {
    psVar2 = (short *)FUN_0041bbbc((uint)param_1,(int)param_1 + (int)plVar5 * 2);
    uVar3 = FUN_0041b8d0(*psVar2);
    if ((char)uVar3 == '\0') break;
  }
  plVar4 = param_1;
  if (param_1 != (longlong *)0x0) {
    plVar4 = *(longlong **)((int)param_1 + -4);
  }
  if (plVar4 == plVar5) {
    FUN_00406dfc(param_2,param_1);
  }
  else {
    FUN_004074e0((int)param_1,1,(int)plVar5,param_2);
  }
  return;
}



void FUN_0041bc34(longlong *param_1)

{
  LPCWSTR lpFileName;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  longlong *local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_14 = &LAB_0041bc7a;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  FUN_0041bbc8(param_1,&local_8);
  lpFileName = (LPCWSTR)FUN_004071e4((int)local_8);
  GetFileAttributesW(lpFileName);
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_0041bc81;
  puStack_14 = (undefined *)0x41bc79;
  FUN_00406b28((int *)&local_8);
  return;
}



undefined4 FUN_0041bc88(longlong *param_1)

{
  uint uVar1;
  
  uVar1 = FUN_0041bc34(param_1);
  if ((uVar1 != 0xffffffff) && ((uVar1 & 0x10) != 0)) {
    return CONCAT31((int3)(uVar1 >> 8),1);
  }
  return 0;
}



undefined4 FUN_0041bc9c(longlong *param_1)

{
  int iVar1;
  
  iVar1 = FUN_0041bc34(param_1);
  return CONCAT31((int3)((uint)(iVar1 + 1) >> 8),iVar1 + 1 != 0);
}



void FUN_0041bcac(int param_1,longlong **param_2)

{
  bool bVar1;
  LPWSTR lpBuffer;
  LPCWSTR lpName;
  DWORD DVar2;
  longlong *nSize;
  
  FUN_004072d0(param_2,0xff);
  while( true ) {
    nSize = *param_2;
    if (nSize != (longlong *)0x0) {
      nSize = *(longlong **)((int)nSize + -4);
    }
    lpBuffer = (LPWSTR)FUN_004071e4((int)*param_2);
    lpName = (LPCWSTR)FUN_004071e4(param_1);
    DVar2 = GetEnvironmentVariableW(lpName,lpBuffer,(DWORD)nSize);
    if (DVar2 == 0) break;
    bVar1 = FUN_0041c0a0(param_2,DVar2);
    if (bVar1) {
      return;
    }
  }
  FUN_00406b28((int *)param_2);
  return;
}



void FUN_0041bd00(ushort *param_1,int param_2,int *param_3)

{
  ushort uVar1;
  byte bVar2;
  
  *param_3 = 0;
  bVar2 = 0;
  for (; (uVar1 = *param_1, uVar1 != 0 && ((bool)(0x20 < uVar1 | bVar2))); param_1 = param_1 + 1) {
    if (uVar1 == 0x22) {
      bVar2 = bVar2 ^ 1;
    }
    else {
      if (param_2 != 0) {
        *(ushort *)(param_2 + *param_3 * 2) = uVar1;
      }
      *param_3 = *param_3 + 1;
    }
  }
  return;
}



void FUN_0041bd50(ushort *param_1,longlong **param_2)

{
  longlong *plVar1;
  ushort *puVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  int local_c;
  longlong *local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_1c = &LAB_0041bdd1;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  FUN_0041bd00(param_1,0,&local_c);
  FUN_00406c80(&local_8,(longlong *)0x0,local_c);
  plVar1 = thunk_FUN_00406f14(&local_8);
  puVar2 = (ushort *)FUN_0041bd00(param_1,(int)plVar1,&local_c);
  FUN_00406dfc(param_2,local_8);
  for (; (*puVar2 != 0 && (*puVar2 < 0x21)); puVar2 = puVar2 + 1) {
  }
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_0041bdd8;
  puStack_1c = (undefined *)0x41bdd0;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_0041bde0(longlong **param_1)

{
  LPWSTR pWVar1;
  longlong *plVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  longlong *local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_14 = &LAB_0041be22;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  pWVar1 = GetCommandLineW();
  plVar2 = (longlong *)FUN_0041bd50((ushort *)pWVar1,&local_8);
  FUN_0040723c(param_1,plVar2);
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_0041be29;
  puStack_14 = (undefined *)0x41be21;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_0041be30(void)

{
  LPWSTR pWVar1;
  ushort *puVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  longlong *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_18 = &LAB_0041be81;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  pWVar1 = GetCommandLineW();
  for (puVar2 = (ushort *)FUN_0041bd50((ushort *)pWVar1,&local_8); *puVar2 != 0;
      puVar2 = (ushort *)FUN_0041bd50(puVar2,&local_8)) {
  }
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_0041be88;
  puStack_18 = (undefined *)0x41be80;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_0041be90(int param_1,longlong **param_2)

{
  DWORD DVar1;
  LPWSTR pWVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_228;
  undefined *puStack_224;
  undefined *puStack_220;
  longlong local_210 [65];
  longlong *local_8;
  
  puStack_220 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_224 = &LAB_0041bf25;
  uStack_228 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_228;
  if (param_1 == 0) {
    puStack_220 = &stack0xfffffffc;
    DVar1 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)local_210,0x104);
    FUN_00406c80(param_2,local_210,DVar1);
  }
  else {
    pWVar2 = GetCommandLineW();
    while (*pWVar2 != L'\0') {
      pWVar2 = (LPWSTR)FUN_0041bd50((ushort *)pWVar2,&local_8);
      if (param_1 == 0) goto LAB_0041bf05;
      param_1 = param_1 + -1;
    }
    FUN_00406b28((int *)&local_8);
LAB_0041bf05:
    FUN_00406dfc(param_2,local_8);
  }
  *in_FS_OFFSET = uStack_228;
  puStack_220 = &LAB_0041bf2c;
  puStack_224 = (undefined *)0x41bf24;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_0041bf34(longlong **param_1)

{
  longlong local_20c [65];
  
  GetWindowsDirectoryW((LPWSTR)local_20c,0x104);
  FUN_00415e78(local_20c,param_1);
  return;
}



void FUN_0041bf60(longlong **param_1)

{
  longlong local_20c [65];
  
  GetSystemDirectoryW((LPWSTR)local_20c,0x104);
  FUN_00415e78(local_20c,param_1);
  return;
}



void FUN_0041bf8c(longlong **param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  longlong *local_c;
  longlong *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  local_c = (longlong *)0x0;
  puStack_18 = &LAB_0041c043;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  FUN_0041bcac((int)&DAT_0041c05c,param_1);
  if (*param_1 != (longlong *)0x0) {
    uVar1 = FUN_0041bc88(*param_1);
    if ((char)uVar1 != '\0') goto LAB_0041c009;
  }
  FUN_0041bcac((int)L"TEMP",param_1);
  if (*param_1 != (longlong *)0x0) {
    uVar1 = FUN_0041bc88(*param_1);
    if ((char)uVar1 != '\0') goto LAB_0041c009;
  }
  iVar2 = FUN_00419bc4();
  if (iVar2 == 2) {
    FUN_0041bcac((int)L"USERPROFILE",param_1);
    if (*param_1 != (longlong *)0x0) {
      uVar1 = FUN_0041bc88(*param_1);
      if ((char)uVar1 != '\0') goto LAB_0041c009;
    }
  }
  FUN_0041bf34(param_1);
LAB_0041c009:
  FUN_0041bac0(*param_1,&local_c);
  FUN_0041b87c(local_c,&local_8);
  FUN_00406dfc(param_1,local_8);
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_0041c04a;
  puStack_18 = (undefined *)0x41c042;
  FUN_00406b88((int *)&local_c,2);
  return;
}



bool FUN_0041c0a0(longlong **param_1,int param_2)

{
  longlong *plVar1;
  
  plVar1 = *param_1;
  if (plVar1 != (longlong *)0x0) {
    plVar1 = *(longlong **)((int)plVar1 + -4);
  }
  FUN_004072d0(param_1,param_2);
  return param_2 < (int)plVar1;
}



void FUN_0041c0bc(HKEY param_1,LPCWSTR param_2,longlong **param_3,DWORD param_4,DWORD param_5)

{
  LSTATUS LVar1;
  longlong *plVar2;
  uint uVar3;
  undefined4 *in_FS_OFFSET;
  uint *lpcbData;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  uint local_18;
  DWORD local_14;
  longlong **local_10;
  LPCWSTR local_c;
  longlong *local_8;
  
  puStack_28 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_2c = &LAB_0041c1f2;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  local_10 = param_3;
  local_c = param_2;
  while( true ) {
    local_18 = 0;
    LVar1 = RegQueryValueExW(param_1,local_c,(LPDWORD)0x0,&local_14,(LPBYTE)0x0,&local_18);
    if ((LVar1 != 0) || ((local_14 != param_5 && (local_14 != param_4)))) goto LAB_0041c1dc;
    if (local_18 == 0) break;
    if (0x6fffffff < local_18) {
      FUN_00418abc();
    }
    FUN_00406c80(&local_8,(longlong *)0x0,local_18 + 1 >> 1);
    lpcbData = &local_18;
    plVar2 = thunk_FUN_00406f14(&local_8);
    LVar1 = RegQueryValueExW(param_1,local_c,(LPDWORD)0x0,&local_14,(LPBYTE)plVar2,lpcbData);
    if (LVar1 != 0xea) {
      if ((LVar1 == 0) && ((local_14 == param_5 || (local_14 == param_4)))) {
        uVar3 = local_18 >> 1;
        while ((uVar3 != 0 && (*(short *)((int)local_8 + uVar3 * 2 + -2) == 0))) {
          uVar3 = uVar3 - 1;
        }
        if ((local_14 == 7) && (uVar3 != 0)) {
          uVar3 = uVar3 + 1;
        }
        FUN_004072d0(&local_8,uVar3);
        if ((local_14 == 7) && (uVar3 != 0)) {
          plVar2 = thunk_FUN_00406f14(&local_8);
          *(undefined2 *)((int)plVar2 + uVar3 * 2 + -2) = 0;
        }
        FUN_00406dfc(local_10,local_8);
      }
LAB_0041c1dc:
      *in_FS_OFFSET = uStack_30;
      puStack_28 = &LAB_0041c1f9;
      puStack_2c = (undefined *)0x41c1f1;
      FUN_00406b28((int *)&local_8);
      return;
    }
  }
  FUN_00406b28((int *)local_10);
  goto LAB_0041c1dc;
}



void FUN_0041c204(HKEY param_1,LPCWSTR param_2,longlong **param_3)

{
  FUN_0041c0bc(param_1,param_2,param_3,2,1);
  return;
}



void FUN_0041c210(char param_1,HKEY param_2,LPCWSTR param_3,PHKEY param_4,REGSAM param_5,
                 DWORD param_6)

{
  if (param_1 == '\x02') {
    param_5 = param_5 | 0x100;
  }
  RegOpenKeyExW(param_2,param_3,param_6,param_5,param_4);
  return;
}



PVOID FUN_0041c238(DWORD param_1)

{
  undefined uVar1;
  int iVar2;
  BOOL BVar3;
  DWORD DVar4;
  HANDLE pvVar5;
  int *TokenInformation;
  PVOID pvVar6;
  undefined extraout_CL;
  undefined extraout_CL_00;
  undefined extraout_CL_01;
  undefined extraout_CL_02;
  undefined extraout_CL_03;
  undefined extraout_CL_04;
  undefined extraout_CL_05;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  code *pcVar7;
  int iVar8;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar9;
  undefined *puVar10;
  HANDLE *ppvVar11;
  HMODULE pHVar12;
  wchar_t *pwVar13;
  DWORD local_18;
  HANDLE local_14;
  int local_10;
  PSID local_c;
  byte local_5;
  
  iVar2 = FUN_00419bc4();
  if (iVar2 == 2) {
    local_5 = 0;
    pHVar12 = (HMODULE)0x0;
    BVar3 = AllocateAndInitializeSid
                      ((PSID_IDENTIFIER_AUTHORITY)&DAT_00428314,'\x02',0x20,param_1,0,0,0,0,0,0,
                       &local_c);
    if (BVar3 != 0) {
      *in_FS_OFFSET = &stack0xffffffcc;
      pcVar7 = (code *)0x0;
      pwVar13 = L"Ｅ";
      DVar4 = GetVersion();
      if (4 < ((ushort)DVar4 & 0xff)) {
        pwVar13 = L"CheckTokenMembership";
        pHVar12 = GetModuleHandleW(L"advapi32.dll");
        pcVar7 = (code *)FUN_0040bdc0((char)pHVar12,extraout_DL,extraout_CL,pHVar12,pwVar13);
      }
      if (pcVar7 != (code *)0x0) {
        uVar9 = 0;
        iVar2 = (*pcVar7)();
        if (iVar2 != 0) {
          local_5 = 1 - (local_10 == 0);
        }
        *in_FS_OFFSET = uVar9;
        pvVar6 = FreeSid(local_c);
        return pvVar6;
      }
      ppvVar11 = &local_14;
      BVar3 = -1;
      DVar4 = 8;
      pvVar5 = GetCurrentThread();
      BVar3 = OpenThreadToken(pvVar5,DVar4,BVar3,ppvVar11);
      if (BVar3 == 0) {
        DVar4 = GetLastError();
        if (DVar4 != 0x3f0) {
          FUN_004063c0((char)DVar4,extraout_DL_00,extraout_CL_00,pHVar12,pwVar13);
          goto LAB_0041c42a;
        }
        ppvVar11 = &local_14;
        DVar4 = 8;
        pvVar5 = GetCurrentProcess();
        BVar3 = OpenProcessToken(pvVar5,DVar4,ppvVar11);
        if (BVar3 == 0) {
          FUN_004063c0(0,extraout_DL_01,extraout_CL_01,pHVar12,pwVar13);
          goto LAB_0041c42a;
        }
      }
      puVar10 = &LAB_0041c405;
      uVar9 = *in_FS_OFFSET;
      *in_FS_OFFSET = &stack0xffffffb8;
      local_18 = 0;
      BVar3 = GetTokenInformation(local_14,TokenGroups,(LPVOID)0x0,0,&local_18);
      if (BVar3 == 0) {
        DVar4 = GetLastError();
        if (DVar4 != 0x7a) {
          uVar1 = FUN_004063c0((char)DVar4,extraout_DL_02,extraout_CL_02,uVar9,puVar10);
          FUN_004063c0(uVar1,extraout_DL_03,extraout_CL_03,pHVar12,pwVar13);
          goto LAB_0041c42a;
        }
      }
      TokenInformation = (int *)FUN_004044b8(local_18);
      BVar3 = GetTokenInformation(local_14,TokenGroups,TokenInformation,local_18,&local_18);
      if (BVar3 != 0) {
        iVar2 = *TokenInformation;
        if (-1 < iVar2 + -1) {
          iVar8 = 0;
          do {
            BVar3 = EqualSid(local_c,(PSID)TokenInformation[iVar8 * 2 + 1]);
            if ((BVar3 != 0) && ((TokenInformation[iVar8 * 2 + 2] & 0x14U) == 4)) {
              local_5 = 1;
              break;
            }
            iVar8 = iVar8 + 1;
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
        *in_FS_OFFSET = uVar9;
        FUN_004044d4((int)TokenInformation);
        pvVar6 = (PVOID)CloseHandle(local_14);
        return pvVar6;
      }
      uVar1 = FUN_004063c0(0,extraout_DL_04,extraout_CL_04,uVar9,puVar10);
      FUN_004063c0(uVar1,extraout_DL_05,extraout_CL_05,pHVar12,pwVar13);
    }
  }
  else {
    local_5 = 1;
  }
LAB_0041c42a:
  return (PVOID)(uint)local_5;
}



void FUN_0041c47c(void)

{
  FUN_0041c238(0x220);
  return;
}



void FUN_0041c488(void)

{
  HMODULE pHVar1;
  code *pcVar2;
  int iVar3;
  undefined extraout_CL;
  undefined extraout_DL;
  HMODULE *in_FS_OFFSET;
  wchar_t *pwVar4;
  HINSTANCE__ HStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  longlong *local_14;
  uint local_10;
  HKEY local_c;
  longlong *local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_14 = (longlong *)0x0;
  local_8 = (longlong *)0x0;
  puStack_20 = &LAB_0041c582;
  HStack_24.unused = (int)*in_FS_OFFSET;
  *in_FS_OFFSET = &HStack_24;
  pwVar4 = L"GetUserDefaultUILanguage";
  pHVar1 = GetModuleHandleW(L"kernel32.dll");
  pcVar2 = (code *)FUN_0040bdc0((char)pHVar1,extraout_DL,extraout_CL,pHVar1,pwVar4);
  if (pcVar2 == (code *)0x0) {
    iVar3 = FUN_00419bc4();
    if (iVar3 == 2) {
      iVar3 = FUN_0041c210('\0',(HKEY)0x80000003,L".DEFAULT\\Control Panel\\International",&local_c,
                           1,0);
      if (iVar3 == 0) {
        FUN_0041c204(local_c,L"Locale",&local_8);
        RegCloseKey(local_c);
      }
    }
    else {
      iVar3 = FUN_0041c210('\0',(HKEY)0x80000001,L"Control Panel\\Desktop\\ResourceLocale",&local_c,
                           1,0);
      if (iVar3 == 0) {
        FUN_0041c204(local_c,L"",&local_8);
        RegCloseKey(local_c);
      }
    }
    FUN_004073a8(&local_14,(longlong *)&LAB_0041c698,local_8);
    FUN_00404994((ushort *)local_14,&local_10);
  }
  else {
    (*pcVar2)();
  }
  *in_FS_OFFSET = pHVar1;
  HStack_24.unused = (int)&LAB_0041c589;
  FUN_00406b28((int *)&local_14);
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_0041c69c(longlong *param_1,longlong **param_2)

{
  ushort *puVar1;
  
  FUN_00406dfc(param_2,param_1);
  if (*param_2 != (longlong *)0x0) {
    puVar1 = (ushort *)FUN_0041bb98((uint)*param_2);
    if (0x2e < *puVar1) {
      FUN_00407350(param_2,(longlong *)&LAB_0041c6d8);
    }
  }
  return;
}



void FUN_0041c758(DWORD param_1,longlong **param_2)

{
  ushort uVar1;
  DWORD DVar2;
  longlong local_804 [256];
  
  DVar2 = FormatMessageW(0x3200,(LPCVOID)0x0,param_1,0,(LPWSTR)local_804,0x400,(va_list *)0x0);
  while ((0 < (int)DVar2 &&
         ((uVar1 = *(ushort *)((int)local_804 + DVar2 * 2 + -2), uVar1 < 0x21 || (uVar1 == 0x2e)))))
  {
    DVar2 = DVar2 - 1;
  }
  FUN_00406c80(param_2,local_804,DVar2);
  return;
}



void FUN_0041d07c(undefined4 param_1,DWORD param_2)

{
  int *piVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  DWORD local_10;
  undefined local_c;
  longlong *local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_1c = &LAB_0041d0f3;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  FUN_0041c758(param_2,&local_8);
  if (local_8 == (longlong *)0x0) {
    local_c = 0;
    local_10 = param_2;
    FUN_00415f70((longlong *)L"File I/O error %d",(int)&local_10,0,&local_8);
  }
  piVar1 = FUN_00418ac8((int *)&PTR_LAB_0041cfc0,'\x01',local_8);
  piVar1[6] = param_2;
  FUN_004062cc((int)piVar1);
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_0041d0fa;
  puStack_1c = (undefined *)0x41d0f2;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_0041d130(undefined4 param_1)

{
  DWORD DVar1;
  
  DVar1 = GetLastError();
  FUN_0041d07c(param_1,DVar1);
  return;
}



void FUN_0041d144(int *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  iVar1 = (**(code **)(*param_1 + 8))(param_1,param_2,param_3);
  if (param_3 != iVar1) {
    FUN_0041d07c(*param_1,0x26);
  }
  return;
}



void FUN_0041d16c(int *param_1,undefined4 param_2)

{
  undefined4 local_8;
  undefined4 local_4;
  
  local_4 = 0;
  local_8 = param_2;
  (**(code **)(*param_1 + 0xc))(param_1,&local_8);
  return;
}



int * FUN_0041d1ac(int *param_1,char param_2,undefined4 param_3,byte param_4,undefined param_5,
                  undefined param_6)

{
  uint uVar1;
  int iVar2;
  undefined4 extraout_ECX;
  char extraout_DL;
  uint *in_FS_OFFSET;
  undefined4 in_stack_ffffffe0;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00405424((int)param_1,param_2,param_3,in_stack_ffffffe0,in_stack_ffffffe4,
                                  in_stack_ffffffe8,in_stack_ffffffec);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00404dc4(param_1,'\0',param_3);
  uVar1 = (uint)param_4;
  iVar2 = (**(code **)(*param_1 + 0x14))(param_1,param_3,param_6,uVar1,param_5);
  param_1[1] = iVar2;
  if ((param_1[1] == 0) || (param_1[1] == -1)) {
    FUN_0041d130(*param_1);
  }
  *(undefined *)(param_1 + 2) = 1;
  if (param_2 != '\0') {
    FUN_0040547c(param_1);
    *in_FS_OFFSET = uVar1;
  }
  return param_1;
}



int * FUN_0041d220(int *param_1,char param_2,int param_3)

{
  int extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00405424((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00404dc4(param_1,'\0',param_3);
  param_1[1] = param_3;
  if (param_2 != '\0') {
    FUN_0040547c(param_1);
    *in_FS_OFFSET = in_stack_ffffffe4;
  }
  return param_1;
}



void FUN_0041d290(undefined4 param_1,int param_2,uint param_3,byte param_4,byte param_5)

{
  LPCWSTR lpFileName;
  DWORD dwDesiredAccess;
  DWORD dwShareMode;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  DWORD dwCreationDisposition;
  DWORD dwFlagsAndAttributes;
  HANDLE hTemplateFile;
  
  hTemplateFile = (HANDLE)0x0;
  dwFlagsAndAttributes = 0x80;
  dwCreationDisposition = *(DWORD *)(&DAT_00428338 + (param_3 & 0xff) * 4);
  lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  dwShareMode = *(DWORD *)(&DAT_00428328 + (uint)param_4 * 4);
  dwDesiredAccess = *(DWORD *)(&DAT_0042831c + (uint)param_5 * 4);
  lpFileName = (LPCWSTR)FUN_004071e4(param_2);
  CreateFileW(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,
              dwFlagsAndAttributes,hTemplateFile);
  return;
}



void FUN_0041d380(undefined4 *param_1,LONG *param_2)

{
  DWORD DVar1;
  LONG local_10;
  
  local_10 = param_2[1];
  DVar1 = SetFilePointer((HANDLE)param_1[1],*param_2,&local_10,0);
  if (DVar1 == 0xffffffff) {
    DVar1 = GetLastError();
    if (DVar1 != 0) {
      FUN_0041d130(*param_1);
    }
  }
  return;
}



void FUN_0041d3f4(undefined4 *param_1)

{
  BOOL BVar1;
  
  BVar1 = SetEndOfFile((HANDLE)param_1[1]);
  if (BVar1 == 0) {
    FUN_0041d130(*param_1);
  }
  return;
}



void FUN_0041dac8(void)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  uint uVar4;
  
  uVar4 = 0;
  puVar2 = &DAT_0042e83c;
  do {
    iVar3 = 8;
    uVar1 = uVar4;
    do {
      if ((uVar1 & 1) == 0) {
        uVar1 = uVar1 >> 1;
      }
      else {
        uVar1 = uVar1 >> 1 ^ 0xedb88320;
      }
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    *puVar2 = uVar1;
    uVar4 = uVar4 + 1;
    puVar2 = puVar2 + 1;
  } while (uVar4 != 0x100);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0041dafc(uint param_1,byte *param_2,int param_3)

{
  if (_DAT_0042e838 == 0) {
    FUN_0041dac8();
    LOCK();
    _DAT_0042e838 = 1;
    UNLOCK();
  }
  if (param_3 != 0) {
    do {
      param_1 = (&DAT_0042e83c)[(ushort)((ushort)param_1 & 0xff ^ (ushort)*param_2)] ^ param_1 >> 8;
      param_3 = param_3 + -1;
      param_2 = param_2 + 1;
    } while (param_3 != 0);
  }
  return param_1;
}



uint FUN_0041db58(byte *param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = FUN_0041dafc(0xffffffff,param_1,param_2);
  return uVar1 ^ 0xffffffff;
}



void FUN_0041db70(int param_1,int param_2,char param_3,int param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  if (4 < param_2) {
    iVar1 = 0;
    if (0 < param_2 + -4) {
      do {
        if ((*(char *)(param_1 + iVar1) == -0x18) || (*(char *)(param_1 + iVar1) == -0x17)) {
          iVar2 = iVar1 + 1;
          if ((*(char *)(param_1 + 3 + iVar2) == '\0') || (*(char *)(param_1 + 3 + iVar2) == -1)) {
            uVar3 = param_4 + iVar2 + 4U & 0xffffff;
            uVar4 = (uint)CONCAT12(*(undefined *)(param_1 + 2 + iVar2),
                                   CONCAT11(*(undefined *)(param_1 + 1 + iVar2),
                                            *(undefined *)(param_1 + iVar2)));
            if (param_3 == '\0') {
              uVar4 = uVar4 - uVar3;
            }
            if ((uVar4 & 0x800000) != 0) {
              *(byte *)(param_1 + 3 + iVar2) = ~*(byte *)(param_1 + 3 + iVar2);
            }
            if (param_3 != '\0') {
              uVar4 = uVar4 + uVar3;
            }
            *(char *)(param_1 + iVar2) = (char)uVar4;
            *(char *)(param_1 + 1 + iVar2) = (char)(uVar4 >> 8);
            *(char *)(param_1 + 2 + iVar2) = (char)(uVar4 >> 0x10);
          }
          iVar1 = iVar1 + 5;
        }
        else {
          iVar1 = iVar1 + 1;
        }
      } while (iVar1 < param_2 + -4);
    }
  }
  return;
}



int * FUN_0041dc2c(int *param_1,char param_2,undefined4 param_3,int param_4,int param_5)

{
  undefined4 extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00405424((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00404dc4(param_1,'\0',param_3);
  param_1[2] = param_4;
  param_1[3] = param_5;
  if (param_2 != '\0') {
    FUN_0040547c(param_1);
    *in_FS_OFFSET = in_stack_ffffffe4;
  }
  return param_1;
}



int * FUN_0041dc74(int *param_1,char param_2,int *param_3,undefined **param_4)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  int *extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffc0;
  undefined4 in_stack_ffffffc4;
  undefined4 in_stack_ffffffc8;
  undefined4 in_stack_ffffffcc;
  uint local_24 [2];
  uint local_1c [2];
  uint local_11;
  char local_d;
  uint local_c;
  char local_5;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00405424((int)param_1,param_2,param_3,in_stack_ffffffc0,in_stack_ffffffc4,
                                  in_stack_ffffffc8,in_stack_ffffffcc);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  local_5 = param_2;
  FUN_00404dc4(param_1,'\0',param_3);
  param_1[2] = (int)param_3;
  iVar1 = (**(code **)(*param_3 + 8))(param_3,&local_c,4);
  if (iVar1 == 4) {
    iVar1 = (**(code **)(*param_3 + 8))(param_3,&local_11,5);
    if (iVar1 == 5) goto LAB_0041dcda;
  }
  piVar2 = FUN_00418ac8((int *)&PTR_LAB_0041d550,'\x01',(longlong *)L"Compressed block is corrupted"
                       );
  FUN_004062cc((int)piVar2);
LAB_0041dcda:
  uVar3 = FUN_0041db58((byte *)&local_11,5);
  if (uVar3 != local_c) {
    piVar2 = FUN_00418ac8((int *)&PTR_LAB_0041d550,'\x01',
                          (longlong *)L"Compressed block is corrupted");
    FUN_004062cc((int)piVar2);
  }
  (**(code **)*param_3)(param_3,local_1c);
  FUN_0041b870(local_1c,local_11);
  (**(code **)(*param_3 + 4))(param_3,local_24);
  iVar1 = FUN_0041b850(local_1c,local_24);
  if (0 < iVar1) {
    piVar2 = FUN_00418ac8((int *)&PTR_LAB_0041d550,'\x01',
                          (longlong *)L"Compressed block is corrupted");
    FUN_004062cc((int)piVar2);
  }
  if (local_d != '\0') {
    iVar1 = (*(code *)*param_4)(param_4,1);
    param_1[1] = iVar1;
  }
  param_1[3] = local_11;
  *(undefined *)(param_1 + 4) = 1;
  if (local_5 != '\0') {
    FUN_0040547c(param_1);
    *in_FS_OFFSET = in_stack_ffffffc0;
  }
  return param_1;
}



void FUN_0041de24(int param_1,undefined4 param_2,uint param_3)

{
  int *piVar1;
  uint uVar2;
  uint local_c;
  
  local_c = param_3;
  if (*(uint *)(param_1 + 0xc) < 5) {
    piVar1 = FUN_00418ac8((int *)&PTR_LAB_0041d550,'\x01',
                          (longlong *)L"Compressed block is corrupted");
    FUN_004062cc((int)piVar1);
  }
  FUN_0041d144(*(int **)(param_1 + 8),&local_c,4);
  *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + -4;
  uVar2 = *(uint *)(param_1 + 0xc);
  if (0x1000 < uVar2) {
    uVar2 = 0x1000;
  }
  FUN_0041d144(*(int **)(param_1 + 8),param_1 + 0x1c,uVar2);
  *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) - uVar2;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(uint *)(param_1 + 0x18) = uVar2;
  uVar2 = FUN_0041db58((byte *)(param_1 + 0x1c),uVar2);
  if (uVar2 != local_c) {
    piVar1 = FUN_00418ac8((int *)&PTR_LAB_0041d550,'\x01',
                          (longlong *)L"Compressed block is corrupted");
    FUN_004062cc((int)piVar1);
  }
  return;
}



int FUN_0041def4(int param_1,longlong *param_2,uint param_3)

{
  uint extraout_ECX;
  longlong *extraout_EDX;
  uint uVar1;
  longlong *plVar2;
  uint uVar3;
  int local_14;
  
  local_14 = 0;
  plVar2 = param_2;
  uVar3 = param_3;
  if (0 < (int)param_3) {
    do {
      if (*(int *)(param_1 + 0x18) == 0) {
        if (*(int *)(param_1 + 0xc) == 0) {
          return local_14;
        }
        FUN_0041de24(param_1,param_2,param_3);
      }
      uVar1 = uVar3;
      if (*(uint *)(param_1 + 0x18) <= uVar3 && uVar3 != *(uint *)(param_1 + 0x18)) {
        uVar1 = *(uint *)(param_1 + 0x18);
      }
      FUN_0040465c((longlong *)(param_1 + 0x1c + *(int *)(param_1 + 0x14)),plVar2,uVar1);
      *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + uVar1;
      *(int *)(param_1 + 0x18) = *(int *)(param_1 + 0x18) - uVar1;
      plVar2 = (longlong *)((int)plVar2 + uVar1);
      uVar3 = uVar3 - uVar1;
      local_14 = local_14 + uVar1;
      param_3 = extraout_ECX;
      param_2 = extraout_EDX;
    } while (0 < (int)uVar3);
  }
  return local_14;
}



void FUN_0041df50(int param_1,longlong *param_2,uint param_3)

{
  uint uVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 4);
  if (piVar2 == (int *)0x0) {
    uVar1 = FUN_0041def4(param_1,param_2,param_3);
    if (param_3 != uVar1) {
      piVar2 = FUN_00418ac8((int *)&PTR_LAB_0041d550,'\x01',
                            (longlong *)L"Compressed block is corrupted");
      FUN_004062cc((int)piVar2);
    }
  }
  else {
    (**(code **)(*piVar2 + 4))(piVar2,param_2,param_3);
  }
  return;
}



void FUN_0041e408(undefined4 param_1)

{
  int iVar1;
  undefined4 local_c;
  undefined local_8;
  
  local_8 = 0;
  local_c = param_1;
  iVar1 = FUN_00418b04((int)&PTR_LAB_0041d550,'\x01',
                       (longlong *)L"lzmadecompsmall: Compressed data is corrupted (%d)",0,
                       (int)&local_c);
  FUN_004062cc(iVar1);
  return;
}



void FUN_0041e4a8(undefined4 param_1)

{
  int iVar1;
  undefined4 local_c;
  undefined local_8;
  
  local_8 = 0x11;
  local_c = param_1;
  iVar1 = FUN_00418b04((int)&PTR_LAB_0041d600,'\x01',(longlong *)L"lzmadecompsmall: %s",0,
                       (int)&local_c);
  FUN_004062cc(iVar1);
  return;
}



void FUN_0041e508(longlong *param_1,int param_2,int param_3)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  int local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_8 = 0;
  puStack_1c = &LAB_0041e551;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  FUN_00415f70(param_1,param_2,param_3,&local_8);
  FUN_0041e4a8(local_8);
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_0041e558;
  puStack_1c = (undefined *)0x41e550;
  FUN_00406b28(&local_8);
  return;
}



void FUN_0041e598(int param_1)

{
  *(undefined4 *)(param_1 + 0x68) = 0;
  if (*(LPVOID *)(param_1 + 100) != (LPVOID)0x0) {
    VirtualFree(*(LPVOID *)(param_1 + 100),0,0x8000);
    *(undefined4 *)(param_1 + 100) = 0;
  }
  return;
}



void FUN_0041e5bc(int param_1,int *param_2,int *param_3)

{
  int iVar1;
  
  *param_2 = param_1 + 0x6c;
  *param_3 = 0;
  if (*(char *)(param_1 + 0x10) == '\0') {
    iVar1 = (**(code **)(param_1 + 8))(*(undefined4 *)(param_1 + 0xc),param_1 + 0x6c,0x10000);
    *param_3 = iVar1;
    if (*param_3 == 0) {
      *(undefined *)(param_1 + 0x10) = 1;
    }
  }
  return;
}



void FUN_0041e5f0(int param_1)

{
  int iVar1;
  LPVOID pvVar2;
  SIZE_T dwSize;
  byte abStack_1c [8];
  int iStack_14;
  uint uStack_10;
  
  iVar1 = (**(code **)(param_1 + 8))(*(undefined4 *)(param_1 + 0xc),abStack_1c,5);
  if (iVar1 != 5) {
    FUN_0041e408(1);
  }
  FUN_004048f8((double *)(param_1 + 0x14),0x50,0);
  iVar1 = FUN_0041f1a4((uint *)(param_1 + 0x14),0x50,abStack_1c,&uStack_10,&iStack_14,5);
  if (iVar1 != 0) {
    FUN_0041e408(3);
  }
  if (0x4000000 < uStack_10) {
    FUN_0041e408(7);
  }
  dwSize = iStack_14 + uStack_10;
  if (dwSize != *(SIZE_T *)(param_1 + 0x68)) {
    FUN_0041e598(param_1);
    pvVar2 = VirtualAlloc((LPVOID)0x0,dwSize,0x1000,4);
    *(LPVOID *)(param_1 + 100) = pvVar2;
    if (pvVar2 == (LPVOID)0x0) {
      FUN_00418abc();
    }
    *(SIZE_T *)(param_1 + 0x68) = dwSize;
  }
  FUN_0041f1f4(param_1 + 0x14,*(undefined4 *)(param_1 + 100),*(int *)(param_1 + 100) + iStack_14);
  *(undefined *)(param_1 + 0x11) = 1;
  return;
}



void FUN_0041e6b4(int param_1,int param_2,uint param_3)

{
  int iVar1;
  undefined *local_20;
  int local_1c;
  uint local_18;
  int local_14;
  undefined local_10;
  
  if (*(char *)(param_1 + 0x11) == '\0') {
    FUN_0041e5f0(param_1);
  }
  local_20 = &LAB_0041e560;
  local_1c = param_1;
  iVar1 = FUN_0041eb08((undefined4 *)(param_1 + 0x14),&local_20,param_2,&local_18,param_3);
  if (iVar1 != 0) {
    if (iVar1 == 1) {
      FUN_0041e408(5);
    }
    else {
      local_10 = 0;
      local_14 = iVar1;
      FUN_0041e508((longlong *)L"LzmaDecode failed (%d)",(int)&local_14,0);
    }
  }
  if (local_18 != param_3) {
    FUN_0041e408(6);
  }
  return;
}



undefined FUN_0041e780(int *param_1,undefined4 param_2,int param_3)

{
  undefined *puVar1;
  int iVar2;
  int iStack_c;
  
  if (*param_1 == param_1[1]) {
    iStack_c = param_3;
    iVar2 = (**(code **)param_1[4])((code **)param_1[4],param_1,&iStack_c);
    param_1[5] = iVar2;
    param_1[1] = *param_1 + iStack_c;
    if (iStack_c == 0) {
      param_1[6] = 1;
      return 0xff;
    }
  }
  puVar1 = (undefined *)*param_1;
  *param_1 = *param_1 + 1;
  return *puVar1;
}



void FUN_0041e7c0(int *param_1)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  param_1[1] = 0;
  uVar3 = 0;
  *param_1 = 0;
  uVar2 = 0;
  param_1[6] = 0;
  param_1[3] = 0;
  param_1[2] = -1;
  iVar4 = 0;
  do {
    bVar1 = FUN_0041e780(param_1,uVar3,uVar2);
    uVar2 = param_1[3] << 8;
    uVar3 = bVar1 | uVar2;
    iVar4 = iVar4 + 1;
    param_1[3] = uVar3;
  } while (iVar4 < 5);
  return;
}



uint FUN_0041e800(int *param_1,uint param_2,int param_3)

{
  byte bVar1;
  int extraout_ECX;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar3 = 0;
  uVar2 = param_1[2];
  uVar4 = param_1[3];
  uVar5 = param_2;
  if (param_2 != 0) {
    do {
      uVar2 = uVar2 >> 1;
      uVar3 = uVar3 * 2;
      if (uVar2 <= uVar4) {
        uVar4 = uVar4 - uVar2;
        uVar3 = uVar3 | 1;
      }
      if (uVar2 < 0x1000000) {
        uVar2 = uVar2 << 8;
        bVar1 = FUN_0041e780(param_1,param_2,param_3);
        param_2 = (uint)bVar1 | uVar4 << 8;
        param_3 = extraout_ECX;
        uVar4 = param_2;
      }
      uVar5 = uVar5 - 1;
    } while (uVar5 != 0);
  }
  param_1[2] = uVar2;
  param_1[3] = uVar4;
  return uVar3;
}



undefined4 FUN_0041e860(ushort *param_1,int *param_2)

{
  ushort uVar1;
  ushort uVar2;
  byte bVar3;
  int iVar4;
  uint uVar5;
  
  uVar1 = *param_1;
  uVar5 = ((uint)param_2[2] >> 0xb) * (uint)uVar1;
  if ((uint)param_2[3] <= uVar5 && uVar5 - param_2[3] != 0) {
    param_2[2] = uVar5;
    uVar1 = *param_1;
    iVar4 = (int)(0x800 - (uint)uVar1) >> 5;
    *param_1 = *param_1 + (short)iVar4;
    if ((uint)param_2[2] < 0x1000000) {
      uVar5 = FUN_0041e780(param_2,(uint)uVar1,iVar4);
      param_2[3] = uVar5 & 0xff | param_2[3] << 8;
      param_2[2] = param_2[2] << 8;
    }
    return 0;
  }
  param_2[2] = param_2[2] - uVar5;
  param_2[3] = param_2[3] - uVar5;
  uVar2 = *param_1;
  *param_1 = *param_1 - (short)((int)(uint)uVar2 >> 5);
  if ((uint)param_2[2] < 0x1000000) {
    bVar3 = FUN_0041e780(param_2,(int)(uint)uVar2 >> 5,(uint)uVar1);
    param_2[3] = (uint)bVar3 | param_2[3] << 8;
    param_2[2] = param_2[2] << 8;
  }
  return 1;
}



int FUN_0041e8e8(int param_1,int param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 1;
  iVar3 = param_2;
  if (param_2 != 0) {
    do {
      iVar1 = FUN_0041e860((ushort *)(param_1 + iVar2 * 2),param_3);
      iVar3 = iVar3 + -1;
      iVar2 = iVar1 + iVar2 * 2;
    } while (iVar3 != 0);
  }
  return iVar2 - (1 << ((byte)param_2 & 0x1f));
}



uint FUN_0041e92c(int param_1,int param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  uVar4 = 0;
  iVar3 = 0;
  iVar2 = 1;
  if (0 < param_2) {
    do {
      iVar1 = FUN_0041e860((ushort *)(param_1 + iVar2 * 2),param_3);
      iVar2 = iVar2 * 2 + iVar1;
      uVar4 = uVar4 | iVar1 << ((byte)iVar3 & 0x1f);
      iVar3 = iVar3 + 1;
    } while (iVar3 < param_2);
  }
  return uVar4;
}



uint FUN_0041e970(int param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 1;
  do {
    uVar1 = FUN_0041e860((ushort *)(param_1 + uVar2 * 2),param_2);
    uVar2 = uVar1 | uVar2 * 2;
  } while ((int)uVar2 < 0x100);
  return uVar2;
}



uint FUN_0041e99c(int param_1,int *param_2,byte param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = 1;
  do {
    uVar3 = (uint)param_3;
    param_3 = param_3 << 1;
    uVar1 = FUN_0041e860((ushort *)(((int)uVar3 >> 7) * 0x200 + param_1 + uVar2 * 2 + 0x200),param_2
                        );
    uVar2 = uVar2 * 2 | uVar1;
    if (uVar1 != (int)uVar3 >> 7) {
      for (; (int)uVar2 < 0x100; uVar2 = uVar1 | uVar2 * 2) {
        uVar1 = FUN_0041e860((ushort *)(param_1 + uVar2 * 2),param_2);
      }
      return uVar2;
    }
  } while ((int)uVar2 < 0x100);
  return uVar2;
}



int FUN_0041ea10(ushort *param_1,int *param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_0041e860(param_1,param_2);
  if (iVar1 == 0) {
    iVar1 = FUN_0041e8e8((int)(param_1 + param_3 * 8 + 2),3,param_2);
  }
  else {
    iVar1 = FUN_0041e860(param_1 + 1,param_2);
    if (iVar1 == 0) {
      iVar1 = FUN_0041e8e8((int)(param_1 + param_3 * 8 + 0x82),3,param_2);
      iVar1 = iVar1 + 8;
    }
    else {
      iVar1 = FUN_0041e8e8((int)(param_1 + 0x102),8,param_2);
      iVar1 = iVar1 + 0x10;
    }
  }
  return iVar1;
}



undefined4 FUN_0041ea88(uint *param_1,byte *param_2,int param_3)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  int iVar4;
  
  if (param_3 < 5) {
    return 1;
  }
  bVar1 = *param_2;
  if (bVar1 < 0xe1) {
    param_1[2] = 0;
    for (; 0x2c < bVar1; bVar1 = bVar1 - 0x2d) {
      param_1[2] = param_1[2] + 1;
    }
    param_1[1] = 0;
    for (; 8 < bVar1; bVar1 = bVar1 - 9) {
      param_1[1] = param_1[1] + 1;
    }
    *param_1 = (uint)bVar1;
    pbVar2 = param_2 + 1;
    param_1[3] = 0;
    iVar3 = 0;
    do {
      bVar1 = *pbVar2;
      iVar4 = iVar3 + 1;
      pbVar2 = pbVar2 + 1;
      param_1[3] = param_1[3] + ((uint)bVar1 << ((byte)(iVar3 << 3) & 0x1f));
      iVar3 = iVar4;
    } while (iVar4 < 4);
    if (param_1[3] == 0) {
      param_1[3] = 1;
    }
    return 0;
  }
  return 1;
}



int FUN_0041eb08(undefined4 *param_1,undefined4 param_2,int param_3,uint *param_4,uint param_5)

{
  undefined uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  int local_74;
  int local_70;
  undefined2 *local_6c;
  int local_68;
  uint local_64;
  uint local_60;
  byte local_59;
  uint local_58;
  uint local_54;
  uint local_50;
  undefined local_4c [4];
  uint local_48;
  undefined *local_44;
  uint local_40;
  int local_3c;
  uint local_38;
  uint local_34;
  uint local_30;
  uint local_2c;
  undefined4 local_28;
  uint local_24;
  uint local_20;
  byte local_19;
  uint local_18;
  undefined2 *local_14;
  int local_10;
  undefined4 local_c;
  undefined4 *local_8;
  
  local_14 = (undefined2 *)param_1[4];
  local_18 = 0;
  local_20 = (1 << ((byte)param_1[2] & 0x1f)) - 1;
  local_24 = (1 << ((byte)param_1[1] & 0x1f)) - 1;
  local_28 = *param_1;
  uVar6 = param_1[0xd];
  iVar5 = param_1[0x11];
  local_2c = param_1[0xe];
  local_30 = param_1[0xf];
  local_34 = param_1[0x10];
  local_38 = param_1[0x12];
  local_3c = param_1[0xb];
  local_40 = param_1[0xc];
  local_44 = (undefined *)param_1[7];
  local_48 = param_1[3];
  uVar7 = param_1[10];
  local_80 = param_1[8];
  local_7c = param_1[9];
  local_88 = param_1[5];
  local_84 = param_1[6];
  *param_4 = 0;
  if (local_38 == 0xffffffff) {
    local_74 = 0;
  }
  else {
    if (local_48 == 0) {
      local_44 = local_4c;
      local_48 = 1;
      local_4c[0] = *(undefined *)(param_1 + 0x13);
    }
    local_78 = param_2;
    local_10 = param_3;
    local_c = param_2;
    local_8 = param_1;
    if (local_38 != 0xfffffffe) {
LAB_0041ecb1:
      local_6c = (undefined2 *)(local_10 + local_18);
      while ((local_38 != 0 && (local_18 < param_5))) {
        uVar4 = uVar7 - uVar6;
        if (local_48 <= uVar4) {
          uVar4 = uVar4 + local_48;
        }
        uVar1 = local_44[uVar4];
        local_44[uVar7] = uVar1;
        *(undefined *)local_6c = uVar1;
        local_18 = local_18 + 1;
        local_6c = (undefined2 *)((int)local_6c + 1);
        uVar7 = uVar7 + 1;
        if (uVar7 == local_48) {
          uVar7 = 0;
        }
        local_38 = local_38 - 1;
      }
      if (uVar7 == 0) {
        local_19 = local_44[local_48 - 1];
      }
      else {
        local_19 = local_44[uVar7 - 1];
      }
      local_74 = 0;
      local_70 = 0;
LAB_0041ed24:
      local_6c = (undefined2 *)(local_10 + local_18);
joined_r0x0041ed36:
      if (param_5 <= local_18) {
LAB_0041f114:
        local_8[8] = local_80;
        local_8[9] = local_7c;
        local_8[10] = uVar7;
        local_8[0xb] = local_3c + local_18;
        local_8[0xc] = local_40;
        local_8[0xd] = uVar6;
        local_8[0xe] = local_2c;
        local_8[0xf] = local_30;
        local_8[0x10] = local_34;
        local_8[0x11] = iVar5;
        local_8[0x12] = local_38;
        *(undefined *)(local_8 + 0x13) = local_4c[0];
        local_8[5] = local_88;
        local_8[6] = local_84;
        *param_4 = local_18;
        return 0;
      }
      local_58 = local_18 + local_3c & local_20;
      if (local_74 != 0) {
        return local_74;
      }
      if (local_70 != 0) {
        return 1;
      }
      iVar3 = FUN_0041e860(local_14 + iVar5 * 0x10 + local_58,&local_88);
      if (iVar3 == 0) {
        if (iVar5 < 7) {
          uVar4 = FUN_0041e970((int)(local_14 +
                                    (((local_18 + local_3c & local_24) << ((byte)local_28 & 0x1f)) +
                                    ((int)(uint)local_19 >> (8 - (byte)local_28 & 0x1f))) * 0x300 +
                                    0x736),&local_88);
          local_19 = (byte)uVar4;
        }
        else {
          local_60 = uVar7 - uVar6;
          if (local_48 <= local_60) {
            local_60 = local_60 + local_48;
          }
          local_59 = local_44[local_60];
          uVar4 = FUN_0041e99c((int)(local_14 +
                                    (((local_18 + local_3c & local_24) << ((byte)local_28 & 0x1f)) +
                                    ((int)(uint)local_19 >> (8 - (byte)local_28 & 0x1f))) * 0x300 +
                                    0x736),&local_88,local_59);
          local_19 = (byte)uVar4;
        }
        *(byte *)local_6c = local_19;
        local_18 = local_18 + 1;
        local_6c = (undefined2 *)((int)local_6c + 1);
        if (local_40 < local_48) {
          local_40 = local_40 + 1;
        }
        local_44[uVar7] = local_19;
        uVar7 = uVar7 + 1;
        if (uVar7 == local_48) {
          uVar7 = 0;
        }
        if (iVar5 < 4) {
          iVar5 = 0;
        }
        else if (iVar5 < 10) {
          iVar5 = iVar5 + -3;
        }
        else {
          iVar5 = iVar5 + -6;
        }
        goto joined_r0x0041ed36;
      }
      iVar3 = FUN_0041e860(local_14 + iVar5 + 0xc0,&local_88);
      if (iVar3 == 1) {
        iVar3 = FUN_0041e860(local_14 + iVar5 + 0xcc,&local_88);
        if (iVar3 == 0) {
          iVar3 = FUN_0041e860(local_14 + iVar5 * 0x10 + local_58 + 0xf0,&local_88);
          uVar4 = uVar6;
          uVar2 = local_2c;
          if (iVar3 == 0) goto code_r0x0041eeb1;
        }
        else {
          iVar3 = FUN_0041e860(local_14 + iVar5 + 0xd8,&local_88);
          uVar4 = local_2c;
          uVar2 = uVar6;
          if (iVar3 != 0) {
            iVar3 = FUN_0041e860(local_14 + iVar5 + 0xe4,&local_88);
            uVar6 = local_34;
            uVar4 = local_30;
            if (iVar3 != 0) {
              local_34 = local_30;
              uVar4 = uVar6;
            }
            local_30 = local_2c;
          }
        }
        local_2c = uVar2;
        uVar6 = uVar4;
        local_38 = FUN_0041ea10(local_14 + 0x534,&local_88,local_58);
        if (iVar5 < 7) {
          iVar5 = 8;
        }
        else {
          iVar5 = 0xb;
        }
      }
      else {
        local_34 = local_30;
        local_30 = local_2c;
        if (iVar5 < 7) {
          iVar5 = 7;
        }
        else {
          iVar5 = 10;
        }
        local_2c = uVar6;
        local_38 = FUN_0041ea10(local_14 + 0x332,&local_88,local_58);
        iVar3 = local_38;
        if (3 < (int)local_38) {
          iVar3 = 3;
        }
        uVar6 = FUN_0041e8e8((int)(local_14 + iVar3 * 0x40 + 0x1b0),6,&local_88);
        local_64 = uVar6;
        if (3 < (int)uVar6) {
          local_68 = ((int)uVar6 >> 1) + -1;
          iVar3 = (uVar6 & 1 | 2) << ((byte)local_68 & 0x1f);
          if ((int)uVar6 < 0xe) {
            uVar6 = FUN_0041e92c((int)(local_14 + iVar3 + (0x2af - uVar6)),local_68,&local_88);
            uVar6 = iVar3 + uVar6;
          }
          else {
            uVar4 = FUN_0041e800(&local_88,((int)uVar6 >> 1) - 5,local_68);
            uVar6 = FUN_0041e92c((int)(local_14 + 0x322),4,&local_88);
            uVar6 = iVar3 + uVar4 * 0x10 + uVar6;
          }
        }
        uVar6 = uVar6 + 1;
        if (uVar6 == 0) {
          local_38 = 0xffffffff;
          goto LAB_0041f114;
        }
      }
      local_38 = local_38 + 2;
      if (local_40 < uVar6) {
        return 1;
      }
      if (local_38 < local_48 - local_40) {
        local_40 = local_40 + local_38;
      }
      else {
        local_40 = local_48;
      }
      do {
        uVar4 = uVar7 - uVar6;
        if (local_48 <= uVar4) {
          uVar4 = uVar4 + local_48;
        }
        local_19 = local_44[uVar4];
        local_44[uVar7] = local_19;
        uVar7 = uVar7 + 1;
        if (uVar7 == local_48) {
          uVar7 = 0;
        }
        local_38 = local_38 - 1;
        *(byte *)local_6c = local_19;
        local_18 = local_18 + 1;
        local_6c = (undefined2 *)((int)local_6c + 1);
      } while ((local_38 != 0) && (local_18 < param_5));
      goto joined_r0x0041ed36;
    }
    local_50 = (0x300 << ((char)param_1[1] + (char)local_28 & 0x1fU)) + 0x736;
    local_54 = 0;
    local_6c = local_14;
    if (local_50 != 0) {
      do {
        *local_6c = 0x400;
        local_54 = local_54 + 1;
        local_6c = local_6c + 1;
      } while (local_54 < local_50);
    }
    local_34 = 1;
    local_30 = 1;
    local_2c = 1;
    uVar6 = 1;
    local_3c = 0;
    local_40 = 0;
    iVar5 = 0;
    uVar7 = 0;
    local_44[local_48 - 1] = 0;
    FUN_0041e7c0(&local_88);
    if (local_74 == 0) {
      if (local_70 == 0) {
        local_38 = 0;
        goto LAB_0041ecb1;
      }
      local_74 = 1;
    }
  }
  return local_74;
code_r0x0041eeb1:
  if (local_40 == 0) {
    return 1;
  }
  if (iVar5 < 7) {
    iVar5 = 9;
  }
  else {
    iVar5 = 0xb;
  }
  uVar4 = uVar7 - uVar6;
  if (local_48 <= uVar4) {
    uVar4 = uVar4 + local_48;
  }
  local_19 = local_44[uVar4];
  local_44[uVar7] = local_19;
  uVar7 = uVar7 + 1;
  if (uVar7 == local_48) {
    uVar7 = 0;
  }
  *(byte *)local_6c = local_19;
  local_18 = local_18 + 1;
  if (local_40 < local_48) {
    local_40 = local_40 + 1;
  }
  goto LAB_0041ed24;
}



int FUN_0041f1a4(uint *param_1,int param_2,byte *param_3,uint *param_4,int *param_5,int param_6)

{
  int iVar1;
  
  if (param_2 == 0x50) {
    iVar1 = FUN_0041ea88(param_1,param_3,param_6);
    if (iVar1 == 0) {
      *param_5 = ((0x300 << ((char)*param_1 + (char)param_1[1] & 0x1fU)) + 0x736) * 2;
      *param_4 = param_1[3];
    }
  }
  else {
    iVar1 = 1;
  }
  return iVar1;
}



void FUN_0041f1f4(int param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)(param_1 + 0x10) = param_2;
  *(undefined4 *)(param_1 + 0x1c) = param_3;
  *(undefined4 *)(param_1 + 0x48) = 0xfffffffe;
  return;
}



void FUN_0041f204(int param_1,longlong *param_2,int param_3,int param_4,int param_5)

{
  undefined *puVar1;
  longlong *plVar2;
  int iVar3;
  int iVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  uint local_18;
  int local_14;
  longlong *local_10;
  longlong *local_c;
  longlong *local_8;
  
  puStack_28 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  local_c = (longlong *)0x0;
  puStack_2c = &LAB_0041f303;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  iVar4 = param_5;
  puVar1 = &stack0xfffffffc;
  local_14 = param_3;
  local_10 = param_2;
  if (0 < param_5) {
    do {
      FUN_0041df50(param_1,(longlong *)&local_18,4);
      iVar3 = (int)local_18 >> 1;
      if (iVar3 < 0) {
        iVar3 = iVar3 + (uint)((local_18 & 1) != 0);
      }
      FUN_004072d0(&local_8,iVar3);
      if (local_18 != 0) {
        plVar2 = thunk_FUN_00406f14(&local_8);
        FUN_0041df50(param_1,plVar2,local_18);
      }
      FUN_00406dfc((longlong **)param_2,local_8);
      param_2 = (longlong *)((int)param_2 + 4);
      iVar4 = iVar4 + -1;
      puVar1 = puStack_28;
    } while (iVar4 != 0);
  }
  puStack_28 = puVar1;
  iVar4 = param_4;
  if (0 < param_4) {
    do {
      FUN_0041df50(param_1,(longlong *)&local_18,4);
      FUN_004070f8(&local_c,local_18,0);
      if (local_18 != 0) {
        plVar2 = thunk_FUN_00406f58(&local_c);
        FUN_0041df50(param_1,plVar2,local_18);
      }
      FUN_00406e98((longlong **)param_2,local_c);
      param_2 = (longlong *)((int)param_2 + 4);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  FUN_0041df50(param_1,param_2,local_14 + (param_5 + param_4) * -4);
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_0041f30a;
  puStack_2c = (undefined *)0x41f2fa;
  FUN_00406b4c((int *)&local_c);
  puStack_2c = (undefined *)0x41f302;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_00420134(longlong *param_1,int param_2,int param_3,longlong **param_4)

{
  longlong *plVar1;
  int iVar2;
  ushort *puVar3;
  longlong *plVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  longlong *local_18;
  ushort local_12;
  int local_10;
  int local_c;
  longlong *local_8;
  
  puStack_28 = &stack0xfffffffc;
  local_18 = (longlong *)0x0;
  local_8 = (longlong *)0x0;
  puStack_2c = &LAB_0042023b;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  local_10 = param_3;
  local_c = param_2;
  FUN_00406b28((int *)param_4);
  if (param_1 != (longlong *)0x0) {
    while( true ) {
      plVar1 = (longlong *)thunk_FUN_00415dde((short *)param_1,0x25);
      if (plVar1 == (longlong *)0x0) break;
      plVar4 = param_1;
      if (param_1 != plVar1) {
        iVar2 = (int)plVar1 - (int)param_1 >> 1;
        if (iVar2 < 0) {
          iVar2 = iVar2 + (uint)(((int)plVar1 - (int)param_1 & 1U) != 0);
        }
        FUN_00406c80(&local_8,param_1,iVar2);
        FUN_00407350(param_4,local_8);
        plVar4 = plVar1;
      }
      puVar3 = (ushort *)((int)plVar1 + 2);
      local_12 = *puVar3;
      if (((ushort)(local_12 - 0x31) < 9) && ((int)(*puVar3 - 0x31) <= local_10)) {
        FUN_00407350(param_4,*(longlong **)(local_c + -0xc4 + (uint)*puVar3 * 4));
        param_1 = (longlong *)((int)plVar4 + 4);
      }
      else {
        FUN_00407350(param_4,(longlong *)&DAT_00420258);
        param_1 = (longlong *)((int)plVar4 + 2);
        if (*puVar3 == 0x25) {
          param_1 = (longlong *)((int)plVar4 + 4);
        }
      }
    }
    FUN_0040723c(&local_18,param_1);
    FUN_00407350(param_4,local_18);
  }
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_00420242;
  puStack_2c = (undefined *)0x420232;
  FUN_00406b28((int *)&local_18);
  puStack_2c = (undefined *)0x42023a;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_0042025c(uint param_1,int param_2,int param_3,longlong **param_4)

{
  longlong *plVar1;
  
  plVar1 = (longlong *)FUN_004071e4(*(int *)(&DAT_0042ec3c + (param_1 & 0xff) * 4));
  FUN_00420134(plVar1,param_2,param_3,param_4);
  return;
}



void FUN_0042028c(uint param_1,undefined4 param_2,longlong **param_3)

{
  undefined4 local_10;
  
  local_10 = param_2;
  FUN_0042025c(param_1,(int)&local_10,0,param_3);
  return;
}



void FUN_004202b0(void)

{
  char cVar1;
  int *piVar2;
  
  cVar1 = -0x23;
  piVar2 = (int *)&DAT_0042ec3c;
  do {
    FUN_00406b28(piVar2);
    piVar2 = piVar2 + 1;
    cVar1 = cVar1 + -1;
  } while (cVar1 != '\0');
  return;
}



void FUN_004202cc(void)

{
  int *piVar1;
  
  piVar1 = FUN_00418ac8((int *)&PTR_LAB_00412e58,'\x01',
                        (longlong *)
                        L"The setup files are corrupted. Please obtain a new copy of the program.");
  FUN_004062cc((int)piVar1);
  return;
}



void FUN_00420380(int *param_1,uint param_2)

{
  int iVar1;
  uint uVar2;
  char cVar3;
  longlong *plVar4;
  longlong *plVar5;
  longlong **pplVar6;
  bool bVar7;
  
  bVar7 = param_2 == 0x50;
  if (0x50 < param_2) {
    FUN_00406fb4(param_1,(int *)PTR_s_Inno_Setup_Messages__5_5_3___u__0042858c,0x40);
    if (bVar7) goto LAB_004203a7;
  }
  FUN_004202cc();
LAB_004203a7:
  if (((param_1[0x11] != ~param_1[0x12]) || (param_2 != param_1[0x11])) || (param_1[0x10] != 0xdd))
  {
    FUN_004202cc();
  }
  plVar4 = (longlong *)(param_1 + 0x14);
  plVar5 = (longlong *)((int)param_1 + param_1[0x11]);
  iVar1 = (int)plVar5 - (int)plVar4 >> 1;
  if (iVar1 < 0) {
    iVar1 = iVar1 + (uint)(((int)plVar5 - (int)plVar4 & 1U) != 0);
  }
  uVar2 = FUN_0041db58((byte *)plVar4,iVar1 * 2);
  if ((uVar2 != param_1[0x13]) || (*(short *)((int)plVar5 + -2) != 0)) {
    FUN_004202cc();
  }
  cVar3 = -0x23;
  pplVar6 = (longlong **)&DAT_0042ec3c;
  do {
    if (plVar5 <= plVar4) {
      FUN_004202cc();
    }
    iVar1 = FUN_00406f00((int)plVar4);
    FUN_00406c80(pplVar6,plVar4,iVar1);
    plVar4 = (longlong *)((int)plVar4 + (iVar1 + 1) * 2);
    pplVar6 = pplVar6 + 1;
    cVar3 = cVar3 + -1;
  } while (cVar3 != '\0');
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00420438(void)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_10;
  undefined *puStack_c;
  undefined *puStack_8;
  
  puStack_8 = &stack0xfffffffc;
  puStack_c = &LAB_00420479;
  uStack_10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10;
  _DAT_0042efb0 = _DAT_0042efb0 + 1;
  if (_DAT_0042efb0 == 0) {
    FUN_004202b0();
    FUN_00407970((int **)&DAT_0042ec3c,"\x12\x06string\x02",0xdd);
  }
  *in_FS_OFFSET = uStack_10;
  return;
}



bool FUN_00420484(char param_1,undefined *param_2)

{
  char cVar1;
  int iVar2;
  
  *param_2 = 0;
  if (param_1 == '\0') {
    return true;
  }
  if (DAT_0042efc0 == '\0') {
    SetLastError(1);
    cVar1 = '\0';
  }
  else {
    iVar2 = (*DAT_0042efb8)();
    cVar1 = '\x01' - (iVar2 == 0);
    if (cVar1 != '\0') {
      *param_2 = 1;
    }
  }
  return (bool)cVar1;
}



void FUN_004204c0(char *param_1)

{
  if (*param_1 != '\0') {
    (*DAT_0042efbc)();
  }
  return;
}



undefined4 FUN_004204d0(char param_1,int param_2)

{
  bool bVar1;
  LPCWSTR lpFileName;
  undefined4 uVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  char local_10 [8];
  BOOL local_8;
  
  puStack_20 = (undefined *)0x4204e6;
  bVar1 = FUN_00420484(param_1,local_10);
  if (!bVar1) {
    return 0;
  }
  puStack_24 = &LAB_0042052d;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  puStack_20 = &stack0xfffffffc;
  lpFileName = (LPCWSTR)FUN_004071e4(param_2);
  local_8 = DeleteFileW(lpFileName);
  GetLastError();
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &DAT_00420534;
  puStack_24 = (undefined *)0x42052c;
  uVar2 = FUN_004204c0(local_10);
  return uVar2;
}



undefined4 FUN_00420548(char param_1,longlong *param_2)

{
  bool bVar1;
  undefined4 uVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  char local_10 [11];
  undefined local_5;
  
  puStack_20 = (undefined *)0x42055e;
  bVar1 = FUN_00420484(param_1,local_10);
  if (!bVar1) {
    return 0;
  }
  puStack_24 = &LAB_0042059e;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  puStack_20 = &stack0xfffffffc;
  uVar2 = FUN_0041bc9c(param_2);
  local_5 = (undefined)uVar2;
  GetLastError();
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &DAT_004205a5;
  puStack_24 = (undefined *)0x42059d;
  uVar2 = FUN_004204c0(local_10);
  return uVar2;
}



void FUN_004205c0(uint param_1,longlong **param_2)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  longlong *local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_1c = &LAB_00420628;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  FUN_00406b28((int *)param_2);
  iVar1 = 5;
  do {
    FUN_004071fc(&local_8,(uint)(ushort)u_0123456789ABCDEFGHIJKLMNOPQRSTUV_004283cc[param_1 & 0x1f])
    ;
    FUN_00407528(local_8,param_2,1);
    param_1 = param_1 >> 5;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_0042062f;
  puStack_1c = (undefined *)0x420627;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_00420638(char param_1,longlong *param_2,undefined4 param_3,longlong **param_4)

{
  uint uVar1;
  undefined4 uVar2;
  int *piVar3;
  uint uVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_38;
  undefined *puStack_34;
  undefined *puStack_30;
  longlong *local_20;
  longlong *local_1c;
  longlong *local_18;
  longlong *local_14;
  undefined4 local_10;
  longlong *local_c;
  longlong *local_8;
  
  local_c = (longlong *)0x0;
  local_14 = (longlong *)0x0;
  local_18 = (longlong *)0x0;
  local_1c = (longlong *)0x0;
  local_20 = (longlong *)0x0;
  puStack_30 = (undefined *)0x42065c;
  local_10 = param_3;
  local_8 = param_2;
  FUN_00406c0c((int)param_2);
  puStack_34 = &LAB_0042072f;
  uStack_38 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_38;
  puStack_30 = &stack0xfffffffc;
  FUN_0041b87c(local_8,&local_14);
  FUN_00406e44((int *)&local_8,(int)local_14);
  uVar1 = FUN_004047c8(0x2000000);
  uVar4 = uVar1;
  do {
    uVar4 = uVar4 + 1;
    if (0x1ffffff < (int)uVar4) {
      uVar4 = 0;
    }
    if (uVar1 == uVar4) {
      uVar2 = FUN_0041bbc8(local_8,&local_1c);
      FUN_0042028c(CONCAT31((int3)((uint)uVar2 >> 8),0x4c),local_1c,&local_18);
      piVar3 = FUN_00418ac8((int *)&PTR_LAB_00412e58,'\x01',local_18);
      FUN_004062cc((int)piVar3);
    }
    FUN_004205c0(uVar4,&local_20);
    uStack_38 = local_10;
    FUN_00407430(&local_c,4);
    uVar2 = FUN_00420548(param_1,local_c);
  } while ((char)uVar2 != '\0');
  FUN_00406dfc(param_4,local_c);
  *in_FS_OFFSET = uStack_38;
  FUN_00406b88((int *)&local_20,4);
  FUN_00406b88((int *)&local_c,2);
  return;
}



void FUN_00420754(longlong **param_1)

{
  char cVar1;
  LPCWSTR pWVar2;
  BOOL BVar3;
  DWORD DVar4;
  undefined4 *in_FS_OFFSET;
  longlong **pplVar5;
  LPSECURITY_ATTRIBUTES p_Var6;
  undefined4 uStack_2c;
  undefined *puStack_28;
  undefined *puStack_24;
  longlong *local_18;
  longlong *local_14;
  longlong *local_10;
  longlong *local_c;
  longlong *local_8;
  
  puStack_24 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  local_c = (longlong *)0x0;
  local_10 = (longlong *)0x0;
  local_14 = (longlong *)0x0;
  local_18 = (longlong *)0x0;
  puStack_28 = &LAB_00420834;
  uStack_2c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_2c;
  FUN_0041bf8c(&local_8);
  pplVar5 = (longlong **)0x42077d;
  cVar1 = FUN_0041c47c();
  if (cVar1 != '\0') {
    FUN_0041bf34(&local_c);
    FUN_0041b87c(local_c,&local_18);
    FUN_004073a8(&local_10,local_18,(longlong *)L"TempInst");
    p_Var6 = (LPSECURITY_ATTRIBUTES)0x0;
    pWVar2 = (LPCWSTR)FUN_004071e4((int)local_10);
    BVar3 = CreateDirectoryW(pWVar2,p_Var6);
    if (BVar3 == 0) {
      pplVar5 = (longlong **)0x4207ce;
      DVar4 = GetLastError();
      if (DVar4 == 0xb7) {
        pplVar5 = &local_14;
        FUN_00420638('\0',local_c,L".tmp",pplVar5);
        p_Var6 = (LPSECURITY_ATTRIBUTES)0x0;
        pWVar2 = (LPCWSTR)FUN_004071e4((int)local_14);
        BVar3 = CreateDirectoryW(pWVar2,p_Var6);
        if (BVar3 != 0) {
          RemoveDirectoryW(pWVar2);
          FUN_00406e44((int *)&local_8,(int)local_10);
        }
      }
    }
    else {
      pplVar5 = (longlong **)0x4207c7;
      FUN_00406e44((int *)&local_8,(int)local_10);
    }
  }
  FUN_00406dfc(param_1,local_8);
  *in_FS_OFFSET = pplVar5;
  puStack_28 = &LAB_0042083b;
  uStack_2c = 0x420833;
  FUN_00406b88((int *)&local_18,5);
  return;
}



// WARNING: Type propagation algorithm not settling

void FUN_0042087c(longlong **param_1)

{
  LPCWSTR lpPathName;
  BOOL BVar1;
  DWORD DVar2;
  int *piVar3;
  int iVar4;
  undefined4 extraout_ECX;
  longlong **in_FS_OFFSET;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  longlong **pplVar5;
  longlong *plVar6;
  undefined8 local_24;
  longlong *local_1c;
  longlong *local_10;
  longlong *local_c;
  longlong *local_8;
  
  local_1c = (longlong *)&stack0xfffffffc;
  iVar4 = 4;
  do {
    local_8 = (longlong *)0x0;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  local_24._4_4_ = (longlong *)&LAB_00420971;
  local_24._0_4_ = *in_FS_OFFSET;
  *in_FS_OFFSET = &local_24;
  local_10 = (longlong *)0x0;
  while( true ) {
    plVar6 = (longlong *)&local_8;
    FUN_00420754(&local_c);
    FUN_00420638('\0',local_c,L".tmp",(longlong **)plVar6);
    lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
    lpPathName = (LPCWSTR)FUN_004071e4((int)local_8);
    BVar1 = CreateDirectoryW(lpPathName,lpSecurityAttributes);
    if (BVar1 != 0) break;
    DVar2 = GetLastError();
    if (DVar2 != 0xb7) {
      pplVar5 = &local_10;
      FUN_0042028c(CONCAT31((int3)((uint)pplVar5 >> 8),0x36),local_8,
                   (longlong **)((int)&local_24 + 4));
      local_1c = local_24._4_4_;
      FUN_00415740((longlong **)&local_24,0,extraout_ECX,DVar2,0);
      FUN_0041c758(DVar2,(longlong **)&stack0xffffffd8);
      FUN_0042025c(CONCAT31((int3)((uint)plVar6 >> 8),0x68),(int)&local_1c,2,pplVar5);
      piVar3 = FUN_00418ac8((int *)&PTR_LAB_00412e58,'\x01',local_10);
      FUN_004062cc((int)piVar3);
    }
  }
  FUN_00406dfc(param_1,local_8);
  *in_FS_OFFSET = (longlong *)local_24;
  local_24._4_4_ = (longlong *)&LAB_00420978;
  local_24._0_4_ = (longlong *)0x420963;
  FUN_00406b88((int *)&stack0xffffffd8,3);
  local_24._0_4_ = (longlong *)0x420970;
  FUN_00406b88((int *)&local_10,3);
  return;
}



BOOL __stdcall
AdjustTokenPrivileges
          (HANDLE TokenHandle,BOOL DisableAllPrivileges,PTOKEN_PRIVILEGES NewState,
          DWORD BufferLength,PTOKEN_PRIVILEGES PreviousState,PDWORD ReturnLength)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00420998. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = AdjustTokenPrivileges
                    (TokenHandle,DisableAllPrivileges,NewState,BufferLength,PreviousState,
                     ReturnLength);
  return BVar1;
}



bool FUN_004209a0(void)

{
  int iVar1;
  HANDLE ProcessHandle;
  BOOL BVar2;
  DWORD DVar3;
  HANDLE *TokenHandle;
  HANDLE local_14;
  _TOKEN_PRIVILEGES local_10;
  
  iVar1 = FUN_00419bc4();
  TokenHandle = &local_14;
  if (iVar1 == 2) {
    DVar3 = 0x28;
    ProcessHandle = GetCurrentProcess();
    BVar2 = OpenProcessToken(ProcessHandle,DVar3,TokenHandle);
    if (BVar2 == 0) {
      return false;
    }
    LookupPrivilegeValueW((LPCWSTR)0x0,L"SeShutdownPrivilege",&local_10.Privileges[0].Luid);
    local_10.PrivilegeCount = 1;
    local_10.Privileges[0].Attributes = 2;
    AdjustTokenPrivileges(local_14,0,&local_10,0,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0);
    DVar3 = GetLastError();
    if (DVar3 != 0) {
      return false;
    }
  }
  BVar2 = ExitWindowsEx(2,0);
  return (bool)('\x01' - (BVar2 == 0));
}



void FUN_00420a44(char param_1,int param_2,int param_3,DWORD param_4,DWORD param_5)

{
  int iVar1;
  DWORD DVar2;
  int iVar3;
  
  if (-1 < param_3 + -1) {
    iVar3 = 0;
    do {
      if (iVar3 == 1) {
        Sleep(param_5);
      }
      else if (1 < iVar3) {
        Sleep(param_4);
      }
      iVar1 = FUN_004204d0(param_1,param_2);
      if (iVar1 != 0) {
        return;
      }
      DVar2 = GetLastError();
      if (DVar2 == 2) {
        return;
      }
      DVar2 = GetLastError();
      if (DVar2 == 3) {
        return;
      }
      iVar3 = iVar3 + 1;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
  }
  return;
}



undefined4 FUN_00420aa8(uint param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 local_8;
  
  local_8 = param_3;
  iVar1 = GetLocaleInfoW(param_1 & 0xffff,0x20001004,(LPWSTR)&local_8,2);
  if (iVar1 < 1) {
    local_8 = 0xffffffff;
  }
  return local_8;
}



undefined FUN_00420ad4(undefined *param_1,char param_2,int param_3,int *param_4)

{
  char cVar1;
  LANGID LVar2;
  undefined2 extraout_var;
  int iVar3;
  int iVar4;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_EDX;
  int iVar5;
  ushort uVar6;
  uint uVar7;
  int *local_c;
  undefined local_6;
  char local_5;
  
  *param_4 = 0;
  local_6 = 0;
  local_5 = param_2;
  if (param_3 != 0) {
    iVar5 = 0;
    while (cVar1 = (*(code *)param_1)(iVar5,&local_c), cVar1 != '\0') {
      uVar7 = FUN_004151dc(param_3,*local_c);
      if (uVar7 == 0) {
        *param_4 = iVar5;
        return 2;
      }
      iVar5 = iVar5 + 1;
    }
  }
  if (local_5 == '\0') {
    uVar7 = FUN_0041c488();
  }
  else if (local_5 == '\x01') {
    LVar2 = GetUserDefaultLangID();
    uVar7 = CONCAT22(extraout_var,LVar2);
  }
  else {
    uVar7 = 0;
  }
  uVar6 = (ushort)uVar7;
  if (uVar6 != 0) {
    iVar5 = 0;
    while (cVar1 = (*(code *)param_1)(iVar5,&local_c), cVar1 != '\0') {
      if (local_c[10] == (uVar7 & 0xffff)) {
        *param_4 = iVar5;
        return 1;
      }
      iVar5 = iVar5 + 1;
    }
    iVar5 = 0;
    while (cVar1 = (*(code *)param_1)(iVar5,&local_c), cVar1 != '\0') {
      if ((local_c[10] & 0x3ffU) == (uint)(uVar6 & 0x3ff)) {
        if ((uVar6 & 0x3ff) != 4) {
LAB_00420bb5:
          *param_4 = iVar5;
          return 1;
        }
        iVar3 = FUN_00420aa8((uint)*(ushort *)(local_c + 10),(uint)(uVar6 & 0x3ff),extraout_ECX_00);
        iVar4 = FUN_00420aa8(uVar7,extraout_EDX,extraout_ECX);
        if (iVar3 == iVar4) goto LAB_00420bb5;
      }
      iVar5 = iVar5 + 1;
    }
  }
  return local_6;
}



void FUN_00420bdc(uint param_1)

{
  DWORD DVar1;
  int *piVar2;
  undefined4 extraout_ECX;
  undefined4 *in_FS_OFFSET;
  longlong **pplVar3;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  longlong *local_1c;
  longlong *local_18;
  undefined4 local_14;
  longlong *local_10;
  longlong *local_c;
  longlong *local_8;
  
  puStack_28 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  local_18 = (longlong *)0x0;
  local_1c = (longlong *)0x0;
  puStack_2c = &LAB_00420c83;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  DVar1 = GetLastError();
  pplVar3 = &local_8;
  local_14 = *(undefined4 *)(PTR_DAT_00428580 + (param_1 & 0xff) * 4);
  FUN_00415740(&local_18,0,extraout_ECX,DVar1,0);
  local_10 = local_18;
  FUN_0041c758(DVar1,&local_1c);
  local_c = local_1c;
  FUN_0042025c(CONCAT31((int3)((uint)local_1c >> 8),0x68),(int)&local_14,2,pplVar3);
  piVar2 = FUN_00418ac8((int *)&PTR_LAB_00412e58,'\x01',local_8);
  FUN_004062cc((int)piVar2);
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_00420c8a;
  puStack_2c = (undefined *)0x420c7a;
  FUN_00406b88((int *)&local_1c,2);
  puStack_2c = (undefined *)0x420c82;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_00420d00(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  longlong *local_10;
  longlong *local_c;
  longlong *local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  local_c = (longlong *)0x0;
  local_10 = (longlong *)0x0;
  puStack_20 = &LAB_00420e04;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  iVar1 = FUN_0041be30();
  if (0 < iVar1) {
    iVar3 = 1;
    do {
      FUN_0041be90(iVar3,&local_8);
      uVar2 = FUN_004151dc((int)local_8,(int)L"/SP-");
      if (uVar2 == 0) {
LAB_00420d6f:
        u_0123456789ABCDEFGHIJKLMNOPQRSTUV_004283cc[32]._1_1_ = 1;
      }
      else {
        FUN_004074e0((int)local_8,1,10,&local_c);
        uVar2 = FUN_004151dc((int)local_c,(int)L"/SPAWNWND=");
        if (uVar2 == 0) goto LAB_00420d6f;
        FUN_004074e0((int)local_8,1,6,&local_10);
        uVar2 = FUN_004151dc((int)local_10,(int)L"/Lang=");
        if (uVar2 == 0) {
          FUN_004074e0((int)local_8,7,0x7fffffff,(longlong **)&DAT_0042efc4);
        }
        else {
          uVar2 = FUN_004151dc((int)local_8,(int)L"/HELP");
          if (uVar2 != 0) {
            uVar2 = FUN_004151dc((int)local_8,(int)&LAB_00420e90);
            if (uVar2 != 0) goto LAB_00420de1;
          }
          u_0123456789ABCDEFGHIJKLMNOPQRSTUV_004283cc[32]._0_1_ = 1;
        }
      }
LAB_00420de1:
      iVar3 = iVar3 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  *in_FS_OFFSET = uStack_24;
  puStack_1c = &LAB_00420e0b;
  puStack_20 = (undefined *)0x420e03;
  FUN_00406b88((int *)&local_10,3);
  return;
}



void FUN_00420f04(undefined4 param_1,undefined4 param_2,int param_3)

{
  int local_4;
  
  local_4 = param_3;
  FUN_00420ad4(&LAB_00420ee4,DAT_0042f0d1,DAT_0042efc4,&local_4);
  func_0x00420e98(local_4);
  return;
}



LRESULT FUN_00420f28(undefined param_1,undefined param_2,undefined param_3,HWND param_4,UINT param_5
                    ,WPARAM param_6,LPARAM param_7)

{
  LRESULT LVar1;
  
  LVar1 = 0;
  if (param_5 != 0x11) {
    if (param_5 == 0x496) {
      if (param_6 == 10000) {
        DAT_00428420 = 1;
      }
      else if (param_6 == 0x2711) {
        DAT_00428414 = param_7;
      }
    }
    else {
      LVar1 = CallWindowProcW(DAT_0042f0f0,param_4,param_5,param_6,param_7);
    }
  }
  return LVar1;
}



void FUN_00420f88(void)

{
  BOOL BVar1;
  MSG MStack_20;
  
  while( true ) {
    BVar1 = PeekMessageW(&MStack_20,(HWND)0x0,0,0,1);
    if (BVar1 == 0) break;
    TranslateMessage(&MStack_20);
    DispatchMessageW(&MStack_20);
  }
  return;
}



void FUN_00420fb4(undefined4 param_1,undefined4 param_2,LPDWORD param_3)

{
  LPWSTR lpCommandLine;
  undefined4 *in_FS_OFFSET;
  LPSECURITY_ATTRIBUTES lpProcessAttributes;
  LPSECURITY_ATTRIBUTES lpThreadAttributes;
  BOOL BVar1;
  DWORD DVar2;
  LPVOID lpEnvironment;
  LPCWSTR lpCurrentDirectory;
  _STARTUPINFOW *lpStartupInfo;
  _PROCESS_INFORMATION *lpProcessInformation;
  undefined4 uStack_74;
  undefined *puStack_70;
  undefined *puStack_6c;
  _PROCESS_INFORMATION local_5c;
  _STARTUPINFOW local_4c;
  longlong *local_8;
  
  puStack_6c = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  puStack_70 = &lpProcessInformation_00421089;
  uStack_74 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_74;
  FUN_00407430(&local_8,4);
  FUN_004048f8((double *)&local_4c,0x44,0);
  local_4c.cb = 0x44;
  lpProcessInformation = &local_5c;
  lpStartupInfo = &local_4c;
  lpCurrentDirectory = (LPCWSTR)0x0;
  lpEnvironment = (LPVOID)0x0;
  DVar2 = 0;
  BVar1 = 0;
  lpThreadAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  lpProcessAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  lpCommandLine = (LPWSTR)FUN_004071e4((int)local_8);
  BVar1 = CreateProcessW((LPCWSTR)0x0,lpCommandLine,lpProcessAttributes,lpThreadAttributes,BVar1,
                         DVar2,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);
  if (BVar1 == 0) {
    FUN_00420bdc(0x6a);
  }
  CloseHandle(local_5c.hThread);
  do {
    FUN_00420f88();
    DVar2 = MsgWaitForMultipleObjects(1,&local_5c.hProcess,0,0xffffffff,0x4ff);
  } while (DVar2 == 1);
  FUN_00420f88();
  GetExitCodeProcess(local_5c.hProcess,param_3);
  CloseHandle(local_5c.hProcess);
  *in_FS_OFFSET = param_2;
  FUN_00406b28((int *)&local_8);
  return;
}



void FUN_004210bc(void)

{
  int *piVar1;
  
  if (*(int *)(PTR_DAT_00428580 + 0x278) != 0) {
    piVar1 = FUN_00418ac8((int *)&PTR_LAB_00412e58,'\x01',*(longlong **)(PTR_DAT_00428580 + 0x278));
    FUN_004062cc((int)piVar1);
    return;
  }
  piVar1 = FUN_00418ac8((int *)&PTR_LAB_00412e58,'\x01',
                        (longlong *)
                        L"The setup files are corrupted. Please obtain a new copy of the program.");
  FUN_004062cc((int)piVar1);
  return;
}



void FUN_0042119c(undefined4 *param_1)

{
  LOCK();
  *param_1 = *param_1;
  UNLOCK();
  return;
}



void FUN_004211a4(LPCVOID param_1)

{
  bool bVar1;
  SIZE_T SVar2;
  BOOL BVar3;
  uint uVar4;
  DWORD local_54;
  _SYSTEM_INFO local_50;
  _MEMORY_BASIC_INFORMATION local_2c;
  
  GetSystemInfo(&local_50);
  SVar2 = VirtualQuery(param_1,&local_2c,0x1c);
  while ((SVar2 != 0 && (local_2c.AllocationBase == param_1))) {
    if ((local_2c.State == 0x1000) && ((local_2c.Protect & 0x100) == 0)) {
      bVar1 = false;
      if (((((local_2c.Protect == 1) || (local_2c.Protect == 2)) || (local_2c.Protect == 0x10)) ||
          (local_2c.Protect == 0x20)) &&
         (BVar3 = VirtualProtect(local_2c.BaseAddress,local_2c.RegionSize,0x40,&local_54),
         BVar3 != 0)) {
        bVar1 = true;
      }
      for (uVar4 = 0; uVar4 < local_2c.RegionSize; uVar4 = uVar4 + local_50.dwPageSize) {
        FUN_0042119c((undefined4 *)((int)local_2c.BaseAddress + uVar4));
      }
      if (bVar1) {
        VirtualProtect(local_2c.BaseAddress,local_2c.RegionSize,local_54,&local_54);
      }
    }
    SVar2 = VirtualQuery((LPCVOID)((int)local_2c.BaseAddress + local_2c.RegionSize),&local_2c,0x1c);
  }
  return;
}



LPVOID FUN_00421278(void)

{
  HRSRC hResInfo;
  DWORD DVar1;
  HGLOBAL hResData;
  LPVOID pvVar2;
  
  hResInfo = FindResourceW((HMODULE)0x0,(LPCWSTR)0x2b67,(LPCWSTR)0xa);
  if (hResInfo == (HRSRC)0x0) {
    FUN_004210bc();
  }
  DVar1 = SizeofResource((HMODULE)0x0,hResInfo);
  if (DVar1 != 0x2c) {
    FUN_004210bc();
  }
  hResData = LoadResource((HMODULE)0x0,hResInfo);
  if (hResData == (HGLOBAL)0x0) {
    FUN_004210bc();
  }
  pvVar2 = LockResource(hResData);
  if (pvVar2 == (LPVOID)0x0) {
    FUN_004210bc();
  }
  return pvVar2;
}



void FUN_004212cc(void)

{
  LPCWSTR lpText;
  undefined4 *in_FS_OFFSET;
  wchar_t *lpCaption;
  UINT uType;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  int local_8;
  
  puStack_c = &stack0xfffffffc;
  local_8 = 0;
  puStack_10 = &LAB_00421319;
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  FUN_00406e44(&local_8,(int)
                        L"The Setup program accepts optional command line parameters.\r\n\r\n/HELP, /?\r\nShows this information.\r\n/SP-\r\nDisables the This will install... Do you wish to continue? prompt at the beginning of Setup.\r\n/SILENT, /VERYSILENT\r\nInstructs Setup to be silent or very silent.\r\n/SUPPRESSMSGBOXES\r\nInstructs Setup to suppress message boxes.\r\n/LOG\r\nCauses Setup to create a log file in the user\'s TEMP directory.\r\n/LOG=\"filename\"\r\nSame as /LOG, except it allows you to specify a fixed path/filename to use for the log file.\r\n/NOCANCEL\r\nPrevents the user from cancelling during the installation process.\r\n/NORESTART\r\nPrevents Setup from restarting the system following a successful installation, or after a Preparing to Install failure that requests a restart.\r\n/RESTARTEXITCODE=exit code\r\nSpecifies a custom exit code that Setup is to return when the system needs to be restarted.\r\n/CLOSEAPPLICATIONS\r\nInstructs Setup to close applications using files that need to be updated.\r\n/NOCLOSEAPPLICATIONS\r\nPrevents Setup from closing applications using files that need to be updated.\r\n/RESTARTAPPLICATIONS\r\nInstructs Setup to restart applications.\r\n/NORESTARTAPPLICATIONS\r\nPrevents Setup from restarting applications.\r\n/LOADINF=\"filename\"\r\nInstructs Setup to load the settings from the specified file after having checked the command line.\r\n/SAVEINF=\"filename\"\r\nInstructs Setup to save installation settings to the specified file.\r\n/LANG=language\r\nSpecifies the internal name of the language to use.\r\n/DIR=\"x:\\dirname\"\r\nOverrides the default directory name.\r\n/GROUP=\"folder name\"\r\nOverrides the default folder name.\r\n/NOICONS\r\nInstructs Setup to initially check the Don\'t create a Start Menu folder check box.\r\n/TYPE=type name\r\nOverrides the default setup type.\r\n/COMPONENTS=\"comma separated list of component names\"\r\nOverrides the default component settings.\r\n/TASKS=\"comma separated list of task names\"\r\nSpecifies a list of tasks that should be initially selected.\r\n/MERGETASKS=\"comma separated list of task names\"\r\nLike the /TASKS parameter, except the specified t..." /* TRUNCATED STRING LITERAL */
              );
  uType = 0x10;
  lpCaption = L"Setup";
  lpText = (LPCWSTR)FUN_004071e4(local_8);
  MessageBoxW((HWND)0x0,lpText,lpCaption,uType);
  *in_FS_OFFSET = uStack_14;
  puStack_c = &LAB_00421320;
  puStack_10 = (undefined *)0x421318;
  FUN_00406b28(&local_8);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00425000(void)

{
  WORD WVar1;
  undefined2 extraout_var;
  undefined4 *in_FS_OFFSET;
  bool bVar2;
  undefined4 uStack_10;
  undefined *puStack_c;
  undefined *puStack_8;
  
  puStack_8 = &stack0xfffffffc;
  puStack_c = &LAB_004250d7;
  uStack_10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10;
  bVar2 = _DAT_00429988 == 0;
  _DAT_00429988 = _DAT_00429988 + -1;
  if (bVar2) {
    FUN_00404be8();
    FUN_00404270();
    SetThreadLocale(0x400);
    FUN_004089c4();
    DAT_0042700c = 2;
    DAT_0042901c = &DAT_00402798;
    DAT_00429020 = &DAT_004027a0;
    DAT_00429056 = 2;
    _DAT_0042905c = FUN_0040abf0();
    _DAT_00429008 = &LAB_00408384;
    FUN_00404c24();
    FUN_00404c40();
    _DAT_00429064 = 0xd7b0;
    _DAT_00429340 = 0xd7b0;
    _DAT_0042961c = 0xd7b0;
    _DAT_0042904c = GetCommandLineW();
    WVar1 = FUN_004028d8();
    _DAT_00429048 = CONCAT22(extraout_var,WVar1);
    DAT_00429978 = GetACP();
    DAT_0042997c = 0x4b0;
    _DAT_00429040 = GetCurrentThreadId();
    FUN_0040ac04();
  }
  *in_FS_OFFSET = uStack_10;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00425a4c(void)

{
  undefined *puVar1;
  HMODULE pHVar2;
  undefined extraout_CL;
  undefined extraout_CL_00;
  undefined extraout_DL;
  undefined extraout_DL_00;
  HMODULE *in_FS_OFFSET;
  bool bVar3;
  HMODULE in_stack_ffffffd4;
  wchar_t *pwVar4;
  HINSTANCE__ HStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  longlong *local_10;
  longlong *local_c;
  longlong *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (longlong *)0x0;
  local_c = (longlong *)0x0;
  local_10 = (longlong *)0x0;
  puStack_18 = &LAB_00425b16;
  HStack_1c.unused = (int)*in_FS_OFFSET;
  *in_FS_OFFSET = &HStack_1c;
  bVar3 = _DAT_0042efb4 == 0;
  _DAT_0042efb4 = _DAT_0042efb4 + -1;
  puVar1 = &stack0xfffffffc;
  if (bVar3) {
    pwVar4 = L"Wow64DisableWow64FsRedirection";
    pHVar2 = GetModuleHandleW(L"kernel32.dll");
    DAT_0042efb8 = FUN_0040bdc0((char)pHVar2,extraout_DL,extraout_CL,pHVar2,pwVar4);
    pwVar4 = L"Wow64RevertWow64FsRedirection";
    in_stack_ffffffd4 = GetModuleHandleW(L"kernel32.dll");
    DAT_0042efbc = FUN_0040bdc0((char)in_stack_ffffffd4,extraout_DL_00,extraout_CL_00,
                                in_stack_ffffffd4,pwVar4);
    if ((DAT_0042efb8 == 0) || (DAT_0042efbc == 0)) {
      DAT_0042efc0 = 0;
    }
    else {
      DAT_0042efc0 = 1;
    }
    FUN_0041bf60(&local_c);
    FUN_0041b87c(local_c,&local_8);
    FUN_00407350(&local_8,(longlong *)L"shell32.dll");
    FUN_0041b0f0((int)local_8,0x8000);
    FUN_0041c758(0x4c783afb,&local_10);
    puVar1 = puStack_14;
  }
  puStack_14 = puVar1;
  *in_FS_OFFSET = in_stack_ffffffd4;
  FUN_00406b88((int *)&local_10,3);
  return;
}



void entry(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined uVar4;
  undefined4 uVar5;
  undefined *puStack_a8;
  undefined *puStack_a4;
  undefined4 uStack_9c;
  undefined *puStack_98;
  undefined *puStack_94;
  undefined4 uStack_84;
  undefined *puStack_80;
  undefined *puStack_7c;
  undefined4 uStack_78;
  undefined *puStack_74;
  undefined *puStack_70;
  uint local_28 [2];
  undefined local_20 [4];
  int local_1c;
  longlong *local_18 [5];
  
  puStack_7c = &stack0xfffffffc;
  local_18[0] = (longlong *)0x0;
  puStack_70 = (undefined *)0x425c10;
  FUN_0040b3c0((int)&DAT_004225a8);
  puStack_74 = &LAB_004262c2;
  uStack_78 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_78;
  puStack_80 = &LAB_0042627e;
  uStack_84 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_84;
  puStack_70 = &stack0xfffffffc;
  FUN_004211a4(DAT_0042c584);
  FUN_00420d00();
  if ((char)u_0123456789ABCDEFGHIJKLMNOPQRSTUV_004283cc[32] != '\0') {
    FUN_004212cc();
    FUN_00406a30(0);
  }
  FUN_0041be90(0,local_18);
  FUN_00406dfc((longlong **)&DAT_0042f0f4,local_18[0]);
  puStack_94 = (undefined *)0x425c7f;
  DAT_0042f0f8 = FUN_0041d1ac((int *)&PTR_LAB_0041cc80,'\x01',DAT_0042f0f4,1,0,2);
  *in_FS_OFFSET = &stack0xffffff70;
  puStack_94 = (undefined *)0x425c97;
  DAT_0042f100 = (byte *)FUN_00421278();
  uVar4 = *(int *)(DAT_0042f100 + 0xc) == 1;
  if ((bool)uVar4) {
    puStack_94 = (undefined *)0x425cb6;
    uVar1 = FUN_0041db58(DAT_0042f100,0x28);
    uVar4 = uVar1 == *(uint *)(DAT_0042f100 + 0x28);
    if ((bool)uVar4) {
      puStack_94 = (undefined *)0x425cce;
      (**(code **)(*DAT_0042f0f8 + 4))(DAT_0042f0f8,local_20);
      uVar4 = local_1c == 0;
      if (!(bool)uVar4) goto LAB_00425cf4;
      puStack_94 = (undefined *)0x425ce1;
      (**(code **)(*DAT_0042f0f8 + 4))(DAT_0042f0f8,local_28);
      uVar4 = local_28[0] == *(uint *)(DAT_0042f100 + 0x10);
      if (*(uint *)(DAT_0042f100 + 0x10) <= local_28[0]) goto LAB_00425cf4;
    }
  }
  puStack_94 = (undefined *)0x425cf4;
  FUN_004210bc();
LAB_00425cf4:
  puStack_94 = (undefined *)0x425d06;
  FUN_0041d16c(DAT_0042f0f8,*(undefined4 *)(DAT_0042f100 + 0x20));
  puStack_94 = (undefined *)0x425d1a;
  FUN_0041d144(DAT_0042f0f8,&DAT_0042f110,0x40);
  puStack_94 = (undefined *)0x425d2f;
  FUN_00406fb4((int *)&DAT_0042f110,(int *)PTR_s_Inno_Setup_Setup_Data__5_5_7___u_0042846c,0x40);
  if (!(bool)uVar4) {
    puStack_94 = (undefined *)0x425d36;
    FUN_004210bc();
  }
  puStack_98 = &LAB_00425dfb;
  uStack_9c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_9c;
  puStack_a4 = (undefined *)0x425d5c;
  puStack_94 = &stack0xfffffffc;
  DAT_0042f154 = FUN_0041dc74((int *)&DAT_0041d8f4,'\x01',DAT_0042f0f8,&PTR_FUN_0041e25c);
  puStack_a4 = &LAB_00425dea;
  puStack_a8 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_a8;
  uVar5 = 4;
  FUN_0041f204((int)DAT_0042f154,(longlong *)&DAT_0042efc8,0x11d,4,0x1c);
  DAT_0042f0ec = DAT_0042f048;
  DAT_0042f0e8 = FUN_004044a0(DAT_0042f048 * 0x3d);
  if (-1 < DAT_0042f0ec + -1) {
    iVar3 = 0;
    iVar2 = DAT_0042f0ec;
    do {
      uVar5 = 4;
      FUN_0041f204((int)DAT_0042f154,(longlong *)(DAT_0042f0e8 + iVar3 * 0x3d),0x3d,4,6);
      iVar3 = iVar3 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  *in_FS_OFFSET = uVar5;
  puStack_a8 = &LAB_00425df1;
  FUN_00404df4(DAT_0042f154);
  return;
}


