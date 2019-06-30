//
// WoL - run simple Windows programs on Linux
//
// Copyright(C) 2017-2019 Constantin Wiemer
//


#include <stdint.h>


// definition of the structures used in PE
// They were adapted from the ones provided by Microsoft in winnt.h. We can't just use winnt.h itself
// because there is a lot of stuff in it GCC or clang will choke on.
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS;
    
typedef struct {
    char Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    };
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct {
    uint16_t Hint;
    char Name[1];
} IMAGE_IMPORT_BY_NAME;
    
typedef struct {
    union {
        uint32_t ForwarderString;
        uint32_t Function;
        uint32_t Ordinal;
        uint32_t AddressOfData;
    };
} IMAGE_THUNK_DATA;
    
typedef struct {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;
    };
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1


// some useful macros
#define RVA_TO_PTR(imgbase, rva) ((void *) ((uint8_t *) rva) + imgbase)

// TODO: replace logmsg() with macros DEBUG(), INFO()...
#define DEBUG 10
#define INFO  20
#define WARN  30
#define ERROR 40
#define CRIT  50

// some constants
#define MAX_PATH_LEN 256
#define STACK_ADDR   0x00200000

// thunk for the switch to 32-bit mode
// The code was generated from thunk.s with
// `nasm -f bin thunk.s -o thunk.bin` and 
// `python3 -c 'import sys; data = open(sys.argv[1], "rb").read(); print(", ".join([hex(x) for x in data]))' thunk.bin`
// TODO: replace code with function call_entry_point()
#define THUNK_ADDR 0x00300000
static uint8_t THUNK_CODE[] = {0x55, 0x53, 0x48, 0x89, 0x24, 0x25, 0x40, 0x0, 0x30, 0x0, 0x68, 0x18, 0x0, 0x30, 0x0, 0xc7, 0x44, 0x24, 0x4, 0x23, 0x0, 0x0, 0x0, 0xcb, 0xbc, 0x0, 0x0, 0x30, 0x0, 0x16, 0x1f, 0xb8, 0x0, 0x10, 0x40, 0x0, 0xff, 0xd0, 0x6a, 0x0, 0x1f, 0x6a, 0x33, 0x68, 0x31, 0x0, 0x30, 0x0, 0xcb, 0x48, 0x8b, 0x24, 0x25, 0x40, 0x0, 0x30, 0x0, 0x5b, 0x5d, 0xc3, 0x90, 0x90, 0x90, 0x90, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde};