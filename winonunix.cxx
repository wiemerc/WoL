#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>


static const unsigned long PE_IMAGE_BASE = 0x00400000;

//
// necessary struct definitions (adapted from the ones provided by Microsoft in winnt.h)
//
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
    uint8_t Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;


//
// generate a hexdump from a buffer of bytes
//
void hexdump (const uint8_t *buffer, size_t length)
{
    size_t pos = 0;
    while (pos < length) {
        printf("%04lx: ", pos);
        char line[256], *p;
        size_t i, nchars;
        for (i = pos, p = line, nchars = 0; (i < pos + 16) && (i < length); ++i, ++p, ++nchars) {
            printf("%02x ", buffer[i]);
            if (buffer[i] >= 0x20 && buffer[i] <= 0x7e) {
                snprintf(p, 256 - nchars, "%c", buffer[i]);
            }
            else {
                snprintf(p, 256 - nchars, ".");
            }
        }
        if (nchars < 16) {
            for (size_t i = 1; i <= (3 * (16 - nchars)); ++i, ++p, ++nchars) {
                snprintf(p, 256 - nchars, " ");
            }
        }

        printf("\t%s\n", line);
        pos += 16;
    }
}


//
// main function
//
int main(int argc, char **argv)
{
    int                  fd, n;
    struct stat          sb;
    IMAGE_DOS_HEADER     *doshdr;
    IMAGE_NT_HEADERS     *nthdrs;
    IMAGE_SECTION_HEADER *sechdr;

    if ((fd = open(argv[1], O_RDONLY)) == -1) {
        perror("ERROR: could not open file");
        return 1;
    }
    if (fstat(fd, &sb) == -1) {
        perror("ERROR: could not get file status");
        close(fd);
        return 1;
    }
    if ((doshdr = (IMAGE_DOS_HEADER *) mmap((void *) PE_IMAGE_BASE, sb.st_size, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0)) == MAP_FAILED) {
        perror("ERROR: could not memory-map file");
        close(fd);
        return 1;
    }
    
    printf("executable mapped at address 0x%08x\n", (unsigned int) doshdr);
    printf("signature of DOS header: 0x%04x\n", doshdr->e_magic);
    nthdrs = (IMAGE_NT_HEADERS *) (((uint8_t *) doshdr) + doshdr->e_lfanew);
    printf("signature of NT headers: 0x%08x\n", nthdrs->Signature);
    printf("number of sections: %d\n", nthdrs->FileHeader.NumberOfSections);
    printf("image base address: 0x%08x\n", nthdrs->OptionalHeader.ImageBase);
    
    printf("sections in executable:\n");
    for (sechdr = (IMAGE_SECTION_HEADER *) (((uint8_t *) nthdrs) + sizeof(IMAGE_NT_HEADERS)), n = 1;
        n <= nthdrs->FileHeader.NumberOfSections;
        ++sechdr, ++n) {
        printf("%.8s at 0x%08x, will be mapped at 0x%08x\n", sechdr->Name,
               sechdr->PointerToRawData,
               sechdr->VirtualAddress + nthdrs->OptionalHeader.ImageBase);
        hexdump(((uint8_t *) doshdr) + sechdr->PointerToRawData, 16);
    }
    
    munmap ((void *) doshdr, sb.st_size);
    close (fd);
    return 0;
}
