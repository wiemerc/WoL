//
// WINONUX - run simple Windows programs on Unix (Linux and macOS)
//
// Copyright(C) 2017-2019 Constantin Wiemer
//


#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "winonux.h"


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
    int                  fd, n, prot;
    struct stat          sb;
    void                 *filebase;
    IMAGE_DOS_HEADER     *doshdr;
    IMAGE_NT_HEADERS     *nthdrs;
    IMAGE_SECTION_HEADER *sechdr;
    uint32_t             imgbase;
    int32_t              (*code)();
    void                 *data;

    // map whole executable into memory
    if ((fd = open(argv[1], O_RDONLY)) == -1) {
        perror("ERROR: could not open file");
        return 1;
    }
    if (fstat(fd, &sb) == -1) {
        perror("ERROR: could not get file status");
        close(fd);
        return 1;
    }
    if ((filebase = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
        perror("ERROR: could not memory-map file");
        close(fd);
        return 1;
    }
    printf("executable mapped at address 0x%08x\n", (unsigned int) filebase);
    
    doshdr = (IMAGE_DOS_HEADER *) filebase;
    printf("checking signature of DOS header... ");
    if (doshdr->e_magic == 0x5a4d) {
        printf("ok\n");
    }
    else {
        printf("not ok - aborting\n");
        goto cleanup;
    }
    
    nthdrs = (IMAGE_NT_HEADERS *) (((uint8_t *) filebase) + doshdr->e_lfanew);
    printf("checking signature of NT headers... ");
    if (nthdrs->Signature == 0x00004550) {
        printf("ok\n");
    }
    else {
        printf("not ok - aborting\n");
        goto cleanup;
    }
    printf("number of sections: %d\n", nthdrs->FileHeader.NumberOfSections);
    printf("image base address: 0x%08x\n", nthdrs->OptionalHeader.ImageBase);
    imgbase = nthdrs->OptionalHeader.ImageBase;
    
    printf("sections in executable:\n");
    for (sechdr = (IMAGE_SECTION_HEADER *) (((uint8_t *) nthdrs) + sizeof(IMAGE_NT_HEADERS)), n = 1;
        n <= nthdrs->FileHeader.NumberOfSections;
        ++sechdr, ++n) {
        void     *secptr  = (void *) (sechdr->PointerToRawData + (uint8_t *) filebase);
        void     *secbase = (void *) (sechdr->VirtualAddress + imgbase);
        uint32_t secsize  = sechdr->Misc.VirtualSize;
        
        printf("%.8s at %p, %d bytes large, will be mapped at %p\n",
               sechdr->Name,
               secptr,
               secsize,
               secbase);
        
        // create anonymous mapping at the corresponding address,
        // writeable so we can copy the data (see below)
        if (mmap(secbase,
                 secsize,
                 PROT_WRITE,
                 MAP_ANON | MAP_SHARED | MAP_FIXED,
                 -1,
                 0) == MAP_FAILED) {
            perror("could not create anonymous mapping");
            goto cleanup;
        }
        
        // copy section data to the mapped area
        // We copy the data because the offset is (normally) not a multiple
        // of the page size, so we can't use it in the mmap() call. We can't
        // use lseek() either, because mmap() seems to ignore the current position.
        memcpy(secbase, secptr, secsize);
        
        // set protection of mapped area depending on section name and perform
        // other section-specific actions
        if (strncmp((const char *) sechdr->Name, ".text", 8) == 0) {
            prot = PROT_READ | PROT_EXEC;
            code = (int32_t (*)()) secbase;
        }
        else if (strncmp((const char *) sechdr->Name, ".data", 8) == 0) {
            prot = PROT_READ | PROT_WRITE;
            data = secbase;
        }
        else if (strncmp((const char *) sechdr->Name, ".rdata", 8) == 0) {
            prot = PROT_READ;
        }
        else if (strncmp((const char *) sechdr->Name, ".idata", 8) == 0) {
            prot = PROT_READ | PROT_WRITE;
            
            // patch addresses of imported functions into the Import Address Table (IAT)
            printf("imported functions:\n");
            for (IMAGE_IMPORT_DESCRIPTOR *impdesc = (IMAGE_IMPORT_DESCRIPTOR *) secbase;
                impdesc->FirstThunk != 0; ++impdesc) {
                printf("%s\n", RVA_TO_PTR(impdesc->Name));
                for (IMAGE_IMPORT_BY_NAME **func = (IMAGE_IMPORT_BY_NAME **) RVA_TO_PTR(impdesc->FirstThunk);
                    *func != NULL; ++func) {
                    if (strcmp((const char *) ((IMAGE_IMPORT_BY_NAME *) RVA_TO_PTR(*func))->Name,
                               "GetStdHandle") == 0) {
                        printf("patching address of GetStdHandle (%p) into IAT at address %p\n",
                               GetStdHandle, func);
                        *func = (IMAGE_IMPORT_BY_NAME *) GetStdHandle;
                    }
                    else if (strcmp((const char *) ((IMAGE_IMPORT_BY_NAME *) ((uint8_t *) *func + imgbase))->Name,
                               "WriteFile") == 0) {
                        printf("patching address of WriteFile (%p) into IAT at address %p\n",
                               WriteFile, func);
                        *func = (IMAGE_IMPORT_BY_NAME *) WriteFile;
                    }
                    else {
                        printf("function %s not implemented - aborting\n",
                               ((IMAGE_IMPORT_BY_NAME *) ((uint8_t *) *func + imgbase))->Name);
                        goto cleanup;
                    }
                }
            }
        }
        if (mprotect(secbase, secsize, prot) == -1) {
            perror("cannot set protection of mapped area");
            goto cleanup;
        }
        
        // dump the first 16 bytes for inspection
        hexdump((uint8_t *) secbase, 128);
    }
        
    printf("exit code of program: %d\n", code());
    
cleanup:
    munmap(filebase, sb.st_size);
    close(fd);
    return 0;
}
