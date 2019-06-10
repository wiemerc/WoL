//
// WINONUX - run simple Windows programs on Unix (Linux and macOS)
//
// Copyright(C) 2017-2019 Constantin Wiemer
//


#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "winonux.h"


//
// log a message with severity
//
static void logmsg(int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
 
    switch (level) {
        case DEBUG: fputs("DEBUG: ", stdout); break;
        case INFO:  fputs("INFO: ", stdout);  break;
        case WARN:  fputs("WARN: ", stdout);  break;
        case ERROR: fputs("ERROR: ", stdout); break;
        case CRIT:  fputs("CRIT: ", stdout);  break;
    }
    vprintf(fmt, args);
    fputs("\n", stdout);
}


//
// generate a hexdump from a buffer of bytes
//
static void hexdump(const uint8_t *buffer, size_t length)
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
// signal handler for SIGSEGV
//
static void sigsegv(int signum)
{
    logmsg(CRIT, "segmentation fault occurred, probably due to an ill-formed program image");
    exit(1);
}


//
// load recursively the program image and the images of all imported DLLs
//
// returns 0 if successful, -1 otherwise. If successful, *entry_point is set to 
// the start address of the .text segment (where the program begins execution).
//
static int load_image(const char *fname, void **entry_point)
{
    int                  fd;                // file descriptor
    struct stat          sb;                // buffer for fstat
    void                 *sof, *eof;        // start-of-file and end-of-file pointers
    IMAGE_DOS_HEADER     *doshdr;           // pointer to DOS header
    IMAGE_NT_HEADERS     *nthdrs;           // pointer to NT headers
    IMAGE_SECTION_HEADER *sechdr;           // pointer to image section headers
    int                  nsec;              // number of section
    uint32_t             imgbase;           // virtual base address of image


    // map whole image into memory
    logmsg(INFO, "mapping file '%s' into memory...", fname);
    if ((fd = open(fname, O_RDONLY)) == -1) {
        logmsg(ERROR, "could not open file: %s", strerror(errno));
        return -1;
    }
    if (fstat(fd, &sb) == -1) {
        logmsg(ERROR, "could not get file status: %s", strerror(errno));
        return -1;
    }
    if ((sof = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
        logmsg(ERROR, "could not memory-map file: %s", strerror(errno));
        return -1;
    }
    eof = ((uint8_t *) sof) + sb.st_size;
    logmsg(DEBUG, "image mapped at address %p", sof);
    

    // check DOS header
    if ((((uint8_t *) sof) + sizeof(IMAGE_DOS_HEADER)) >= eof) {
        logmsg(ERROR, "image does not contain complete DOS header");
        return -1;
    }
    doshdr = (IMAGE_DOS_HEADER *) sof;
    if (doshdr->e_magic != 0x5a4d) {
        logmsg(ERROR, "signature of DOS header incorrect");
        return -1;
    }
    nthdrs = (IMAGE_NT_HEADERS *) (((uint8_t *) sof) + doshdr->e_lfanew);


    // check NT headers
    if ((nthdrs < sof) || (nthdrs >= eof)) {
        logmsg(ERROR, "pointer to NT headers incorrect");
        return -1;
    }
    if ((((uint8_t *) nthdrs) + sizeof(IMAGE_NT_HEADERS)) >= eof) {
        logmsg(ERROR, "image does not contain complete NT headers");
        return -1;
    }
    if (nthdrs->Signature != 0x00004550) {
        logmsg(ERROR, "signature of NT headers incorrect");
        return -1;
    }
    logmsg(DEBUG, "number of sections: %d", nthdrs->FileHeader.NumberOfSections);
    logmsg(DEBUG, "image base address: 0x%08x", nthdrs->OptionalHeader.ImageBase);
    imgbase = nthdrs->OptionalHeader.ImageBase;
    

    // load individual sections and process them
    logmsg(INFO, "loading sections...");
    sechdr = (IMAGE_SECTION_HEADER *) (((uint8_t *) nthdrs) + sizeof(IMAGE_NT_HEADERS));
    nsec = 1;
    while (nsec <= nthdrs->FileHeader.NumberOfSections) {
        if ((sechdr < sof) || (sechdr >= eof)) {
            logmsg(ERROR, "pointer to section header incorrect");
            return -1;
        }
        // TODO: check if section header is complete
        void     *secptr  = (void *) (sechdr->PointerToRawData + (uint8_t *) sof);
        void     *secbase = (void *) (sechdr->VirtualAddress + imgbase);
        uint32_t secsize  = sechdr->Misc.VirtualSize;
        if ((secptr < sof) || (secptr >= eof)) {
            logmsg(ERROR, "pointer to section incorrect");
            return -1;
        }
        // TODO: check if section is complete
        
        logmsg(DEBUG, "section %.8s at %p, %d bytes large, will be mapped at 0x%08x",
               sechdr->Name,
               secptr,
               secsize,
               secbase
        );
        
        // create anonymous mapping at the corresponding address,
        // writeable so we can copy the data (see below)
        if (mmap(secbase,
                 secsize,
                 PROT_WRITE,
                 MAP_ANON | MAP_PRIVATE | MAP_FIXED,
                 -1,
                 0
            ) == MAP_FAILED) {
            logmsg(ERROR, "could not create anonymous mapping: %s", strerror(errno));
            return -1;
        }
        
        // copy section data to the mapped area
        // We copy the data because the offset in the image is (normally) not a multiple
        // of the page size, so we can't use it in the mmap() call. We can't
        // use lseek() either, because mmap() seems to ignore the current file position.
        memcpy(secbase, secptr, secsize);
        
        // set protection of mapped area depending on section name and perform
        // other section-specific actions
        int prot = 0;
        if (strncmp((const char *) sechdr->Name, ".text", 8) == 0) {
            prot = PROT_READ | PROT_EXEC;
            *entry_point = secbase;
        }
        else if (strncmp((const char *) sechdr->Name, ".data", 8) == 0) {
            prot = PROT_READ | PROT_WRITE;
        }
        else if (strncmp((const char *) sechdr->Name, ".rdata", 8) == 0) {
            prot = PROT_READ;
        }
        else if (strncmp((const char *) sechdr->Name, ".idata", 8) == 0) {
            prot = PROT_READ | PROT_WRITE;
            
            // patch addresses of imported functions into the Import Address Table (IAT)
            IMAGE_IMPORT_DESCRIPTOR *impdesc = (IMAGE_IMPORT_DESCRIPTOR *) secbase;
            while (impdesc->FirstThunk != 0) {
                logmsg(DEBUG, "functions imported from %s:", RVA_TO_PTR(impdesc->Name));
                IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *) RVA_TO_PTR(impdesc->FirstThunk);
                while (thunk->AddressOfData != 0) {
                    IMAGE_IMPORT_BY_NAME *func = (IMAGE_IMPORT_BY_NAME *) RVA_TO_PTR(thunk->AddressOfData); 
                    logmsg(DEBUG, "%s (%d)", func->Name, func->Hint);
                    ++thunk;
                }
                ++impdesc;
            }
        }

        if (mprotect(secbase, secsize, prot) == -1) {
            logmsg(ERROR, "cannot set protection of mapped area: %s", strerror(errno));
            return -1;
        }
        
        // dump the first 128 bytes for inspection
        hexdump((uint8_t *) secbase, 128);

        // move to next section
        ++sechdr;
        ++nsec;
    }
    return 0;
}


//
// main function
//
int main(int argc, char **argv)
{
    struct sigaction     act;
    int32_t              (*entry_point)();

    // install signal handler for SIGSEGV
    act.sa_handler = sigsegv;
    act.sa_flags   = 0;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGSEGV, &act, NULL) == -1) {
        logmsg(CRIT, "failed to install signal handler: %s", strerror(errno));
        return -1;
    }

    // load program
    if (load_image(argv[1], &entry_point) == -1) {
        logmsg(ERROR, "failed to load image");
        return 1;
    }
    logmsg(INFO, "loaded program successfully, entry point = %p", entry_point);

    // run program
    #if 0
    logmsg(INFO, "running program...");
    logmsg(INFO, "exit code = %d", entry_point());
    #endif
    return 0;
}
