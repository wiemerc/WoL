//
// WoL - run simple Windows programs on Linux
//
// Copyright(C) 2017-2019 Constantin Wiemer
//


#include <ctype.h>
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

#include "wol.h"


//
// log a message with severity
//
static void logmsg(int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
 
    switch (level) {
        case DEBUG: fputs("DEBUG: ", stdout); break;
        case INFO:  fputs("INFO:  ", stdout);  break;
        case WARN:  fputs("WARN:  ", stdout);  break;
        case ERROR: fputs("ERROR: ", stdout); break;
        case CRIT:  fputs("CRIT:  ", stdout);  break;
    }
    vprintf(fmt, args);
    fputs("\n", stdout);
}


//
// signal handler for SIGSEGV
//
static void sigsegv(int signum)
{
    logmsg(CRIT, "segmentation fault occurred while loading program image");
    exit(1);
}


//
// get function by name in list of functions exported by a DLL
//
// return: pointer to the function if successful, NULL otherwise
//
static void *get_func_by_name(
    const char      *fname,                 // name of function to find
    uint32_t        dllbase,                // base address of DLL these functions are imported from
    const uint32_t  *func_names,            // pointer to AddressOfNames in the .edata segment of the DLL
    const uint32_t  *func_ptrs,             // pointer to AddressOfFunctions in the .edata segment of the DLL
    uint32_t        nfuncs                  // number of function name / pointer pairs
)
{
    for (uint32_t i = 0; i < nfuncs; ++i) {
        if (strcmp(fname, RVA_TO_PTR(dllbase, func_names[i])) == 0)
            return RVA_TO_PTR(dllbase, func_ptrs[i]);
    }
    return NULL;
}


//
// load recursively the program image and the images of all imported DLLs
//
// returns: 0 if successful, -1 otherwise
//
static int load_image(
    const char *fname,                      // name of the image file (executable or DLL)
    uint32_t *out_imgbase,                  // will be set to the image base address
    int32_t (**entry_point)(),              // if not NULL, *entry_point will be set to start address of the .text segment
    uint32_t **func_names,                  // if not NULL, *func_names will be set to AddressOfNames in the .edata segment
    uint32_t **func_ptrs,                   // if not NULL, *func_ptrs will be set to AddressOfFunctions in the .edata segment
    uint32_t *nfuncs                        // if not NULL, *nfuncs will be set to the number of exported functions
)
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
    logmsg(INFO, "mapping file %s into memory", fname);
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
    imgbase = *out_imgbase = nthdrs->OptionalHeader.ImageBase;
    

    // load individual sections
    // We just load the sections here and access the export and import tables via the data directory
    // later. This is the correct approach because while MinGW puts these tables into their own
    // .edata and .idata sections, which means we wouldn't need to lookup these tables in the
    // data directory, the Microsoft compiler / linker (MSVC) does not.
    logmsg(INFO, "loading sections");
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
        // VirtualSize is the size of the section mapped into the virtual address space of the process,
        // SizeOfRawData is the amount of space the section occupies on disk. It can be larger than the
        // virtual size because of the alignment of the sections in the image (on 512-byte boundaries in
        // images created with MinGW) or it can be 0 in case of uninitialized data (section .bss).
        uint32_t secsize      = sechdr->VirtualSize;
        uint32_t size_on_disk = sechdr->SizeOfRawData;
        if ((secptr < sof) || (secptr >= eof)) {
            logmsg(ERROR, "pointer to section incorrect");
            return -1;
        }
        // TODO: check if section is complete
        
        logmsg(
            DEBUG,
            "section %.8s at offset 0x%08x, %d / %d (virtual / on disk) bytes large, will be mapped at 0x%08x",
            sechdr->Name,
            secptr,
            secsize,
            size_on_disk,
            secbase
        );
        
        // create anonymous mapping at the corresponding address,
        // writeable so we can copy the data (see below)
        // TODO: Can the actual mapping be larger than specified because only whole pages get mapped?
        //       How do we make sure in this case that consecutive sections don't overlap?
        if (mmap(secbase, secsize, PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) == MAP_FAILED) {
            logmsg(ERROR, "could not create anonymous mapping: %s", strerror(errno));
            return -1;
        }
        
        // copy section data to the mapped area
        // We copy the data because the offset in the image is (normally) not a multiple
        // of the page size, so we can't use it in the mmap() call. We can't
        // use lseek() either, because mmap() seems to ignore the current file position.
        // We check if there is actually data to copy but only copy the real, not any
        // padded bytes.
        if (size_on_disk > 0)
            memcpy(secbase, secptr, secsize);
        
        // set protection of mapped area depending on section name
        int prot = 0;
        if (strncmp((const char *) sechdr->Name, ".text", 8) == 0) {
            prot = PROT_READ | PROT_EXEC;
            if (entry_point)
                *entry_point = secbase;
        }
        else if ((strncmp((const char *) sechdr->Name, ".data", 8) == 0) || 
                 (strncmp((const char *) sechdr->Name, ".bss", 8) == 0)) {
            prot = PROT_READ | PROT_WRITE;
        }
        else if (strncmp((const char *) sechdr->Name, ".rdata", 8) == 0) {
            // MSVC for some reason puts the IAT in the .rdata section. This means we need
            // to make the section writable although it is meant to contain read-only data.
            prot = PROT_READ | PROT_WRITE;
        }
        else if (strncmp((const char *) sechdr->Name, ".idata", 8) == 0) {
            // needs to be writable because we patch the IAT
            prot = PROT_READ | PROT_WRITE;
            
        }
        else if (strncmp((const char *) sechdr->Name, ".edata", 8) == 0) {
            // needs to be writable because we "fix" the function names
            prot = PROT_READ | PROT_WRITE;
        }
        if (mprotect(secbase, secsize, prot) == -1) {
            logmsg(ERROR, "cannot set protection of mapped area: %s", strerror(errno));
            return -1;
        }
        
        // move to next section
        ++sechdr;
        ++nsec;
    }


    // load needed DLLs and patch addresses of imported functions into the Import Address Table (IAT)
    if (nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        IMAGE_IMPORT_DESCRIPTOR *impdesc = (IMAGE_IMPORT_DESCRIPTOR *) RVA_TO_PTR(imgbase, nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (impdesc->FirstThunk != 0) {
            char *fname = RVA_TO_PTR(imgbase, impdesc->Name);
            char *p = fname;
            while ((*p = tolower(*p)))
                ++p;
            
            // load specified DLL, all DLLs are located in the libs/ subdirectory
            char libname[MAX_PATH_LEN];
            strncpy(libname, "libs/", MAX_PATH_LEN - 1);
            strncat(libname, fname, MAX_PATH_LEN - 1 - strlen("libs/"));
            uint32_t dllbase;
            uint32_t *fnames;
            uint32_t *fptrs;
            uint32_t nfuncs;
            logmsg(INFO, "loading DLL %s used by this image", fname);
            if (load_image(libname, &dllbase, NULL, &fnames, &fptrs, &nfuncs) == -1) {
                logmsg(ERROR, "failed to load DLL %s");
                return -1;
            }

            logmsg(INFO, "patching addresses of imported functions into the Import Address Table (IAT)");
            IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *) RVA_TO_PTR(imgbase, impdesc->FirstThunk);
            void *faddr;
            // A thunk is just a 32-bit value than can mean different things (implemented as a C union).
            // Before patching is is (usually) an RVA pointing to an IMAGE_IMPORT_BY_NAME structure (the 
            // AddressOfData field). When the function described by this structure is found in the imported
            // DLL, this RVA get replaced by a (32-bit) pointer to the function itself (the Function field).
            while (thunk->AddressOfData != 0) {
                IMAGE_IMPORT_BY_NAME *func = (IMAGE_IMPORT_BY_NAME *) RVA_TO_PTR(imgbase, thunk->AddressOfData); 
                if ((faddr = get_func_by_name(func->Name, dllbase, fnames, fptrs, nfuncs)) != NULL) {
                    thunk->Function = (uint32_t) faddr;
                    logmsg(DEBUG, "patched function %s with address %p", func->Name, faddr);
                }
                else {
                    logmsg(ERROR, "function %s not found in DLL %s", func->Name, fname);
                    return -1;
                }
                ++thunk;
            }
            ++impdesc;
        }
    }


    // "fix" names of exported functions (see below) and store pointers in output parameters
    if (nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0) {
        logmsg(DEBUG, "functions exported by this DLL:");
        IMAGE_EXPORT_DIRECTORY *expdir = (IMAGE_EXPORT_DIRECTORY *) RVA_TO_PTR(imgbase, nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        // AddressOfNames and AddressOfFunctions are arrays of *RVAs*, not pointers (4 bytes vs. 8 bytes on a 64-bit architecture)
        uint32_t *fnames = (uint32_t *) RVA_TO_PTR(imgbase, expdir->AddressOfNames);
        uint32_t *fptrs  = (uint32_t *) RVA_TO_PTR(imgbase, expdir->AddressOfFunctions);
        if (func_names && func_ptrs && nfuncs) {
            *func_names = fnames;
            *func_ptrs  = fptrs;
            *nfuncs     = expdir->NumberOfNames;
        }
        for (uint32_t i = 0; i < expdir->NumberOfNames; ++i) {
            char *fname = RVA_TO_PTR(imgbase, fnames[i]);
            // remove trailing '@' and (ordinal?) number
            fname = strsep(&fname, "@");
            logmsg(DEBUG, "%s at address %p", fname, RVA_TO_PTR(imgbase, fptrs[i]));
        }
    }

    return 0;
}


//
// main function
//
int main(int argc, char **argv)
{
    struct sigaction     act;
    uint32_t             imgbase;
    int32_t              (*entry_point)(), status;

    // install signal handler for SIGSEGV
    act.sa_handler = sigsegv;
    act.sa_flags   = 0;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGSEGV, &act, NULL) == -1) {
        logmsg(CRIT, "failed to install signal handler: %s", strerror(errno));
        return -1;
    }

    // load program
    logmsg(INFO, "loading program %s", argv[1]);
    if (load_image(argv[1], &imgbase, &entry_point, NULL, NULL, NULL) == -1) {
        logmsg(ERROR, "failed to load program");
        return 1;
    }
    logmsg(INFO, "loaded program successfully, entry point = %p", entry_point);

    // run program
    // TODO: build program as 64-bit executable and switch to 32-bit mode before calling
    //       the entry point, as described here: https://stackoverflow.com/a/32384358
    logmsg(INFO, "running program...");
    fputs("\n>>>>>>>>>>>>\n", stdout);
    status = entry_point();
    fputs("<<<<<<<<<<<<\n\n", stdout);
    logmsg(INFO, "exit code = %d", status);
    return 0;
}
