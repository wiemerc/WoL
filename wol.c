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
// signal handler for SIGSEGV
//
static void sigsegv(int signum)
{
    CRIT("segmentation fault occurred while loading program image");
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
    uint32_t *out_imgbase,                  // will be set to the image base address (only needed for DLLs)
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
    INFO("mapping file %s into memory", fname);
    if ((fd = open(fname, O_RDONLY)) == -1) {
        ERROR("could not open file: %s", strerror(errno));
        return -1;
    }
    if (fstat(fd, &sb) == -1) {
        ERROR("could not get file status: %s", strerror(errno));
        return -1;
    }
    if ((sof = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        ERROR("could not memory-map file: %s", strerror(errno));
        return -1;
    }
    eof = ((uint8_t *) sof) + sb.st_size;
    DEBUG("image mapped at address %p", sof);
    

    // check DOS header
    if ((((uint8_t *) sof) + sizeof(IMAGE_DOS_HEADER)) >= eof) {
        ERROR("image does not contain complete DOS header");
        return -1;
    }
    doshdr = (IMAGE_DOS_HEADER *) sof;
    if (doshdr->e_magic != 0x5a4d) {
        ERROR("signature of DOS header incorrect");
        return -1;
    }
    nthdrs = (IMAGE_NT_HEADERS *) (((uint8_t *) sof) + doshdr->e_lfanew);


    // check NT headers
    if ((nthdrs < sof) || (nthdrs >= eof)) {
        ERROR("pointer to NT headers incorrect");
        return -1;
    }
    if ((((uint8_t *) nthdrs) + sizeof(IMAGE_NT_HEADERS)) >= eof) {
        ERROR("image does not contain complete NT headers");
        return -1;
    }
    if (nthdrs->Signature != 0x00004550) {
        ERROR("signature of NT headers incorrect");
        return -1;
    }
    DEBUG("number of sections: %d", nthdrs->FileHeader.NumberOfSections);
    DEBUG("image base address: 0x%08x", nthdrs->OptionalHeader.ImageBase);
    imgbase = *out_imgbase = nthdrs->OptionalHeader.ImageBase;
    

    // load individual sections
    // We just load the sections here and access the export and import tables via the data directory
    // later. This is the correct approach because while MinGW puts these tables into their own
    // .edata and .idata sections, which means we wouldn't need to look these tables up in the
    // data directory, the Microsoft compiler / linker (MSVC) does not.
    INFO("loading sections");
    sechdr = (IMAGE_SECTION_HEADER *) (((uint8_t *) nthdrs) + sizeof(IMAGE_NT_HEADERS));
    nsec = 1;
    while (nsec <= nthdrs->FileHeader.NumberOfSections) {
        if ((sechdr < sof) || (sechdr >= eof)) {
            ERROR("pointer to section header incorrect");
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
            ERROR("pointer to section incorrect");
            return -1;
        }
        // TODO: check if section is complete
        
        DEBUG(
            "section %.8s at offset 0x%08x, %d / %d (virtual / on disk) bytes large, will be mapped at 0x%08x",
            sechdr->Name,
            sechdr->PointerToRawData,
            secsize,
            size_on_disk,
            (uint32_t) secbase
        );
        
        // create anonymous mapping at the corresponding address,
        // writeable so we can copy the data (see below)
        // The actual mapping can be larger than specified because only whole pages get mapped.
        // However, this is not a problem because the base addresses of the sections are always
        // at least one page (= 4096 bytes) apart.
        if (mmap(secbase, secsize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) == MAP_FAILED) {
            ERROR("could not create anonymous mapping: %s", strerror(errno));
            return -1;
        }
        
        // copy section data to the mapped area
        // We copy the data because the offset in the image is (normally) not a multiple
        // of the page size, so we can't use it in an mmap() call. We can't
        // use lseek() either, because mmap() seems to ignore the current file position.
        // Also, we can't map the whole image at the base address (normally 0x00400000)
        // because the offsets of the sections differ from their RVAs (e. g. the .text
        // section starts at offset 0x0200 in the image but has to be mapped at 0x00401000).
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
            ERROR("cannot set protection of mapped area: %s", strerror(errno));
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
            INFO("loading DLL %s used by this image", fname);
            if (load_image(libname, &dllbase, NULL, &fnames, &fptrs, &nfuncs) == -1) {
                ERROR("failed to load DLL");
                return -1;
            }

            INFO("patching addresses of imported functions into the Import Address Table (IAT)");
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
                    DEBUG("patched function %s with address %p", func->Name, faddr);
                }
                else {
                    ERROR("function %s not found in DLL %s", func->Name, fname);
                    return -1;
                }
                ++thunk;
            }
            ++impdesc;
        }
    }


    // "fix" names of exported functions (see below) and store pointers in output parameters
    if (nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0) {
        DEBUG("functions exported by this DLL:");
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
            DEBUG("%s at address %p", fname, RVA_TO_PTR(imgbase, fptrs[i]));
        }
    }


    // setup separate stack for the program (necessary for 32-bit programs because
    // our stack lives above the 4GB limit, and safer anyway)
    // TODO: use stack size specified in the image
    if (entry_point) {
        if (mmap((void *) STACK_ADDR, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) == MAP_FAILED) {
            ERROR("could not create anonymous mapping for stack: %s", strerror(errno));
            return -1;
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
    // TODO: install / deinstall handler in load_image()
    act.sa_handler = sigsegv;
    act.sa_flags   = 0;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGSEGV, &act, NULL) == -1) {
        CRIT("failed to install signal handler: %s", strerror(errno));
        return -1;
    }

    // load program
    INFO("loading program %s", argv[1]);
    if (load_image(argv[1], &imgbase, &entry_point, NULL, NULL, NULL) == -1) {
        ERROR("failed to load program");
        return 1;
    }
    INFO("loaded program successfully, entry point = %p", entry_point);

    // run program
    // TODO: check if Windows program is 32 or 64 bits and pass type to our thunk
    INFO("running program...");
    fputs("\n>>>>>>>>>>>>\n", stdout);
    status = entry_point_thunk(entry_point, (void *) (STACK_ADDR + STACK_SIZE));
    fputs("<<<<<<<<<<<<\n\n", stdout);
    INFO("exit code = %d", status);
    return 0;
}
