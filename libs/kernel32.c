//
// WoL - run simple Windows programs on Linux
//
// Copyright(C) 2017-2019 Constantin Wiemer
//


#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "kernel32.h"


// entry point just there to make the linker happy
void start()
{
}

// Windows API routines needed by the example program (provided on Windows by KERNEL32.dll)
// They need to be defined with the __stdcall calling convention (callee removes
// the arguments from the stack before returning) because that's the calling
// convention of Windows API routines (called WINAPI).
HANDLE __stdcall GetStdHandle(uint32_t nStdHandle)
{
    if (nStdHandle == STD_INPUT_HANDLE) {
        return (HANDLE) 0;
    }
    else if (nStdHandle == STD_OUTPUT_HANDLE) {
        return (HANDLE) 1;
    }
    else if (nStdHandle == STD_ERROR_HANDLE) {
        return (HANDLE) 2;
    }
    else {
        return INVALID_HANDLE_VALUE;
    }
}


bool __stdcall WriteFile(
    HANDLE   hFile,
    void     *lpBuffer,
    uint32_t nNumberOfBytesToWrite,
    uint32_t *lpNumberOfBytesWritten,
    void     *lpOverlapped
)
{
    int32_t nbytes_written = 0;

    // We can't call write() the normal way here because write() is just a stub in the
    // standard library on Linux (the GNU C library). This doesn't work in this case because
    // (1) the standard library on Windows (msvcrt.dll), which MinGW links against, doesn't
    //     provide this stub of course and
    // (2) it itself (or the startup code that comes with it) uses several (actually a
    //     whopping 20) functions from the real KERNEL32.DLL.
    // So we put the arguments into the right registers and use the native system call
    // interface (INT 0x80) instead. The return value is placed in EAX, which we need
    // to move to the local variable (located on the stack) nbytes_written afterwards.
    asm("movl   $4, %eax\n"         // system call number = sys_write
        "movl   8(%ebp), %ebx\n"    // hFile
        "movl   12(%ebp), %ecx\n"   // lpBuffer
        "movl   16(%ebp), %edx\n"   // nNumberOfBytesToWrite
        "int    $0x80\n"
        "movl   %eax, -4(%ebp)\n"
    );
    if (nbytes_written == -1) {
        *lpNumberOfBytesWritten = 0;
        return false;
    }
    else {
        *lpNumberOfBytesWritten = (uint32_t) nbytes_written;
        return true;
    }
}
