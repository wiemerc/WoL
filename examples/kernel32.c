//
// WINONUX - run simple Windows programs on Unix (Linux and macOS)
//
// Copyright(C) 2017-2019 Constantin Wiemer
//


#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "kernel32.h"


//
// Windows API routines needed by the example program (provided on Windows by kernel32.dll)
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


bool __stdcall WriteFile(HANDLE   hFile,
               void     *lpBuffer,
               uint32_t nNumberOfBytesToWrite,
               uint32_t *lpNumberOfBytesWritten,
               void     *lpOverlapped)
{
    ssize_t nbytes = write((int) hFile, lpBuffer, nNumberOfBytesToWrite);
    if (nbytes == -1) {
        *lpNumberOfBytesWritten = 0;
        return false;
    }
    else {
        *lpNumberOfBytesWritten = (uint32_t) nbytes;
        return true;
    }
}
