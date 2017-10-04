/*
 * winhello.c - my first attempt at Windows system programming
 */


#include <windows.h>


int cwmain()
{
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  nOut;

    WriteFile(hStdOut, "hello, windows\r\n", 16, &nOut, NULL);
    return 0;
}
