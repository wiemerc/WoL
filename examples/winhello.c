//
// winhello.c - my first attempt at Windows system programming
//


#include <windows.h>


// We don't use a startup code nor the standard library, hence no main() function
void start()
{
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  nOut;

    WriteFile(hStdOut, "Hello, Windows\r\n", 16, &nOut, NULL);
}
