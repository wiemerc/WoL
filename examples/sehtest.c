//
// sehdemo.c - program that shows what happens "under the hood" when you use SEH on Windows
//             It is more or less the same program that is shown in Matt Pietrek's article
//             "A Crash Course on the Depths of Win32 Structured Exception Handling"
//             (http://bytepointer.com/resources/pietrek_crash_course_depths_of_win32_seh.htm),
//             only adapted for MinGW. Unfortunately, this form of SEH is no longer supported
//             on 64-bit versions of Windows (has been replaced with VEH).


#include <windows.h>


EXCEPTION_DISPOSITION __cdecl handle_exception(
	struct _EXCEPTION_RECORD	*ExceptionRecord,
	void						*EstablisherFrame,
	struct _CONTEXT				*ContextRecord,
	void						*DispatcherContext
)
{
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  nOut;
    WriteFile(hStdOut, "oooppsss\r\n", 10, &nOut, NULL);

    // tell the OS to keep searching for an exception handler that will handle the exception
    // Ultimately, this will be the OS's own exception handler.
    return ExceptionContinueSearch;
}


int start()
{
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  nOut, i, j = 0;

    // build new EXCEPTION_REGISTRATION record and install it (start of __try block), registers
    // need to be prefixed with two percent signs here because we also use an operand...
    // annoying GCC inline assembly syntax :-(
    asm("pushl  %0\n"               // push address of new handler
        "pushl  %%fs:0\n"           // push address of previous record
        "movl   %%esp, %%fs:0\n"    // install new record
        : : "r"(handle_exception)
    );

    WriteFile(hStdOut, "before exception\r\n", 18, &nOut, NULL);
    i = 1 / j;
    WriteFile(hStdOut, "after exception\r\n", 17, &nOut, NULL);

    // restore previous EXCEPTION_REGISTRATION record (end of __try block)
    asm("movl   (%esp), %eax\n"     // get pointer to previous record (ESP still points to it)
        "movl   %eax, %fs:0\n"      // restore previous record
        "addl   $8, %esp\n"         // remove new record from stack
    );

    return 0;
}

