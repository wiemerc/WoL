//
// WINONUX - run simple Windows programs on Unix (Linux and macOS)
//
// Copyright(C) 2017-2019 Constantin Wiemer
//


// definitions for the API routines
typedef void *HANDLE;
#define INVALID_HANDLE_VALUE ((HANDLE) (int32_t)-1)
#define STD_INPUT_HANDLE ((uint32_t) -10)
#define STD_OUTPUT_HANDLE ((uint32_t) -11)
#define STD_ERROR_HANDLE ((uint32_t) -12)


// function declarations
void entry();
HANDLE __declspec(dllexport) __stdcall GetStdHandle(uint32_t);
bool __declspec(dllexport) __stdcall WriteFile(HANDLE, void *, uint32_t , uint32_t *, void *);
