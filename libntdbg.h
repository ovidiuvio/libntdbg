#ifndef _NT_DEBUG_LIB_H_
#define _NT_DEBUG_LIB_H_

/*
-------------------------------------------------------------------------
// Include standard files
-------------------------------------------------------------------------
*/

#include <Windows.h>

/*
-------------------------------------------------------------------------
// Api codes
-------------------------------------------------------------------------
*/

#define NTDBG_RESULT                         INT32

#define NTDBG_OK                                 0 
#define NTDBG_FAIL                          -1
#define NTDBG_INVALID_ADDRESS                   -2
#define NTDBG_ACCESS_DENIED                 -3
#define NTDBG_INVALID_SIZE                  -4

/*
-------------------------------------------------------------------------
// NTDBG defines
-------------------------------------------------------------------------
*/
#define NTDBG_PAGE_SIZE                     4096

/*
-------------------------------------------------------------------------
// Library Linking
-------------------------------------------------------------------------
*/

#ifdef  NTDBG_EXPORTS
#define NTDBG_API                           __declspec(dllexport)
#else
#define NTDBG_API                           __declspec(dllimport)
#endif  

#define NTDBG_CALL                          __cdecl

/*
-------------------------------------------------------------------------
// Compiler Helpers
-------------------------------------------------------------------------
*/

#define NTDBG_INLINE                        __forceinline

/*
-------------------------------------------------------------------------
// Syntax Helpers
-------------------------------------------------------------------------
*/

#define IN
#define OUT

/*
-------------------------------------------------------------------------
// Api 
-------------------------------------------------------------------------
*/

extern "C"
{

    /*
    -------------------------------------------------------------------------
    // NtDbgOpenProcess - Open a process handle with the specified access rights
    -------------------------------------------------------------------------
    */
    NTDBG_API
    HANDLE
    NTDBG_CALL
    NtDbgOpenProcess            (   IN  DWORD   dwDesiredAccess,
                                    IN  BOOL    bInheritHandle,
                                    IN  DWORD   dwProcessId );

    /*
    -------------------------------------------------------------------------
    // NtDbgCloseHandle - Close handle
    -------------------------------------------------------------------------
    */
    NTDBG_API
    NTDBG_RESULT
    NTDBG_CALL
    NtDbgCloseHandle            (   IN  HANDLE  hObject     );


    /*
    -------------------------------------------------------------------------
    // NtDbgReadProcessMemory  - Read Process Memory
    -------------------------------------------------------------------------
    */
    NTDBG_API
    NTDBG_RESULT
    NTDBG_CALL
    NtDbgReadProcessMemory      (   IN  HANDLE  hProcess,
                                    IN  DWORD64 lpBaseAddress,
                                    OUT LPVOID  lpBuffer,
                                    OUT SIZE_T  nSize,
                                    OUT SIZE_T* lpNumberOfBytesRead );

    /*
    -------------------------------------------------------------------------
    // NtDbgWriteProcessMemory  - Write Process Memory
    -------------------------------------------------------------------------
    */
    NTDBG_API
    NTDBG_RESULT
    NTDBG_CALL
    NtDbgWriteProcessMemory     (   IN  HANDLE  hProcess,
                                    IN  DWORD64 lpBaseAddress,
                                    IN  LPVOID  lpBuffer,
                                    IN  SIZE_T  nSize,
                                    OUT SIZE_T* lpNumberOfBytesWritten );

    NTDBG_API
    NTDBG_RESULT
    NTDBG_CALL
    NtDbgProcessMemCpy          (   IN  HANDLE  hSrcProcess,
                                    IN  HANDLE  hDstProcess,
                                    IN  DWORD64 lpSrcAddress,
                                    IN  DWORD64 lpDstAddress,
                                    IN  SIZE_T  nSize,
                                    OUT SIZE_T* lpNumberOfBytesCopyed );

    NTDBG_API
    NTDBG_RESULT
    NTDBG_CALL
    NtDbgProcessMemSet          (   IN  HANDLE  hProcess,
                                    IN  DWORD64 lpBaseAddress,
                                    IN  DWORD   uByte,
                                    IN  SIZE_T  nSize,
                                    OUT SIZE_T* lpNumberOfBytesSet );

    NTDBG_API
    DWORD64
    NTDBG_CALL
    NtDbgProcessAlloc           (   IN      HANDLE   hProcess,
                                    IN      SIZE_T   nSize );

    NTDBG_API
    NTDBG_RESULT
    NTDBG_CALL
    NtDbgProcessFree            (   IN      HANDLE  hProcess,
                                    IN      DWORD64 lpAddress );
}
#endif