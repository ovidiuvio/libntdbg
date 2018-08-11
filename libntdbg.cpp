#include "libntdbg.h"

// functions imports from wow64ext.dll

// wow64 functions we need
extern "C"
{
    __declspec(dllimport)DWORD64 __cdecl X64Call(DWORD64 func, int argC, ...);
    __declspec(dllimport)DWORD64 __cdecl GetModuleHandle64(wchar_t* lpModuleName);
    __declspec(dllimport)DWORD64 __cdecl GetProcAddress64(DWORD64 hModule, char* funcName);
    __declspec(dllimport)SIZE_T __cdecl VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength);
    __declspec(dllimport)DWORD64 __cdecl VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    __declspec(dllimport)BOOL __cdecl VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    __declspec(dllimport)BOOL __cdecl VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect);
    __declspec(dllimport)BOOL __cdecl ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
    __declspec(dllimport)BOOL __cdecl WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
}

// link with wow64
#pragma comment(lib, "wow64ext/bin/wow64ext.lib")

static BOOL Is64BitWindows()
{
#if defined(_WIN64)
 return TRUE;  // 64-bit programs run only on Win64
#elif defined(_WIN32)
 // 32-bit programs run on both 32-bit and 64-bit Windows
 // so must sniff
 BOOL f64 = FALSE;
 return IsWow64Process(GetCurrentProcess(), &f64) && f64;
#else
 return FALSE; // Win64 does not support Win16
#endif
}

static BOOL CheckReadPtr( HANDLE hProcess, DWORD64 lpAddress )
{
    SIZE_T                          dw  = 0;
    MEMORY_BASIC_INFORMATION        mbi;
    MEMORY_BASIC_INFORMATION64      mbi64;
    int                             ok  = 0;

    if( Is64BitWindows() )
    {
        dw = VirtualQueryEx64( hProcess, lpAddress, &mbi64, sizeof(mbi64));

        ok = (  (mbi64.Protect & PAGE_READONLY) ||
                (mbi64.Protect & PAGE_READWRITE) ||
                (mbi64.Protect & PAGE_WRITECOPY) ||
                (mbi64.Protect & PAGE_EXECUTE_READ) ||
                (mbi64.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi64.Protect & PAGE_EXECUTE_WRITECOPY));

        // check the page is not a guard page

        if (mbi64.Protect & PAGE_GUARD)
            ok = FALSE;
        if (mbi64.Protect & PAGE_NOACCESS)
            ok = FALSE;
    }
    else
    {
        dw = VirtualQueryEx( hProcess, (LPCVOID)(DWORD)lpAddress, &mbi, sizeof(mbi));

        ok = (  (mbi.Protect & PAGE_READONLY) ||
                (mbi.Protect & PAGE_READWRITE) ||
                (mbi.Protect & PAGE_WRITECOPY) ||
                (mbi.Protect & PAGE_EXECUTE_READ) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi.Protect & PAGE_EXECUTE_WRITECOPY));

        // check the page is not a guard page

        if (mbi.Protect & PAGE_GUARD)
            ok = FALSE;
        if (mbi.Protect & PAGE_NOACCESS)
            ok = FALSE;
    }   

    return ok;
}

static BOOL CheckWritePtr( HANDLE hProcess, DWORD64 lpAddress )
{
    SIZE_T                          dw  = 0;
    MEMORY_BASIC_INFORMATION        mbi;
    MEMORY_BASIC_INFORMATION64      mbi64;
    int                             ok  = 0;

    if( Is64BitWindows() )
    {
        dw = VirtualQueryEx64( hProcess, lpAddress, &mbi64, sizeof(mbi64));


        ok = (  (mbi64.Protect & PAGE_READWRITE) ||
                (mbi64.Protect & PAGE_WRITECOPY) ||
                (mbi64.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi64.Protect & PAGE_EXECUTE_WRITECOPY));

        // check the page is not a guard page

        if (mbi64.Protect & PAGE_GUARD)
            ok = FALSE;
        if (mbi64.Protect & PAGE_NOACCESS)
            ok = FALSE;
    }
    else
    {
        dw = VirtualQueryEx( hProcess, (LPCVOID)(DWORD)lpAddress, &mbi, sizeof(mbi));

        ok = (  (mbi.Protect & PAGE_READWRITE) ||
                (mbi.Protect & PAGE_WRITECOPY) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi.Protect & PAGE_EXECUTE_WRITECOPY));

        // check the page is not a guard page

        if (mbi.Protect & PAGE_GUARD)
            ok = FALSE;
        if (mbi.Protect & PAGE_NOACCESS)
            ok = FALSE;
    }   

    return ok;
}


NTDBG_API
HANDLE
NTDBG_CALL
NtDbgOpenProcess                (   IN  DWORD   dwDesiredAccess,
                                IN  BOOL    bInheritHandle,
                                IN  DWORD   dwProcessId )
{
    return OpenProcess( dwDesiredAccess, bInheritHandle, dwProcessId );
}

NTDBG_API
NTDBG_RESULT
NTDBG_CALL
NtDbgCloseHandle                (   IN  HANDLE  hObject     )
{
    return CloseHandle( hObject ) ? NTDBG_OK : NTDBG_FAIL;
}


NTDBG_API
NTDBG_RESULT
NTDBG_CALL
NtDbgReadProcessMemory      (   IN  HANDLE  hProcess,
                                IN  DWORD64 lpBaseAddress,
                                OUT LPVOID  lpBuffer,
                                OUT SIZE_T  nSize,
                                OUT SIZE_T* lpNumberOfBytesRead )
{
    NTDBG_RESULT    ret                         = NTDBG_FAIL;

    // create local variables for the x64call
    HANDLE      ld_hProcess                 = hProcess;
    DWORD64     ld_lpBaseAddress            = lpBaseAddress;
    LPVOID      ld_lpBuffer                 = lpBuffer;
    DWORD64     ld_nSize                    = (DWORD64)nSize;
    DWORD64     ld_nNumberOfBytesRead       = 0;
    SIZE_T*     ld_lpNumberOfBytesRead      = (SIZE_T*)&ld_nNumberOfBytesRead;

    // check for valid size
    if( ld_nSize == 0 )
        return NTDBG_INVALID_SIZE;

    // check for valid read address
    if (!CheckReadPtr(ld_hProcess, ld_lpBaseAddress))
        return NTDBG_ACCESS_DENIED;

    // check for valid read end address
    if (!CheckReadPtr(ld_hProcess, ld_lpBaseAddress + (ld_nSize - 1)))
        return NTDBG_ACCESS_DENIED;

    // if windows is 64 bits, call NTReadVirtualMemory
    if( Is64BitWindows() )
    {

        if( ReadProcessMemory64(    ld_hProcess,
                                    ld_lpBaseAddress,
                                    ld_lpBuffer,
                                    (SIZE_T)ld_nSize,
                                    ld_lpNumberOfBytesRead ) )
                                    ret = NTDBG_OK;
    }
    else
    {
        if( ReadProcessMemory(      ld_hProcess,
                                    (LPCVOID)(DWORD)ld_lpBaseAddress,
                                    ld_lpBuffer,
                                    (SIZE_T)ld_nSize,
                                    ld_lpNumberOfBytesRead ) )
                                    ret = NTDBG_OK;
    }

    // set number of read bytes
    *lpNumberOfBytesRead = (SIZE_T)ld_nNumberOfBytesRead;

    return ret;
}

NTDBG_API
NTDBG_RESULT
NTDBG_CALL
NtDbgWriteProcessMemory     (   IN  HANDLE  hProcess,
                                IN  DWORD64 lpBaseAddress,
                                IN  LPVOID  lpBuffer,
                                IN  SIZE_T  nSize,
                                OUT SIZE_T* lpNumberOfBytesWritten )
{
    NTDBG_RESULT    ret                         = NTDBG_FAIL;

    // create local variables for the x64call
    HANDLE      ld_hProcess                 = hProcess;
    DWORD64     ld_lpBaseAddress            = lpBaseAddress;
    LPVOID      ld_lpBuffer                 = lpBuffer;
    DWORD64     ld_nSize                    = (DWORD64)nSize;
    DWORD64     ld_nNumberOfBytesWritten    = 0;
    SIZE_T*     ld_lpNumberOfBytesWritten   = (SIZE_T*)&ld_nNumberOfBytesWritten;

    // check for valid size
    if( ld_nSize == 0 )
        return NTDBG_INVALID_SIZE;

    // check for valid write address
    if (!CheckWritePtr(ld_hProcess, ld_lpBaseAddress))
        return NTDBG_ACCESS_DENIED;

    // check for valid write end address
    if (!CheckWritePtr(ld_hProcess, ld_lpBaseAddress + (ld_nSize - 1)))
        return NTDBG_ACCESS_DENIED;

    // if windows is 64 bits, call NTWriteVirtualMemory
    if( Is64BitWindows() )
    {
        if( WriteProcessMemory64(   ld_hProcess,
                                    ld_lpBaseAddress,
                                    ld_lpBuffer,
                                    (SIZE_T)ld_nSize,
                                    ld_lpNumberOfBytesWritten ) )
                                    ret = NTDBG_OK;
    }
    else
    {
        if( WriteProcessMemory(     ld_hProcess,
                                    (LPVOID)(DWORD)ld_lpBaseAddress,
                                    ld_lpBuffer,
                                    (SIZE_T)ld_nSize,
                                    ld_lpNumberOfBytesWritten ) )
                                    ret = NTDBG_OK;
    }

    // set number of written bytes
    *lpNumberOfBytesWritten = (SIZE_T)ld_nNumberOfBytesWritten;

    return ret;
}

NTDBG_API
NTDBG_RESULT
NTDBG_CALL
NtDbgProcessMemCpy          (   IN  HANDLE  hSrcProcess,
                                IN  HANDLE  hDstProcess,
                                IN  DWORD64 lpSrcAddress,
                                IN  DWORD64 lpDstAddress,
                                IN  SIZE_T  nSize,
                                OUT SIZE_T* lpNumberOfBytesCopyed )
{
    NTDBG_RESULT    ret                         = NTDBG_OK;
    // create local variables for the x64call
    HANDLE      ld_hSrcProcess              = hSrcProcess;
    HANDLE      ld_hDstProcess              = hDstProcess;
    DWORD64     ld_lpSrcAddress             = lpSrcAddress;
    DWORD64     ld_lpDstAddress             = lpDstAddress;
    INT64       ld_nSize                    = (INT64)nSize;
    DWORD64     ld_nNumberOfBytesCopied     = 0;
    DWORD64     ld_nNumberOfBytesRead       = 0;
    DWORD64     ld_nNumberOfBytesWritten    = 0;
    SIZE_T*     ld_lpNumberOfBytesRead      = (SIZE_T*)&ld_nNumberOfBytesRead;
    SIZE_T*     ld_lpNumberOfBytesWritten   = (SIZE_T*)&ld_nNumberOfBytesWritten;

    // check for valid read address
    if( !CheckReadPtr( ld_hSrcProcess, ld_lpSrcAddress ) )
        return NTDBG_ACCESS_DENIED;

    // check for valid read end address
    if( !CheckReadPtr( ld_hSrcProcess, ld_lpSrcAddress + (ld_nSize - 1) ) )
        return NTDBG_ACCESS_DENIED;

    // check for valid write address
    if( !CheckWritePtr( ld_hDstProcess, ld_lpDstAddress ) )
        return NTDBG_ACCESS_DENIED;

    // check for valid write end address
    if( !CheckWritePtr( ld_hDstProcess, ld_lpDstAddress + (ld_nSize - 1) ) )
        return NTDBG_ACCESS_DENIED;

    // allocate buffer for bufferd copy
    UINT8*      ld_buffer                   = (UINT8*)malloc( NTDBG_PAGE_SIZE );

    // copy chunks of NTDBG_PAGE_SIZE bytes
    for (INT64 i = 0; (i < ld_nSize) && (NTDBG_OK == ret); i += ld_nNumberOfBytesRead )
    {
        ret = NtDbgReadProcessMemory( ld_hSrcProcess
            , ld_lpSrcAddress + i
            , ld_buffer
            , (SIZE_T)min(ld_nSize - i, NTDBG_PAGE_SIZE)
            , ld_lpNumberOfBytesRead
            );

        if (NTDBG_OK != ret)
            break;

        ret = NtDbgWriteProcessMemory( ld_hDstProcess
            , ld_lpDstAddress + i
            , ld_buffer
            , (SIZE_T)min(ld_nSize - i, NTDBG_PAGE_SIZE)
            , ld_lpNumberOfBytesWritten
            );

        if (ld_nNumberOfBytesRead != ld_nNumberOfBytesWritten)
            ret = NTDBG_FAIL;

        ld_nNumberOfBytesCopied += ld_nNumberOfBytesWritten;
    }

    // set number of copied bytes
    *lpNumberOfBytesCopyed = (SIZE_T)ld_nNumberOfBytesCopied;

    // free buffer
    free( ld_buffer );

    return ret;
}

NTDBG_API
NTDBG_RESULT
NTDBG_CALL
NtDbgProcessMemSet              (   IN  HANDLE  hProcess,
                                    IN  DWORD64 lpBaseAddress,
                                    IN  DWORD   uByte,
                                    IN  SIZE_T  nSize,                                  
                                    OUT SIZE_T* lpNumberOfBytesSet )
{
    NTDBG_RESULT    ret                     = NTDBG_OK;
    // create local variables for the x64call
    HANDLE      ld_hProcess                 = hProcess;
    DWORD64     ld_lpBaseAddress            = lpBaseAddress;
    INT64       ld_nSize                    = (INT64)nSize;
    DWORD64     ld_nNumberOfBytesSet        = 0;
    DWORD64     ld_nNumberOfBytesWritten    = 0;
    SIZE_T*     ld_lpNumberOfBytesWritten   = (SIZE_T*)&ld_nNumberOfBytesWritten;

    // check for valid write address
    if( !CheckWritePtr( ld_hProcess, ld_lpBaseAddress ) )
        return NTDBG_ACCESS_DENIED;

    // check for valid write end address
    if( !CheckWritePtr( ld_hProcess, ld_lpBaseAddress + (ld_nSize - 1) ) )
        return NTDBG_ACCESS_DENIED;

    // allocate buffer for bufferd memset
    UINT8*      ld_buffer                   = (UINT8*)malloc( NTDBG_PAGE_SIZE );

    // fill buffer with pattern
    memset( ld_buffer, (UINT8)uByte, NTDBG_PAGE_SIZE );

    // fill the whole area of memory in chunks
    for( INT64 i = 0; (i < ld_nSize) && ( NTDBG_OK == ret ); i += ld_nNumberOfBytesWritten)
    {              

        ret = NtDbgWriteProcessMemory(ld_hProcess
            , ld_lpBaseAddress + i
            , ld_buffer
            , (SIZE_T)min(ld_nSize - i, NTDBG_PAGE_SIZE)
            , ld_lpNumberOfBytesWritten
            );

        ld_nNumberOfBytesSet += ld_nNumberOfBytesWritten;
    }

    // set number of bytes set
    *lpNumberOfBytesSet = (SIZE_T)ld_nNumberOfBytesSet;

    // free buffer
    free( ld_buffer );

    return ret;
}

NTDBG_API
DWORD64
NTDBG_CALL
NtDbgProcessAlloc               (   IN      HANDLE   hProcess,
                                    IN      SIZE_T   nSize )
{
    DWORD64 addr        = 0;
    // create local variables for the x64call
    HANDLE  ld_hProcess = hProcess;
    INT64   ld_nSize    = (INT64)nSize;

    // check OS type
    if( Is64BitWindows() )
    {
        addr = (DWORD64)VirtualAllocEx64( ld_hProcess, 0, (SIZE_T)ld_nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    }
    else
    {
        addr = (DWORD64)VirtualAllocEx( ld_hProcess, 0, (SIZE_T)ld_nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    }

    return addr;
}

NTDBG_API
NTDBG_RESULT
NTDBG_CALL
NtDbgProcessFree                (   IN      HANDLE  hProcess,
                                    IN      DWORD64 lpAddress )
{
    NTDBG_RESULT ret        = NTDBG_FAIL;
    // create local variables for the x64call
    HANDLE  ld_hProcess     = hProcess;
    DWORD64 ld_lpAddress    = lpAddress;

    // check OS type
    if( Is64BitWindows() )
    {
        // check for success
        if( VirtualFreeEx64( ld_hProcess, ld_lpAddress, 0, MEM_RELEASE ) )
        {
            ret = NTDBG_OK;
        }
    }
    else
    {
        // check for success
        if( VirtualFreeEx( ld_hProcess, (LPVOID)ld_lpAddress, 0, MEM_RELEASE ) )
        {
            ret = NTDBG_OK;
        }
    }

    return ret;
}