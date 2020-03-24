    /*
 * Copyright (C) 2020 Duarte Silva
 *
 * This file is part of GPO Bypass.
 *
 * GPO Bypass is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GPO Bypass is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GPO Bypass. If not, see <http://www.gnu.org/licenses/>.
 */
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>

#include "helper.h"
#include "inject.h"

#define KERNEL32DLL TEXT("kernel32.dll")

#ifdef UNICODE
#define LOADLIBRARY "LoadLibraryW"
#else
#define LOADLIBRARY "LoadLibraryA"
#endif

/**
 * Inject the specified library into the specified process.
 */
BOOL InjectLibrary(HANDLE process, LPTSTR libraryPath) {
    BOOL result = TRUE;
    ULONGLONG kernel32dllAddress;
    ULONGLONG loadLibraryAddress;

    // TODO Assumption is that the GetProcAddress function will have the same address in the target process as the one in the calling process. It
    // might be better not to do that.
    if (GetModuleAddress(KERNEL32DLL, &kernel32dllAddress) == FALSE) {
        goto FAILED;
    }

    if (GetExportedSymbol(kernel32dllAddress, LOADLIBRARY, &loadLibraryAddress) == FALSE) {
        goto FAILED;
    }
    
    LPVOID libraryPathAddress = VirtualAllocEx(process, NULL, _tcslen(libraryPath) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);

    if (libraryPathAddress == NULL) {
        goto FAILED;
    }

    if (WriteProcessMemory(process, libraryPathAddress, libraryPath, _tcslen(libraryPath) * sizeof(TCHAR), NULL) == FALSE) {
        goto FAILED;
    }

    HANDLE remoteThread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE) loadLibraryAddress, libraryPathAddress, 0, NULL);

    if (remoteThread == NULL) {
        goto FAILED;
    }

    WaitForSingleObject(remoteThread, INFINITE);

    goto EXIT;

FAILED:
    result = FALSE;

EXIT:
    if (remoteThread != NULL) {
        CloseHandle(remoteThread);
    }

    if (libraryPathAddress != NULL) {
        VirtualFreeEx(process, libraryPathAddress, 0, MEM_RELEASE);
    }

    return result;
}
