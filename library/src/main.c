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
#include <windows.h>
#include <winternl.h>

#include "helper.h"
#include "detour.h"
#include "inject.h"


#define KERNEL32DLL TEXT("kernel32.dll")
#define ADVAPI32DLL TEXT("advapi32.dll")
#define KERNELBASEDLL TEXT("kernelbase.dll")
#define CREATEPROCESSW "CreateProcessW"
#define CREATEPROCESSASUSERW "CreateProcessAsUserW"
#define REGOPENKEYEXW "RegOpenKeyExW"
#define REGQUERYVALUEEXW "RegQueryValueExW"

/*
 *
 */
TCHAR selfPath[MAX_PATH];

/*
 * Prototype of functions to be hooked.
 */
typedef WINBOOL WINAPI (*PCREATEPROCESSW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, WINBOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
        LPPROCESS_INFORMATION);

typedef LONG WINAPI (*PREGOPENKEYEXW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);

typedef LONG WINAPI (*PREGQUERYVALUEEXW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

/*
 * Detour structure of the hooked functions.
 */
DETOUR DetourCreateProcessW;

DETOUR DetourRegOpenKeyExW;

DETOUR DetourRegQueryValueExW;

BOOL AppliedCreateProcessW;

BOOL AppliedRegOpenKeyExW;

BOOL AppliedRegQueryValueExW;

HKEY installPermissionKey;

/**
 * HookRegOpenKeyExW hook function. Saves the registry key handle for "InstallAddonsPermission" key for later use in the HookRegQueryValueExW
 * function. There should be no concurrency problems as both calls (the one to RegOpenKeyExW and RegQueryValueExW) are made in sequence and in
 * the same thread.
 */
LONG WINAPI HookRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
    LONG result = ((PREGOPENKEYEXW)DetourRegOpenKeyExW.OriginalAddress)(hKey, lpSubKey, ulOptions, samDesired, phkResult);

    if (wcsicmp(lpSubKey, L"InstallAddonsPermission") == 0) {
        installPermissionKey = *phkResult;
    }

    return result;
}

/**
 * HookRegQueryValueExW hook function. Change the necessary values when these are being queried.
 */
LONG WINAPI HookRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {

    if (lpData != NULL && lpcbData != NULL) {
        if (wcsicmp(lpValueName, L"BlockAboutAddons") == 0) {
            *((LPDWORD)lpData) = 0;
            *lpcbData = 4;

            return ERROR_SUCCESS;
        }
        else if (wcsicmp(lpValueName, L"Default") == 0 && hKey == installPermissionKey) {
            *((LPDWORD)lpData) = 1;
            *lpcbData = 4;

            return ERROR_SUCCESS;
        }
    }

    return ((PREGQUERYVALUEEXW)DetourRegQueryValueExW.OriginalAddress)(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

/**
 * CreateProcessW hook function. Firefox likes to create child processes / fork when launched from another application, this way we guarantee the
 * library is injected in the newly created process. Firefox also uses CreateProcessAsUserW for this, but tests have shown hooking that function
 * and injecting the library is unstable and not really necessary.
 */
WINBOOL WINAPI HookCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
        WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation) {

    BOOL alreadyDefined = (dwCreationFlags & CREATE_SUSPENDED) == CREATE_SUSPENDED;

    if (alreadyDefined == FALSE) {
        dwCreationFlags |= CREATE_SUSPENDED;
    }

    if (((PCREATEPROCESSW)DetourCreateProcessW.OriginalAddress)(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
            bInheritHandles, dwCreationFlags, lpEnvironment,lpCurrentDirectory, lpStartupInfo, lpProcessInformation) == FALSE) {
        return FALSE;
    }

    InjectLibrary(lpProcessInformation->hProcess, selfPath);

    if (alreadyDefined == FALSE) {
        ResumeThread(lpProcessInformation->hThread);
    }

    return TRUE;
}

/**
 * Startup function that creates all the hooks.
 */
BOOL Startup() {
    AppliedCreateProcessW = AddImportDetour((ULONGLONG)GetModuleHandle(KERNEL32DLL), KERNELBASEDLL, CREATEPROCESSW, (ULONGLONG) HookCreateProcessW,
            &DetourCreateProcessW);

    if (AppliedCreateProcessW == FALSE) {
        return FALSE;
    }

    AppliedRegOpenKeyExW = AddImportDetour((ULONGLONG)GetModuleHandle(ADVAPI32DLL), KERNELBASEDLL, REGOPENKEYEXW, (ULONGLONG) HookRegOpenKeyExW,
            &DetourRegOpenKeyExW);

    if (AppliedRegOpenKeyExW == FALSE) {
        return FALSE;
    }

    AppliedRegQueryValueExW = AddImportDetour((ULONGLONG)GetModuleHandle(ADVAPI32DLL), KERNELBASEDLL, REGQUERYVALUEEXW, (ULONGLONG) HookRegQueryValueExW,
            &DetourRegQueryValueExW);

    if (AppliedRegQueryValueExW == FALSE) {
        return FALSE;
    }
    
    return TRUE;
}

/**
 * Cleanup function that removes all the applied hooks.
 */
void Cleanup() {
    if (AppliedRegQueryValueExW == TRUE) {
        RemoveDetour(&DetourRegQueryValueExW);
    }

    if (AppliedRegOpenKeyExW == TRUE) {
        RemoveDetour(&DetourRegOpenKeyExW);
    }

    if (AppliedCreateProcessW == TRUE) {
        RemoveDetour(&DetourCreateProcessW);
    }
}

/**
 * Library entry point.
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(lpReserved);

    DisableThreadLibraryCalls(hinstDLL);

    BOOL result = TRUE;

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            if (GetModuleFileName(hinstDLL, selfPath, MAX_PATH) == 0) {
                result = FALSE;
            }
            else {
                result = Startup();
            }
            break;

        case DLL_PROCESS_DETACH:
            Cleanup();
            break;
    }

    return result;
}
