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

#include "helper.h"
#include "detour.h"

#define CAVE_PATTERN "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
#define CAVE_MASK "bbbbbbbbbbbb"

#define TRAMPOLINE_PATTERN "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xE0"
#define TRAMPOLINE_MASK "bb????????bb"
#define TRAMPOLINE_LENGTH 12

/**
 * Detours a imported function. This function doesn't skip DLL entries in the Import Address Table by name. It only cares about the address of the
 * target function. The ownerAddress is the address to the library/executable that is importing the function.It can be used to add a detour and
 * remove a detour provided the correct addresses are used.
 */
BOOL DetourImportedSymbol(ULONGLONG ownerAddress, ULONGLONG symbolAddress, ULONGLONG hookAddress) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) ownerAddress;

    if (dosHeader == NULL || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeader = MAKEPTR(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = MAKEPTR(PIMAGE_IMPORT_DESCRIPTOR, dosHeader,
            ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDescriptor->Characteristics) {  
        PIMAGE_THUNK_DATA frstThunk = MAKEPTR(PIMAGE_THUNK_DATA, dosHeader, importDescriptor->FirstThunk);

        while (frstThunk->u1.Function) {
            ULONGLONG importAddress = frstThunk->u1.Function;

            if (importAddress == symbolAddress) {
                DWORD oldProtection, ignoredProtection;

                if (VirtualProtect(&frstThunk->u1.Function, sizeof(ULONGLONG), PAGE_READWRITE, &oldProtection) == FALSE) {
                    return FALSE;
                }

                frstThunk->u1.Function = hookAddress;
                
                VirtualProtect(&frstThunk->u1.Function, sizeof(ULONGLONG), oldProtection, &ignoredProtection);

                return TRUE;
            }

            ++frstThunk;
        }

        ++importDescriptor;
    }

    return FALSE;
}

/**
 * Detour an imported function.
 */
BOOL AddImportDetour(ULONGLONG ownerAddress, LPCTSTR moduleName, LPSTR functionName, ULONGLONG hookAddress, PDETOUR detour) {
    ULONGLONG moduleAddress;
    ULONGLONG functionAddress;

    if (GetModuleAddress(moduleName, &moduleAddress) == FALSE) {
        return FALSE;
    }

    if (GetExportedSymbol(moduleAddress, functionName, &functionAddress) == FALSE) {
        return FALSE;
    }

    if (DetourImportedSymbol(ownerAddress, functionAddress, hookAddress) == FALSE) {
        return FALSE;
    }

    detour->Type = TYPE_IMPORT;
    detour->ModuleAddress = moduleAddress;
    detour->HookAddress = hookAddress;
    detour->OriginalAddress = functionAddress;
    detour->TrampolineAddress = 0L;
    detour->OwnerAddress = ownerAddress;

    return TRUE;
}

/**
 * Writes a x86_64 trampoline into any code cave existing in between the specified upper and lower address. The trampoline written is of the following form.
 * 
 * 48 B8 ?? ?? ?? ?? ?? ?? ?? ??    mov rax, destinationAddress
 * FF E0                            jmp rax
 * 
 * The trampoline requires 12 bytes of writable space. This function changes the memory page protection and restores it. It will only fail if changing
 * the memory page to writable fails. If restoring the original memory protection fails the function will return success as the memory protection is
 * still executable.
 */
BOOL WriteTrampoline(ULONGLONG lowerAddress, ULONGLONG upperAddress, ULONGLONG destinationAddress, PULONGLONG trampolineAddress) {
    ULONGLONG caveAddress;

    if (FindPattern(CAVE_PATTERN, CAVE_MASK, lowerAddress, upperAddress, &caveAddress) == FALSE) {
        return FALSE;
    }

    DWORD oldProtection, ignoredProtection;

    if (VirtualProtect((LPVOID)caveAddress, 12, PAGE_EXECUTE_READWRITE, &oldProtection) == FALSE) {
        return FALSE;
    }

    *(PUSHORT)(caveAddress + 0) = 0xB848;
    *(PULONGLONG)(caveAddress + 2) = destinationAddress;
    *(PUSHORT)(caveAddress + 10) = 0xE0FF;

    VirtualProtect((LPVOID)caveAddress, 12, oldProtection, &ignoredProtection);

    *trampolineAddress = caveAddress;

    return TRUE;
}

/**
 * Erase a trampoline using "int 3" instructions. It will verify if the address does contain a trampoline pattern before filling the memory
 * with breakpoints.
 */
BOOL EraseTrampoline(ULONGLONG trampolineAddress) {
    ULONGLONG verificationAddress;

    if (FindPattern(TRAMPOLINE_PATTERN, TRAMPOLINE_MASK, trampolineAddress, trampolineAddress + TRAMPOLINE_LENGTH,
            &verificationAddress) == FALSE) {
        return FALSE;
    }

    DWORD oldProtection, ignoredProtection;

    if (VirtualProtect((LPVOID)trampolineAddress, TRAMPOLINE_LENGTH, PAGE_EXECUTE_READWRITE, &oldProtection) == FALSE) {
        return FALSE;
    }

    *(PULONGLONG)(trampolineAddress + 0) = 0xCCCCCCCCCCCCCCCC;
    *(PULONG)(trampolineAddress + 8) = 0xCCCCCCCC;

    VirtualProtect((LPVOID)trampolineAddress, TRAMPOLINE_LENGTH, oldProtection, &ignoredProtection);

    return TRUE;
}

/**
 * In essence, this function changes the address on the Export Address Table of an exported symbol. It can be used to add a detour and remove a detour
 * provided the correct addresses are used.
 */
BOOL DetourExportedSymbol(ULONGLONG moduleAddress, ULONGLONG symbolAddress, ULONGLONG hookAddress) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) moduleAddress;

    if (dosHeader == NULL || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeader = MAKEPTR(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_EXPORT_DIRECTORY expDescriptor = MAKEPTR(PIMAGE_EXPORT_DIRECTORY, dosHeader,
            ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PULONG exportOffsets = MAKEPTR(PULONG, dosHeader, expDescriptor->AddressOfFunctions);

    for (DWORD index = 0; index < expDescriptor->NumberOfNames; ++index) {
        ULONGLONG exportAddress = MAKEPTR(ULONGLONG, dosHeader, exportOffsets[index]);

        if (exportAddress == symbolAddress) {
            DWORD oldProtection, ignoredProtection;

            if (VirtualProtect(&exportOffsets[index], sizeof(ULONG), PAGE_READWRITE, &oldProtection) == FALSE) {
                return FALSE;
            }

            exportOffsets[index] = MAKEDLT(ULONG, hookAddress, dosHeader);
            
            VirtualProtect(&exportOffsets[index], sizeof(ULONG), oldProtection, &ignoredProtection);

            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Detour an exported function.
 */
BOOL AddExportDetour(LPCTSTR moduleName, LPCSTR functionName, ULONGLONG hookAddress, PDETOUR detour) {
    ULONGLONG moduleAddress;
    ULONGLONG functionAddress;
    ULONGLONG scLowerAddress;
    ULONGLONG scUpperAddress;
    ULONGLONG trampolineAddress;

    if (GetModuleAddress(moduleName, &moduleAddress) == FALSE) {
        return FALSE;
    }

    if (GetExportedSymbol(moduleAddress, functionName, &functionAddress) == FALSE) {
        return FALSE;
    }

    if (GetSectionBounds(moduleAddress, functionAddress, &scLowerAddress, &scUpperAddress) == FALSE) {
        return FALSE;
    }

    if (WriteTrampoline(scLowerAddress, scUpperAddress, hookAddress, &trampolineAddress) == FALSE) {
        return FALSE;
    }

    if (DetourExportedSymbol(moduleAddress, functionAddress, trampolineAddress) == FALSE) {
        EraseTrampoline(trampolineAddress);

        return FALSE;
    }
    
    detour->Type = TYPE_EXPORT;
    detour->ModuleAddress = moduleAddress;
    detour->HookAddress = hookAddress;
    detour->OriginalAddress = functionAddress;
    detour->TrampolineAddress = trampolineAddress;
    detour->OwnerAddress = 0L;

    return TRUE;
}

/**
 * Removes a applied detour.
 */
BOOL RemoveDetour(PDETOUR detour) {
    BOOL result = FALSE;

    if ((detour->Type & TYPE_EXPORT) == TYPE_EXPORT) {
        result = DetourExportedSymbol(detour->ModuleAddress, detour->TrampolineAddress, detour->OriginalAddress);

        if (result == TRUE) {
            EraseTrampoline(detour->TrampolineAddress);
        }
    }
    else if ((detour->Type & TYPE_IMPORT) == TYPE_IMPORT) {
        result = DetourImportedSymbol(detour->OwnerAddress, detour->HookAddress, detour->OriginalAddress);
    }

    if (result == TRUE) {
        SecureZeroMemory(detour, sizeof(DETOUR));
    }

    return result;
}
