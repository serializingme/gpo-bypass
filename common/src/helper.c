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

/**
 * Function to obtain the address of a loaded module. Returns false if the specified module isn't found. Currently a simple wrapper around the
 * Windows API.
 */
BOOL GetModuleAddress(LPCTSTR moduleName, ULONGLONG *moduleAddress) {
    return ((*moduleAddress = (ULONGLONG)GetModuleHandle(moduleName)) != 0L);
}

/**
 * Function to obtain the address of a exported symbol of a module. Returns false if the specified function isn't found.  Currently a simple
 * wrapper around the Windows API.
 */
BOOL GetExportedSymbol(ULONGLONG moduleAddress, LPCSTR symbolName, ULONGLONG *symbolAddress) {
    return ((*symbolAddress = (ULONGLONG)GetProcAddress((HMODULE)moduleAddress, symbolName)) != 0L);
}

/**
 * Searches for the section of a in-memory module that contains the specidied address. It returns true if the
 * section is found, false otherwise. The section bounds are returned in scLowerAddress and scUpperAddress.
 */
// TODO Add supplied parameter validation: scLowerAddress and scUpperAddress not null, etc.
BOOL GetSectionBounds(ULONGLONG module, ULONGLONG address, PULONGLONG scLowerAddress, PULONGLONG scUpperAddress) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) module;

    if (dosHeader == NULL || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeader = MAKEPTR(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_SECTION_HEADER scHeader = MAKEPTR(PIMAGE_SECTION_HEADER, ntHeader, sizeof(IMAGE_NT_HEADERS));

    for (int index = 0; index < ntHeader->FileHeader.NumberOfSections; ++index) {
        ULONGLONG lowerAddress = MAKEPTR(ULONGLONG, dosHeader, scHeader->VirtualAddress);
        ULONGLONG upperAddress = MAKEPTR(ULONGLONG, lowerAddress, scHeader->Misc.VirtualSize);

        if (address > lowerAddress && address < upperAddress) {
            *scLowerAddress = lowerAddress;
            *scUpperAddress = upperAddress;

            return TRUE;
        }

        scHeader = MAKEPTR(PIMAGE_SECTION_HEADER, scHeader, sizeof(IMAGE_SECTION_HEADER));
    }

    return FALSE;
}

/**
 * Searches for a specific pattern in memory. The pattern to search for is specified in the pattern variable
 * using byte escapes. The mask variable sepcifies of those bytes which ones are wildcards. the startAddress
 * and endAddress specify the bounds of where to search.
 * 
 * Make sure the pattern and the mask have the exact same length in characters as the mask length is the one
 * that will be used since the pattern may contain null bytes.
 */
// TODO Add supplied parameter validation: startAddress less than endAddress, patternAddress isn't null, etc.
BOOL FindPattern(LPCSTR pattern, LPCSTR mask, ULONGLONG startAddress, ULONGLONG endAddress, PULONGLONG patternAddress) {
    ULONGLONG length = strlen(mask);

    for (ULONGLONG currAddress = startAddress; currAddress < endAddress; ++currAddress) {
        ULONGLONG index;

        // Note that if the current address plus the number of bytes we want to search for is biggger than the
        // maximum searchable address, it will not enter the search loop. This is intentional to avoid the
        // search going out of bounds.
        for (index = 0; index < length && currAddress + length <= endAddress; ++index) {
            BYTE actual = *MAKEPTR(PBYTE, currAddress, index);
            BYTE wanted = *MAKEPTR(PBYTE, pattern, index);

            // Different byte in memory than the the one specified in the pattern and specified in the mask as
            // non-wildcard.
            if (actual != wanted && mask[index] == 'b') {
                break;
            }
        }
        
        if (index == length) {
            *patternAddress = currAddress;

            return TRUE;
        }
    }

    return FALSE;
}
