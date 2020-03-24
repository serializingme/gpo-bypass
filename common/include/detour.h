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

#ifndef DETOUR_H
#define DETOUR_H

/**
 * Types of detours.
 */
#define TYPE_NONE   0x00
#define TYPE_EXPORT 0x02
#define TYPE_IMPORT 0x04

/**
 * Structure to hold the information of a detour.
 */
typedef struct _DETOUR {
    BYTE Type;
    ULONGLONG ModuleAddress;
    ULONGLONG OriginalAddress;
    ULONGLONG HookAddress;
    ULONGLONG TrampolineAddress;
    ULONGLONG OwnerAddress;
} DETOUR,*PDETOUR;

/**
 * Detours management functions.
 */
BOOL AddExportDetour(LPCTSTR moduleName, LPCSTR functionName, ULONGLONG hookAddress, PDETOUR detour);

BOOL AddImportDetour(ULONGLONG ownerAddress, LPCTSTR moduleName, LPSTR functionName, ULONGLONG hookAddress, PDETOUR detour);

BOOL RemoveDetour(PDETOUR detour);

#endif
