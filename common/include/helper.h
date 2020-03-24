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

#ifndef HELPER_H
#define HELPER_H

/**
 * Helper macros for dealing with pointers.
 */
#define MAKEPTR(type, address, offset) \
    (type)((ULONGLONG)(address) + (ULONGLONG)(offset))

#define MAKEDLT(type, address, offset) \
    (type)((ULONGLONG)(address) - (ULONGLONG)(offset))

/**
 * Portable Executable functions.
 */
BOOL GetModuleAddress(LPCTSTR moduleName, ULONGLONG *moduleAddress);

BOOL GetExportedSymbol(ULONGLONG moduleAddress, LPCSTR symbolName, ULONGLONG *symbolAddress);

BOOL GetSectionBounds(ULONGLONG module, ULONGLONG address, PULONGLONG scLowerAddress, PULONGLONG scUpperAddress);

/**
 * Pattern related functions.
 */
BOOL FindPattern(LPCSTR pattern, LPCSTR mask, ULONGLONG startAddress, ULONGLONG endAddress, PULONGLONG caveAddress);

#endif
