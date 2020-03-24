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
#include <stdio.h>
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "resource.h"
#include "helper.h"
#include "inject.h"

INT wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR lpCmdLine, INT nCmdShow) {
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    // Structure for control initialization.
    INITCOMMONCONTROLSEX commonControls;
    commonControls.dwSize = sizeof(INITCOMMONCONTROLSEX);
    commonControls.dwICC = ICC_LISTVIEW_CLASSES;
    
    InitCommonControlsEx(&commonControls);

    TCHAR firefoxExecutable[MAX_PATH];
    ZeroMemory(firefoxExecutable, sizeof(TCHAR) * MAX_PATH);

    TCHAR bypassLibrary[MAX_PATH];
    ZeroMemory(bypassLibrary, sizeof(TCHAR) * MAX_PATH);

    OPENFILENAME selectedFile;
    ZeroMemory(&selectedFile, sizeof(OPENFILENAME));
    selectedFile.lStructSize = sizeof(OPENFILENAME);
    selectedFile.hwndOwner = NULL;
    selectedFile.lpstrFilter = TEXT("Firefox Executable\0firefox.exe\0");
    selectedFile.lpstrFile = firefoxExecutable;
    selectedFile.nMaxFile = MAX_PATH;
    selectedFile.lpstrTitle = TEXT("Select Firefox Executable");
    selectedFile.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;
  
    if (GetOpenFileName(&selectedFile) == FALSE) {
        return -1;
    }

    ZeroMemory(&selectedFile, sizeof(OPENFILENAME));
    selectedFile.lStructSize = sizeof(OPENFILENAME);
    selectedFile.hwndOwner = NULL;
    selectedFile.lpstrFilter = TEXT("GPO Bypass Library\0library.dll\0");
    selectedFile.lpstrFile = bypassLibrary;
    selectedFile.nMaxFile = MAX_PATH;
    selectedFile.lpstrTitle = TEXT("Select GPO Bypass Library");
    selectedFile.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;
  
    if (GetOpenFileName(&selectedFile) == FALSE) {
        return -2;
    }
    
    STARTUPINFO startupInfo;
    ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
    startupInfo.cb = sizeof(STARTUPINFO);

    PROCESS_INFORMATION processInfo;
    ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

    if (CreateProcess(NULL, firefoxExecutable, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo) != TRUE) {
         return -3;
    }

    if (InjectLibrary(processInfo.hProcess, bypassLibrary) == FALSE) {
        ResumeThread(processInfo.hThread);

         CloseHandle(processInfo.hProcess);
         CloseHandle(processInfo.hThread);

        return -4;
    }

    ResumeThread(processInfo.hThread);

    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    return 0;
}
