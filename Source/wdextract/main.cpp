/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2026
*
*  TITLE:       WDEXTRACT.CPP
*
*  VERSION:     1.13
*
*  DATE:        11 Apr 2026
*
*  WDEXTRACT commands parsing and entrypoint.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* ExtractDataCommand
*
* Purpose:
*
* Extract data worker routine, determinate input file type and process it.
*
*/
void ExtractDataCommand(
    _In_ LPCWSTR FileName,
    _In_ BOOLEAN ExtractImageChunks,
    _In_ BOOLEAN ExtractContainerOnly)
{
    UINT Result;
    ULONG TotalBytesWritten = 0, TotalBytesRead = 0, NumberOfImageChunks = 0;
    IMAGE_NT_HEADERS* NtHeaders;
    WCHAR szTotalMsg[240];

    PVOID ImageBase = MapContainerFile(FileName);
    if (ImageBase == NULL) {
        ShowWin32Error(GetLastError(), __FUNCTIONW__);
        return;
    }

    NtHeaders = ImageNtHeader(ImageBase);
    if (NtHeaders == NULL) {
        ShowWin32Error(ERROR_BAD_EXE_FORMAT, __FUNCTIONW__);
        UnmapViewOfFile(ImageBase);
        return;
    }

    //
    // Rough check if this is MRT.
    //
    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        if (ExtractContainerOnly) {
            wprintf_s(L"ExtractDataDll: Attempt to extract raw RMDX data from VDM container\r\n");
        }
        else {
            wprintf_s(L"ExtractDataDll: Attempt to unpack VDM container\r\n");
        }

        Result = ExtractDataDll(FileName,
            ImageBase,
            &TotalBytesWritten,
            &TotalBytesRead,
            ExtractImageChunks,
            &NumberOfImageChunks,
            ExtractContainerOnly);

    }
    else {
        if (ExtractContainerOnly) {
            wprintf_s(L"ExtractDataEXE: Attempt to extract raw RMDX data from MRT container\r\n");
        }
        else {
            wprintf_s(L"ExtractDataEXE: Attempt to extract and decrypt MRT container\r\n");
        }

        Result = ExtractDataEXE(FileName,
            ImageBase,
            &TotalBytesWritten,
            &TotalBytesRead,
            ExtractImageChunks,
            &NumberOfImageChunks,
            ExtractContainerOnly);

    }

    if (Result == ERROR_SUCCESS && !ExtractContainerOnly) {
        if (ExtractImageChunks) {
            StringCbPrintf(szTotalMsg,
                _countof(szTotalMsg),
                L"\r\nStats: \r\nRead bytes = %lu (%lu KB)\r\nWritten bytes = %lu (%lu KB)\r\nImage chunks = %lu",
                TotalBytesRead,
                TotalBytesRead / 1024,
                TotalBytesWritten,
                TotalBytesWritten / 1024,
                NumberOfImageChunks);
        }
        else {
            StringCbPrintf(szTotalMsg,
                _countof(szTotalMsg),
                L"\r\nStats: \r\nRead bytes = %lu (%lu KB)\r\nWritten bytes = %lu (%lu KB)",
                TotalBytesRead,
                TotalBytesRead / 1024,
                TotalBytesWritten,
                TotalBytesWritten / 1024);
        }
        wprintf_s(L"%s", szTotalMsg);
    }
    else if (Result != ERROR_SUCCESS) {
        ShowWin32Error(Result, __FUNCTIONW__);
    }

    UnmapViewOfFile(ImageBase);
}

/*
* MergeDeltaCommand
*
* Purpose:
*
* Merge data worker routine.
*
*/
void MergeDeltaCommand(
    _In_ LPCWSTR BaseFileName,
    _In_ LPCWSTR DeltaFileName,
    _In_ BOOLEAN ExtractImageChunks,
    _In_ BOOLEAN VerifyChecksum)
{
    ULONG TotalBytesWritten = 0, NumberOfImageChunks = 0;

    UINT Result = MergeDeltaFiles(
        BaseFileName,
        DeltaFileName,
        &TotalBytesWritten,
        ExtractImageChunks,
        &NumberOfImageChunks,
        VerifyChecksum);

    if (Result == ERROR_SUCCESS) {
        WCHAR szTotalMsg[240];

        if (ExtractImageChunks) {
            if (SUCCEEDED(StringCchPrintf(szTotalMsg,
                _countof(szTotalMsg),
                L"\r\nStats: \r\nWritten bytes = %lu (%lu KB)\r\nImage chunks = %lu",
                TotalBytesWritten,
                TotalBytesWritten / 1024,
                NumberOfImageChunks)))
            {
                wprintf_s(L"%s", szTotalMsg);
            }
        }
        else {
            if (SUCCEEDED(StringCchPrintf(szTotalMsg,
                _countof(szTotalMsg),
                L"\r\nStats: \r\nWritten bytes = %lu (%lu KB)",
                TotalBytesWritten,
                TotalBytesWritten / 1024)))
            {
                wprintf_s(L"%s", szTotalMsg);
            }
        }
    }
    else {
        ShowWin32Error(Result, L"MergeDeltaFiles()");
    }
}

/*
* main
*
* Purpose:
*
* Program entry point (CRT).
*
*/
int __cdecl main()
{
    INT nArgs = 0;
    BOOLEAN fCommand = FALSE, fExtractImageChunks = FALSE, fMergeDelta = FALSE, fExtractContainerOnly = FALSE, fVerifyMergeChecksum = FALSE;
    LPWSTR DeltaFileName = NULL;
    LPWSTR* szArglist = NULL;

    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

    wprintf_s(L"%s built at %s %s\r\n", WDEXTRACT_VERSION, TEXT(__DATE__), WDEXTRACT_COPYRIGHT);

    __try {
        szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
        if (szArglist) {
            if (nArgs > 1) {
                LPWSTR BaseFileName = szArglist[1];

                // Parse flags and find delta file name if present
                for (INT i = 2; i < nArgs; i++) {
                    if (_wcsicmp(szArglist[i], L"-e") == 0) {
                        fExtractImageChunks = TRUE;
                    }
                    else if (_wcsicmp(szArglist[i], L"-m") == 0) {
                        fMergeDelta = TRUE;
                    }
                    else if (_wcsicmp(szArglist[i], L"-ec") == 0) {
                        fExtractContainerOnly = TRUE;
                    }
                    else if (_wcsicmp(szArglist[i], L"-mc") == 0) {
                        fVerifyMergeChecksum = TRUE;
                    }
                    else if (DeltaFileName == NULL) {
                        DeltaFileName = szArglist[i];
                    }
                }

                // Check for incompatible flags
                if (fExtractContainerOnly && (fExtractImageChunks || fMergeDelta)) {
                    wprintf_s(L"Error: -ec option is incompatible with -e and -m options\r\n");
                }
                else if (fVerifyMergeChecksum && !fMergeDelta) {
                    wprintf_s(L"Warning: -mc option is only used with -m\r\n");
                }
                else if (fMergeDelta) {
                    if (DeltaFileName) {
                        MergeDeltaCommand(BaseFileName, DeltaFileName, fExtractImageChunks, fVerifyMergeChecksum);
                        fCommand = TRUE;
                    }
                    else {
                        wprintf_s(L"Error: Delta file not specified for merge operation\r\n");
                    }
                }
                else {
                    ExtractDataCommand(BaseFileName, fExtractImageChunks, fExtractContainerOnly);
                    fCommand = TRUE;
                }
            }
            LocalFree(szArglist);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        wprintf_s(L"Exception caught in command line parsing: %lu\r\n", GetExceptionCode());
    }

    if (fCommand != TRUE)
        wprintf_s(L"Usage: wdextract file [-e]\n"
            L"       wdextract file [-ec]\n"
            L"       wdextract baseFile deltaFile -m [-e] [-mc]\n"
            L"       wdextract baseFile -m deltaFile [-e] [-mc]");
    else
        wprintf_s(L"\r\nBye!");

    return 0;
}
