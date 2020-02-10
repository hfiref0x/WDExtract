/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       WDEXTRACT.CPP
*
*  VERSION:     1.03
*
*  DATE:        10 Feb 2020
*
*  WDEXTRACT main logic and entrypoint.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#define MAX_FILENAME_BUFFER_LENGTH 1024

#define DEFAULT_CHUNK_NAME          L"module"
#define DEFAULT_CHUNK_NAME_NIS      L"nis_module"

#define CODEBLOB_OPEN               L"<CodeBlob>"
#define CODEBLOB_CLOSE              L"</CodeBlob>"

#define WDEXTRACT_VERSION           "wdextract 1.03"

typedef struct _LANGANDCODEPAGE {
    WORD wLanguage;
    WORD wCodePage;
} LANGANDCODEPAGE, *LPTRANSLATE;

/*
* ExtractCallback
*
* Purpose:
*
* Save image chunk to file with original name (either from export directory or file version info).
*
*/
ULONG ExtractCallback(
    _In_ LPWSTR CurrentDirectory,
    _In_ PVOID ChunkPtr,
    _In_ ULONG ChunkLength,
    _In_ ULONG ChunkId,
    _In_ BOOLEAN fNIS)
{
    BOOLEAN FileNameAvailable;
    ULONG Result = ERROR_SUCCESS;
    HANDLE FileHandle;
    WCHAR szImageName[MAX_PATH + 1];
    WCHAR ImageChunkFileName[MAX_FILENAME_BUFFER_LENGTH + 1];
    WCHAR ImageChunkFileName2[MAX_FILENAME_BUFFER_LENGTH + 1];

    LPCWSTR lpDefaultChunkName;

    if (fNIS)
        lpDefaultChunkName = DEFAULT_CHUNK_NAME_NIS;
    else
        lpDefaultChunkName = DEFAULT_CHUNK_NAME;

    RtlSecureZeroMemory(szImageName, sizeof(szImageName));
    FileNameAvailable = ExtractImageNameFromExport(ChunkPtr, (LPWSTR)&szImageName, MAX_PATH);

    if (FileNameAvailable) {

        RtlSecureZeroMemory(ImageChunkFileName, sizeof(ImageChunkFileName));
        StringCchPrintf(ImageChunkFileName, MAX_FILENAME_BUFFER_LENGTH,
            TEXT("%s\\chunks\\%s_%s%u.dll"), CurrentDirectory, szImageName, lpDefaultChunkName, ChunkId);

        FileHandle = FileCreate(ImageChunkFileName);
        if (FileHandle != INVALID_HANDLE_VALUE) {
            FileWrite((PBYTE)ChunkPtr, ChunkLength, FileHandle);
            FileClose(FileHandle);
        }
        else {
            return GetLastError();
        }

    }
    else {

        DWORD dwSize;
        DWORD dwHandle;
        PVOID vinfo = NULL;
        LPTRANSLATE lpTranslate = NULL;
        LPWSTR lpOriginalFileName;

        WCHAR szKey[100 + 1];

        StringCchPrintf(ImageChunkFileName, MAX_FILENAME_BUFFER_LENGTH,
            TEXT("%s\\chunks\\%s%u.dll"), CurrentDirectory, lpDefaultChunkName, ChunkId);

        FileHandle = FileCreate(ImageChunkFileName);
        if (FileHandle != INVALID_HANDLE_VALUE) {
            FileWrite((PBYTE)ChunkPtr, ChunkLength, FileHandle);
            FileClose(FileHandle);
        }
        else {
            return GetLastError();
        }

        dwSize = GetFileVersionInfoSize(ImageChunkFileName, &dwHandle);
        if (dwSize) {
            vinfo = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)dwSize);
            if (vinfo) {
                if (GetFileVersionInfo(ImageChunkFileName, 0, dwSize, vinfo)) {

                    dwSize = 0;
                    if (VerQueryValue(vinfo,
                        L"\\VarFileInfo\\Translation",
                        (LPVOID*)&lpTranslate,
                        (PUINT)&dwSize))
                    {
                        StringCchPrintf(szKey, 100, TEXT("\\StringFileInfo\\%04x%04x\\OriginalFileName"),
                            lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

                        if (VerQueryValue(vinfo, szKey, (LPVOID*)&lpOriginalFileName, (PUINT)&dwSize)) {

                            RtlSecureZeroMemory(ImageChunkFileName2, sizeof(ImageChunkFileName2));
                            StringCchPrintf(ImageChunkFileName2, MAX_FILENAME_BUFFER_LENGTH,
                                TEXT("%s\\chunks\\%s_%s%u.dll"), CurrentDirectory, lpOriginalFileName, lpDefaultChunkName, ChunkId);
                            if (!MoveFileEx(ImageChunkFileName, ImageChunkFileName2,
                                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                            {
                                Result = GetLastError();
                            }
                        }
                    }
                }
                LocalFree(vinfo);
            }
            else {
                Result = GetLastError();
            }
        }
    }

    return Result;
}

/*
* ExtractDataXML_BruteForce
*
* Purpose:
*
* Extract image chunks from XML scheme.
*
*/
UINT ExtractDataXML_BruteForce(
    _In_ LPWSTR szCurrentDirectory,
    _In_ PVOID Container,
    _In_ LPCWSTR OpenElement,
    _In_ LPCWSTR CloseElement,
    _Out_ PULONG ExtractedChunks
)
{
    ULONG ctr = 0;
    SIZE_T tl1, tl2;
    CDATA_HEADER_NIS *NisDataHeader = (CDATA_HEADER_NIS*)Container;
    PWCHAR p = (PWCHAR)&NisDataHeader->Data;

    INT nLength = MultiByteToWideChar(CP_ACP, 0, (CHAR*)p, -1, NULL, 0);
    if (nLength) {
        LPWSTR pConverted = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, (1 + (SIZE_T)nLength) * sizeof(WCHAR));
        if (pConverted) {

            tl1 = wcslen(OpenElement);
            tl2 = wcslen(CloseElement);

            MultiByteToWideChar(CP_ACP, 0, (CHAR*)p, -1, pConverted, nLength);

            PWCHAR CurrentPosition = pConverted;
            PWCHAR MaximumPosition = (PWCHAR)(pConverted + wcslen(pConverted)) - tl2;

            while (CurrentPosition < MaximumPosition) {

                WCHAR *OpenBlob = wcsstr(CurrentPosition, OpenElement);
                if (OpenBlob) {

                    OpenBlob += tl1;
                    ULONG ChunkLength = 0;
                    WCHAR *ptr = OpenBlob;
                    if (ptr) {
                        while ((*ptr != L'<') && (ptr < MaximumPosition)) {
                            ChunkLength++;
                            ptr++;
                        }
                    }
                    if (ptr) {

                        DWORD cbBinary = 0;
                        CryptStringToBinary(OpenBlob, (DWORD)ChunkLength,
                            CRYPT_STRING_BASE64, NULL, (DWORD*)&cbBinary, NULL, NULL);

                        BYTE *pbBinary = (BYTE*)LocalAlloc(LMEM_ZEROINIT, cbBinary);
                        if (pbBinary) {

                            if (CryptStringToBinary(OpenBlob, (DWORD)ChunkLength,
                                CRYPT_STRING_BASE64, pbBinary, &cbBinary, NULL, NULL))
                            {
                                printf_s("%s: Found image at position %08IX with size = %lu\r\n", __FUNCTION__,
                                    (ULONG_PTR)OpenBlob,
                                    ChunkLength);

                                ExtractCallback(szCurrentDirectory, pbBinary, cbBinary, ctr, TRUE);
                                ++ctr;
                            }
                            LocalFree(pbBinary);
                        }

                    }

                    CurrentPosition = (OpenBlob + ChunkLength);
                    continue;
                }

                CurrentPosition++;
            }

        }
    }

    *ExtractedChunks = ctr;

    return ERROR_SUCCESS;
}

/*
* ExtractDataDll
*
* Purpose:
*
* Extract VDM database from compressed container.
*
*/
UINT ExtractDataDll(
    _In_ LPWSTR FileName,
    _In_ PVOID ImageBase,
    _Out_ PULONG TotalBytesWritten,
    _Out_ PULONG TotalBytesRead,
    _In_ BOOLEAN ExtractImageChunks,
    _Out_opt_ PULONG ExtractedChunks
)
{
    UINT Result = 0;
    BOOLEAN IsCompressed;

    ULONG ContainerSize = 0, totalBytesWritten = 0, cError;

    LPWSTR  NewFileName;
    size_t  FileNameLength = 0;

    PVOID Data;
    PRMDX_HEADER ContainerHeader;
    PCDATA_HEADER DataHeader;

    HANDLE OutputFileHandle;

    WCHAR szCurrentDirectory[MAX_PATH + 1];

    __try {

        printf_s("%s: Attempt to unpack VDM container\r\n", __FUNCTION__);

        RtlSecureZeroMemory(szCurrentDirectory, sizeof(szCurrentDirectory));
        GetCurrentDirectory(MAX_PATH, szCurrentDirectory);

        *TotalBytesWritten = 0;
        *TotalBytesRead = 0;
        if (ExtractedChunks)
            *ExtractedChunks = 0;

        Data = GetContainerFromResource(ImageBase, &ContainerSize);
        if (Data == NULL)
            return ERROR_RESOURCE_NAME_NOT_FOUND;

        if (!IsValidContainer(Data, ContainerSize))
            return ERROR_INVALID_DATA;

        ContainerHeader = (PRMDX_HEADER)Data;

        IsCompressed = ((ContainerHeader->Options >> 1) & 0xff);
        if (IsCompressed == FALSE)
            return ERROR_UNKNOWN_REVISION;

        DataHeader = (PCDATA_HEADER)RtlOffsetToPointer(ContainerHeader, ContainerHeader->DataOffset);

        if (FAILED(StringCchLength(FileName, MAX_PATH, &FileNameLength))) {
            return GetLastError();
        }

        FileNameLength += (1 + MAX_PATH);
        NewFileName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, FileNameLength * sizeof(WCHAR));
        if (NewFileName == NULL)
            return GetLastError();

        StringCchPrintf(NewFileName, FileNameLength, TEXT("%s.extracted"), FileName);

        OutputFileHandle = FileCreate(NewFileName);
        LocalFree(NewFileName);

        if (OutputFileHandle == INVALID_HANDLE_VALUE)
            return GetLastError();

        if (!ZLibUnpack(DataHeader, OutputFileHandle, &totalBytesWritten, TotalBytesRead))
            Result = ERROR_INTERNAL_ERROR;
        else
            Result = ERROR_SUCCESS;

        *TotalBytesWritten = totalBytesWritten;
        if (totalBytesWritten > 2) {
            if (ExtractImageChunks) {

                CreateDirectory(L"chunks", NULL);
                SetCurrentDirectory(L"chunks");

                ULONG ctr = 0;
                PBYTE ReadData = (PBYTE)LocalAlloc(LMEM_ZEROINIT, totalBytesWritten);
                if (ReadData) {

                    SetFilePointer(OutputFileHandle, 0, NULL, FILE_BEGIN);
                    FileRead(ReadData, totalBytesWritten, OutputFileHandle);

                    if (IsContainerNIS(ReadData)) {

                        printf_s("%s: Container is NIS\r\n", __FUNCTION__);

                        Result = ExtractDataXML_BruteForce(szCurrentDirectory,
                            ReadData,
                            CODEBLOB_OPEN,
                            CODEBLOB_CLOSE,
                            &ctr);

                    }
                    else {

                        ULONG CurrentPosition = 0;
                        ULONG SizeOfImage;
                        PBYTE CurrentPtr;
                        while (CurrentPosition < totalBytesWritten - sizeof(WORD)) {

                            CurrentPtr = (PBYTE)RtlOffsetToPointer(ReadData, CurrentPosition);

                            if ((*(PWORD)(CurrentPtr)) == 'ZM') {

                                SizeOfImage = 0;

                                if (IsValidImage(CurrentPtr) && GetImageSize(CurrentPtr, &SizeOfImage)) {

                                    if (CurrentPosition + SizeOfImage > totalBytesWritten) {
                                        break;
                                    }

                                    printf_s("%s: Found image at position %08X with size = %lu\r\n", __FUNCTION__,
                                        CurrentPosition,
                                        SizeOfImage);

                                    cError = ExtractCallback(szCurrentDirectory, CurrentPtr, SizeOfImage, ctr, NULL);

                                    if (cError != ERROR_SUCCESS) {
                                        ShowWin32Error(cError, "ExtractCallback()");
                                    }

                                    ++ctr;

                                    CurrentPosition += SizeOfImage;
                                    continue;
                                }

                            }

                            CurrentPosition += 1;
                        }

                    }
                    LocalFree(ReadData);
                }

                *ExtractedChunks = ctr;
            }

        }

        FileClose(OutputFileHandle);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return Result;
}

/*
* ExtractDataEXE
*
* Purpose:
*
* Extract VDM database from MRT container (Malicious software Removal Tool).
*
*/
UINT ExtractDataEXE(
    _In_ LPWSTR FileName,
    _In_ PVOID ImageBase,
    _Out_ PULONG TotalBytesWritten,
    _Out_ PULONG TotalBytesRead,
    _In_ BOOLEAN ExtractImageChunks,
    _Out_opt_ PULONG ExtractedChunks
)
{
    UINT Result = 0;

    HMODULE ExtractedModule = NULL;
    HANDLE tempFileHandle = INVALID_HANDLE_VALUE;

    ULONG Size = 0, ChunkLength, EntryLength, ContainerSize = 0;

    PBYTE DataPtr, DecodedBuffer;
    SIZE_T CurrentPosition, MaximumLength;
    PVOID Data;

    IMAGE_NT_HEADERS *NtHeaders;

    RMDX_HEADER *ContainerHeader;
    CDATA_HEADER *DataHeader;
    CHUNK_HEAD Chunk;

    LPWSTR  NewFileName;
    size_t  FileNameLength = 0;
    WCHAR szCurrentDirectory[MAX_PATH + 1];
    WCHAR TempFileName[MAX_PATH * 2];

    __try {

        printf_s("%s: Attempt to extract and decrypt MRT container\r\n", __FUNCTION__);

        *TotalBytesWritten = 0;
        *TotalBytesRead = 0;
        if (ExtractedChunks)
            *ExtractedChunks = 0;

        RtlSecureZeroMemory(szCurrentDirectory, sizeof(szCurrentDirectory));
        GetCurrentDirectory(MAX_PATH, szCurrentDirectory);

        Data = GetContainerFromResource(ImageBase, &Size);

        NtHeaders = ImageNtHeader(Data);
        if (NtHeaders == NULL) {
            return ERROR_RESOURCE_NAME_NOT_FOUND;
        }

        if ((NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
            return ERROR_UNKNOWN_COMPONENT;
        }

        RtlSecureZeroMemory(&TempFileName, sizeof(TempFileName));
        GetTempPath(MAX_PATH, TempFileName);
        StringCchCat(TempFileName, MAX_PATH, TEXT("mrt_vdm.dll"));

        tempFileHandle = FileCreate(TempFileName);
        if (tempFileHandle == INVALID_HANDLE_VALUE) {
            return GetLastError();
        }
        else {
            FileWrite((PBYTE)Data, Size, tempFileHandle);
            FileClose(tempFileHandle);
            tempFileHandle = INVALID_HANDLE_VALUE;
        }

        do {

            if (FAILED(StringCchLength(FileName, MAX_PATH, &FileNameLength))) {
                Result = GetLastError();
                break;
            }

            FileNameLength += (1 + MAX_PATH);
            NewFileName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, FileNameLength * sizeof(WCHAR));
            if (NewFileName == NULL) {
                Result = GetLastError();
                break;
            }

            StringCchPrintf(NewFileName, FileNameLength, TEXT("%s.extracted"), FileName);
            tempFileHandle = FileCreate(NewFileName);
            LocalFree(NewFileName);

            if (tempFileHandle == INVALID_HANDLE_VALUE) {
                Result = GetLastError();
                break;
            }

            ExtractedModule = LoadLibraryEx(TempFileName, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (ExtractedModule == NULL) {
                Result = GetLastError();
                break;
            }

            Data = GetContainerFromResource((PVOID)ExtractedModule, &ContainerSize);
            if (Data == NULL) {
                Result = ERROR_RESOURCE_NAME_NOT_FOUND;
                break;
            }

            if (!IsValidContainer(Data, ContainerSize)) {
                Result = ERROR_INVALID_DATA;
                break;
            }

            ContainerHeader = (PRMDX_HEADER)Data;
            DataHeader = (PCDATA_HEADER)RtlOffsetToPointer(ContainerHeader, ContainerHeader->DataOffset);

            MaximumLength = ContainerHeader->DataOffset + sizeof(CDATA_HEADER) + DataHeader->Length - 4;
            CurrentPosition = ContainerHeader->DataOffset + sizeof(CDATA_HEADER);

            DataPtr = (PBYTE)RtlOffsetToPointer(DataHeader, sizeof(CDATA_HEADER));

            ULONG ctr = 0, cError;
            DWORD totalBytesWritten = 0;

            if (ExtractImageChunks) {
                CreateDirectory(L"chunks", NULL);
                SetCurrentDirectory(L"chunks");
            }

            while (CurrentPosition < MaximumLength) {

                memcpy(&Chunk, DataPtr, sizeof(CHUNK_HEAD));
                Chunk.L0 ^= Chunk.Key;
                Chunk.L1 ^= Chunk.Key;
                Chunk.L2 ^= Chunk.Key;
                ChunkLength = Chunk.L0 + (Chunk.L1 << 8) + (Chunk.L2 << 16);

                DecodedBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, ChunkLength);
                if (DecodedBuffer) {
                    memcpy(DecodedBuffer, RtlOffsetToPointer(DataPtr, sizeof(CHUNK_HEAD)), ChunkLength);
                    XorMemoryBuffer(DecodedBuffer, Chunk.Key, ChunkLength);
                    totalBytesWritten += FileWrite(DecodedBuffer, ChunkLength, tempFileHandle);

                    if (ExtractImageChunks) {

                        if ((Chunk.Key == DB_EXECUTABLE_IMAGE) ||
                            (Chunk.Key == DB_EXECUTABLE_IMAGE2) ||
                            (Chunk.Key == DB_EXECUTABLE_IMAGE3))
                        {
                            printf_s("%s: Found image at position %08IX with size = %lu\r\n", __FUNCTION__,
                                CurrentPosition,
                                ChunkLength);

                            cError = ExtractCallback(szCurrentDirectory, DecodedBuffer, ChunkLength, ctr, FALSE);
                            if (cError != ERROR_SUCCESS) {
                                ShowWin32Error(cError, "ExtractCallback()");
                            }
                            ++ctr;
                        }

                    }

                    LocalFree(DecodedBuffer);
                }

                EntryLength = sizeof(CHUNK_HEAD) + ChunkLength;
                CurrentPosition += EntryLength;
                DataPtr = (PBYTE)RtlOffsetToPointer(DataPtr, EntryLength);
            }

            if (ExtractedChunks)
                *ExtractedChunks = ctr;

            *TotalBytesWritten = totalBytesWritten;
            *TotalBytesRead = (ULONG)CurrentPosition;
            Result = ERROR_SUCCESS;

        } while (FALSE);

        if (tempFileHandle) {
            if (tempFileHandle != INVALID_HANDLE_VALUE) FileClose(tempFileHandle);
        }
        if (ExtractedModule) FreeLibrary(ExtractedModule);
        DeleteFile(TempFileName);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return Result;
}

/*
* ExtractData
*
* Purpose:
*
* Main worker routine, determinate input file type and process it.
*
*/
void ExtractData(LPWSTR FileName, BOOLEAN ExtractImageChunks)
{
    UINT Result;
    ULONG TotalBytesWritten = 0, TotalBytesRead = 0, NumberOfImageChunks = 0;
    IMAGE_NT_HEADERS *NtHeaders;
    CHAR szTotalMsg[240];

    PVOID ImageBase = MapContainerFile(FileName);
    if (ImageBase) {

        NtHeaders = ImageNtHeader(ImageBase);

        //
        // Rough check if this is MRT.
        //
        if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {

            Result = ExtractDataDll(FileName,
                ImageBase,
                &TotalBytesWritten,
                &TotalBytesRead,
                ExtractImageChunks,
                &NumberOfImageChunks);

        }
        else {

            Result = ExtractDataEXE(FileName,
                ImageBase,
                &TotalBytesWritten,
                &TotalBytesRead,
                ExtractImageChunks,
                &NumberOfImageChunks);

        }

        if (Result == ERROR_SUCCESS) {

            if (ExtractImageChunks) {

                StringCbPrintfA(szTotalMsg,
                    _countof(szTotalMsg),
                    "\r\nStats: \r\nRead bytes = %lu (%lu KB)\r\nWritten bytes = %lu (%lu KB)\r\nImage chunks = %lu",
                    TotalBytesRead,
                    TotalBytesRead / 1024,
                    TotalBytesWritten,
                    TotalBytesWritten / 1024,
                    NumberOfImageChunks);
            }
            else {

                StringCbPrintfA(szTotalMsg,
                    _countof(szTotalMsg),
                    "\r\nStats: \r\nRead bytes = %lu (%lu KB)\r\nWritten bytes = %lu (%lu KB)",
                    TotalBytesRead,
                    TotalBytesRead / 1024,
                    TotalBytesWritten,
                    TotalBytesWritten / 1024);
            }

            printf_s("%s", szTotalMsg);

        }
        else {
            ShowWin32Error(Result, "ExtractData()");
        }

        UnmapViewOfFile(ImageBase);
    }
    else {
        ShowWin32Error(GetLastError(), "ExtractData()");
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
    BOOLEAN fCommand = FALSE, fExtractImageChunks = FALSE;

    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

    printf_s("%s build at %s\r\n", WDEXTRACT_VERSION, __DATE__);

    LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist) {

        if (nArgs > 1) {
            LPWSTR Param = szArglist[1];
            if (nArgs > 2) {
                LPWSTR OptionalParam = szArglist[2];
                fExtractImageChunks = _wcsicmp(OptionalParam, L"-e") == 0;
            }
            if (Param) {
                ExtractData(Param, fExtractImageChunks);
                fCommand = TRUE;
            }
        }
        LocalFree(szArglist);
    }

    if (fCommand != TRUE)
        printf_s("Usage: wdextract file [-e]");
    else
        printf_s("\r\nBye!");

    return 0;
}
