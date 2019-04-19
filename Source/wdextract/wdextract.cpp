/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       MAIN.CPP
*
*  VERSION:     1.01
*
*  DATE:        18 Apr 2019
*
*  WDEXTRACT main logic and entrypoint.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "pch.h"
#include "global.h"

#define WDEXTRACT_TITLE TEXT("Windows Defender VDM extractor")
#define MAX_FILENAME_BUFFER_LENGTH 1024

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
void ExtractCallback(
    _In_ LPWSTR CurrentDirectory,
    _In_ PVOID ChunkPtr,
    _In_ ULONG ChunkLength,
    _In_ ULONG ChunkId)
{
    BOOLEAN FileNameAvailable;
    HANDLE FileHandle;
    WCHAR szImageName[MAX_PATH + 1];
    WCHAR ImageChunkFileName[MAX_FILENAME_BUFFER_LENGTH + 1];
    WCHAR ImageChunkFileName2[MAX_FILENAME_BUFFER_LENGTH + 1];

    RtlSecureZeroMemory(szImageName, sizeof(szImageName));
    FileNameAvailable = ExtractImageNameFromExport(ChunkPtr, (LPWSTR)&szImageName, MAX_PATH);

    if (FileNameAvailable) {

        RtlSecureZeroMemory(ImageChunkFileName, sizeof(ImageChunkFileName));
        StringCchPrintf(ImageChunkFileName, MAX_FILENAME_BUFFER_LENGTH,
            TEXT("%s\\chunks\\%s_module%u.dll"), CurrentDirectory, szImageName, ChunkId);

        FileHandle = FileCreate(ImageChunkFileName);
        if (FileHandle != INVALID_HANDLE_VALUE) {
            FileWrite((PBYTE)ChunkPtr, ChunkLength, FileHandle);
            FileClose(FileHandle);
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
            TEXT("%s\\chunks\\module%u.dll"), CurrentDirectory, ChunkId);

        FileHandle = FileCreate(ImageChunkFileName);
        if (FileHandle != INVALID_HANDLE_VALUE) {
            FileWrite((PBYTE)ChunkPtr, ChunkLength, FileHandle);
            FileClose(FileHandle);
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
                                TEXT("%s\\chunks\\%s_module%u.dll"), CurrentDirectory, lpOriginalFileName, ChunkId);
                            MoveFileEx(ImageChunkFileName, ImageChunkFileName2, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);

                        }
                    }

                }
                LocalFree(vinfo);
            }
        }
    }
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

    ULONG ContainerSize = 0, totalBytesWritten = 0;

    LPWSTR  NewFileName;
    SIZE_T  FileNameLength = 0;

    PVOID Data;
    PRMDX_HEADER ContainerHeader;
    PCDATA_HEADER DataHeader;

    HANDLE OutputFileHandle;

    WCHAR szCurrentDirectory[MAX_PATH + 1];

    __try {

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

        StringCchLength(FileName, MAX_PATH, &FileNameLength);
        FileNameLength += (1 + MAX_PATH);
        NewFileName = (LPWSTR)LocalAlloc(LPTR, FileNameLength * sizeof(WCHAR));
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

                                printf("Found image at position %08X with size = %lu\r\n", CurrentPosition, SizeOfImage);

                                ExtractCallback(szCurrentDirectory, CurrentPtr, SizeOfImage, ctr);

                                ++ctr;

                                CurrentPosition += SizeOfImage;
                                continue;
                            }

                        }

                        CurrentPosition += 1;
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
* Extract VDM database from MRT container (Malicious Removal Tool).
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
    SIZE_T  FileNameLength = 0;
    WCHAR szCurrentDirectory[MAX_PATH + 1];
    WCHAR TempFileName[MAX_PATH * 2];

    __try {

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

        FileWrite((PBYTE)Data, Size, tempFileHandle);
        FileClose(tempFileHandle);
        tempFileHandle = INVALID_HANDLE_VALUE;
        Data = NULL;

        do {

            StringCchLength(FileName, MAX_PATH, &FileNameLength);
            FileNameLength += (1 + MAX_PATH);
            NewFileName = (LPWSTR)LocalAlloc(LPTR, FileNameLength * sizeof(WCHAR));
            if (NewFileName == NULL) {
                Result = GetLastError();
                break;
            }

            StringCchPrintf(NewFileName, FileNameLength, TEXT("%s.extracted"), FileName);
            tempFileHandle = FileCreate(NewFileName);
            LocalFree(NewFileName);

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

            ULONG ctr = 0;
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

                DecodedBuffer = (PBYTE)LocalAlloc(LPTR, ChunkLength);
                if (DecodedBuffer) {
                    memcpy(DecodedBuffer, RtlOffsetToPointer(DataPtr, sizeof(CHUNK_HEAD)), ChunkLength);
                    XorMemoryBuffer(DecodedBuffer, Chunk.Key, ChunkLength);
                    totalBytesWritten += FileWrite(DecodedBuffer, ChunkLength, tempFileHandle);

                    if (ExtractImageChunks) {

                        if ((Chunk.Key == DB_EXECUTABLE_IMAGE) ||
                            (Chunk.Key == DB_EXECUTABLE_IMAGE2) ||
                            (Chunk.Key == DB_EXECUTABLE_IMAGE3))
                        {
                            printf("Found image at position %08llX with size = %lu\r\n", CurrentPosition, ChunkLength);

                            ExtractCallback(szCurrentDirectory, DecodedBuffer, ChunkLength, ctr);

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

        if (tempFileHandle != INVALID_HANDLE_VALUE) FileClose(tempFileHandle);
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

            printf(szTotalMsg);

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
int main()
{
    INT nArgs = 0;
    BOOLEAN fCommand = FALSE, fExtractImageChunks = FALSE;

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
        printf("Usage: wdextract file [-e]");

    return 0;
}
