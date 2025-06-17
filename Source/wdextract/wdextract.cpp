/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       WDEXTRACT.CPP
*
*  VERSION:     1.10
*
*  DATE:        16 Jun 2025
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

#define WDEXTRACT_VERSION           L"wdextract 1.10"

/*
* ExtractContainerOnly
*
* Purpose:
*
* Extract raw RMDX container without further processing.
*
*/
UINT ExtractContainerOnly(
    _In_ LPCWSTR FileName,
    _In_ PVOID Container,
    _In_ ULONG ContainerSize
)
{
    UINT Result = ERROR_INTERNAL_ERROR;
    HANDLE OutputFileHandle = INVALID_HANDLE_VALUE;
    LPWSTR OutputFileName = NULL;
    size_t FileNameLength = 0;
    WCHAR BaseName[MAX_PATH + 1];
    LPWSTR Extension;

    do {
        RtlSecureZeroMemory(BaseName, sizeof(BaseName));
        StringCchCopy(BaseName, MAX_PATH, FileName);

        Extension = wcsrchr(BaseName, L'.');
        if (Extension) {
            *Extension = L'\0';
        }

        if (FAILED(StringCchLength(BaseName, MAX_PATH, &FileNameLength))) {
            Result = GetLastError();
            break;
        }

        FileNameLength += 6;
        OutputFileName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, FileNameLength * sizeof(WCHAR));
        if (OutputFileName == NULL) {
            Result = GetLastError();
            break;
        }

        if (FAILED(StringCchPrintf(OutputFileName, FileNameLength, TEXT("%s.rdmx"), BaseName))) {
            Result = ERROR_INSUFFICIENT_BUFFER;
            break;
        }

        OutputFileHandle = CreateFile(OutputFileName, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL);;
        if (OutputFileHandle == INVALID_HANDLE_VALUE) {
            Result = GetLastError();
            break;
        }

        DWORD bytesWritten = FileWrite((PBYTE)Container, ContainerSize, OutputFileHandle);
        if (bytesWritten != ContainerSize) {
            Result = GetLastError();
            if (Result == ERROR_SUCCESS) Result = ERROR_WRITE_FAULT;
            break;
        }

        wprintf_s(L"Successfully extracted raw container to %s (%lu bytes)\r\n",
            OutputFileName, ContainerSize);
        Result = ERROR_SUCCESS;

    } while (FALSE);

    if (OutputFileName)
        LocalFree(OutputFileName);

    if (OutputFileHandle != INVALID_HANDLE_VALUE)
        CloseHandle(OutputFileHandle);

    return Result;
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
    _In_ LPCWSTR FileName,
    _In_ PVOID ImageBase,
    _Out_ PULONG TotalBytesWritten,
    _Out_ PULONG TotalBytesRead,
    _In_ BOOLEAN ExtractImageChunks,
    _Out_opt_ PULONG ExtractedChunks,
    _In_ BOOLEAN ExtractContainerFlag
)
{
    UINT Result = ERROR_INTERNAL_ERROR;
    BOOLEAN IsCompressed;

    ULONG ContainerSize = 0, totalBytesWritten = 0;

    LPWSTR  NewFileName = NULL;
    size_t  FileNameLength = 0;
    WCHAR BaseName[MAX_PATH + 1];
    LPWSTR Extension;

    PVOID Data = NULL;
    PRMDX_HEADER ContainerHeader = NULL;
    PCDATA_HEADER DataHeader = NULL;

    HANDLE OutputFileHandle = INVALID_HANDLE_VALUE;
    PBYTE ReadData = NULL;

    WCHAR szCurrentDirectory[MAX_PATH + 1];
    WCHAR szOriginalDirectory[MAX_PATH + 1];

    *TotalBytesWritten = 0;
    *TotalBytesRead = 0;
    if (ExtractedChunks)
        *ExtractedChunks = 0;

    __try {
        RtlSecureZeroMemory(szCurrentDirectory, sizeof(szCurrentDirectory));
        RtlSecureZeroMemory(szOriginalDirectory, sizeof(szOriginalDirectory));

        if (GetCurrentDirectory(MAX_PATH, szCurrentDirectory) == 0) {
            return GetLastError();
        }

        StringCchCopy(szOriginalDirectory, MAX_PATH, szCurrentDirectory);

        do {
            Data = GetContainerFromResource(ImageBase, &ContainerSize);
            if (Data == NULL) {
                Result = ERROR_RESOURCE_NAME_NOT_FOUND;
                break;
            }

            if (!IsValidContainer(Data, ContainerSize)) {
                Result = ERROR_INVALID_DATA;
                break;
            }

            if (ExtractContainerFlag) {
                Result = ExtractContainerOnly(FileName, Data, ContainerSize);
                break;
            }

            ContainerHeader = (PRMDX_HEADER)Data;

            IsCompressed = ((ContainerHeader->Options >> 1) & 0xff);
            if (IsCompressed == FALSE) {
                Result = ERROR_UNKNOWN_REVISION;
                break;
            }

            DataHeader = (PCDATA_HEADER)RtlOffsetToPointer(ContainerHeader, ContainerHeader->DataOffset);

            RtlSecureZeroMemory(BaseName, sizeof(BaseName));
            StringCchCopy(BaseName, MAX_PATH, FileName);

            Extension = wcsrchr(BaseName, L'.');
            if (Extension) {
                *Extension = L'\0';
            }

            if (FAILED(StringCchLength(BaseName, MAX_PATH, &FileNameLength))) {
                Result = GetLastError();
                break;
            }

            FileNameLength += 11;
            NewFileName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, FileNameLength * sizeof(WCHAR));
            if (NewFileName == NULL) {
                Result = GetLastError();
                break;
            }

            if (FAILED(StringCchPrintf(NewFileName, FileNameLength, TEXT("%s.extracted"), BaseName))) {
                Result = ERROR_INSUFFICIENT_BUFFER;
                break;
            }

            OutputFileHandle = CreateFile(NewFileName, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL);
            LocalFree(NewFileName);
            NewFileName = NULL;

            if (OutputFileHandle == INVALID_HANDLE_VALUE) {
                Result = GetLastError();
                break;
            }

            if (!ZLibUnpack(DataHeader, OutputFileHandle, &totalBytesWritten, TotalBytesRead)) {
                Result = ERROR_INTERNAL_ERROR;
                break;
            }

            Result = ERROR_SUCCESS;
            *TotalBytesWritten = totalBytesWritten;

            if (totalBytesWritten > 2 && ExtractImageChunks) {
                if (totalBytesWritten > 1024 * 1024 * 1024) { // 1 GB limit
                    wprintf_s(L"%s: Extracted file too large (%lu bytes)\r\n", __FUNCTIONW__, totalBytesWritten);
                    break;
                }

                ReadData = (PBYTE)LocalAlloc(LMEM_ZEROINIT, totalBytesWritten);
                if (ReadData) {
                    SetFilePointer(OutputFileHandle, 0, NULL, FILE_BEGIN);
                    ULONG bytesRead = FileRead(ReadData, totalBytesWritten, OutputFileHandle);

                    if (bytesRead != totalBytesWritten) {
                        wprintf_s(L"%s: Failed to read back extracted data (read %lu of %lu bytes)\r\n",
                            __FUNCTIONW__, bytesRead, totalBytesWritten);
                        break;
                    }

                    ULONG extractedChunks = 0;
                    Result = ExtractImageChunksFromBuffer(szCurrentDirectory,
                        ReadData,
                        totalBytesWritten,
                        &extractedChunks,
                        __FUNCTIONW__);

                    if (ExtractedChunks) {
                        *ExtractedChunks = extractedChunks;
                    }
                }
                else {
                    wprintf_s(L"%s: Failed to allocate memory for extracted data\r\n", __FUNCTIONW__);
                }
            }
        } while (FALSE);

        // Clean up resources
        if (ReadData) {
            LocalFree(ReadData);
        }

        if (OutputFileHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(OutputFileHandle);
        }

        if (NewFileName) {
            LocalFree(NewFileName);
        }

        SetCurrentDirectory(szOriginalDirectory);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetCurrentDirectory(szOriginalDirectory);
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
    _In_ LPCWSTR FileName,
    _In_ PVOID ImageBase,
    _Out_ PULONG TotalBytesWritten,
    _Out_ PULONG TotalBytesRead,
    _In_ BOOLEAN ExtractImageChunks,
    _Out_opt_ PULONG ExtractedChunks,
    _In_ BOOLEAN ExtractContainerFlag
)
{
    UINT Result = 0;

    HMODULE ExtractedModule = NULL;
    HANDLE tempFileHandle = INVALID_HANDLE_VALUE;

    ULONG Size = 0, ChunkLength, EntryLength, ContainerSize = 0;

    PBYTE DataPtr, DecodedBuffer = NULL;
    SIZE_T CurrentPosition, MaximumLength;
    PVOID Data;

    IMAGE_NT_HEADERS* NtHeaders;

    RMDX_HEADER* ContainerHeader;
    CDATA_HEADER* DataHeader;
    CHUNK_HEAD Chunk;

    LPWSTR NewFileName = NULL;
    size_t FileNameLength = 0;
    WCHAR BaseName[MAX_PATH + 1];
    LPWSTR Extension;
    WCHAR szCurrentDirectory[MAX_PATH + 1];
    WCHAR szOriginalDirectory[MAX_PATH + 1];
    WCHAR TempFileName[MAX_PATH * 2];

    *TotalBytesWritten = 0;
    *TotalBytesRead = 0;
    if (ExtractedChunks)
        *ExtractedChunks = 0;

    __try {
        RtlSecureZeroMemory(szCurrentDirectory, sizeof(szCurrentDirectory));
        RtlSecureZeroMemory(szOriginalDirectory, sizeof(szOriginalDirectory));

        GetCurrentDirectory(MAX_PATH, szCurrentDirectory);

        StringCchCopy(szOriginalDirectory, MAX_PATH, szCurrentDirectory);

        Data = GetContainerFromResource(ImageBase, &Size);
        if (!Data) {
            return ERROR_RESOURCE_NAME_NOT_FOUND;
        }

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

        tempFileHandle = CreateFile(TempFileName, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (tempFileHandle == INVALID_HANDLE_VALUE) {
            return GetLastError();
        }
        else {
            FileWrite((PBYTE)Data, Size, tempFileHandle);
            CloseHandle(tempFileHandle);
            tempFileHandle = INVALID_HANDLE_VALUE;
        }

        do {
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

            if (ExtractContainerFlag) {
                Result = ExtractContainerOnly(FileName, Data, ContainerSize);
                break;
            }

            ContainerHeader = (PRMDX_HEADER)Data;
            DataHeader = (PCDATA_HEADER)RtlOffsetToPointer(ContainerHeader, ContainerHeader->DataOffset);

            RtlSecureZeroMemory(BaseName, sizeof(BaseName));
            StringCchCopy(BaseName, MAX_PATH, FileName);

            Extension = wcsrchr(BaseName, L'.');
            if (Extension) {
                *Extension = L'\0';
            }

            if (FAILED(StringCchLength(BaseName, MAX_PATH, &FileNameLength))) {
                Result = GetLastError();
                break;
            }

            FileNameLength += 11;
            NewFileName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, FileNameLength * sizeof(WCHAR));
            if (NewFileName == NULL) {
                Result = GetLastError();
                break;
            }

            if (FAILED(StringCchPrintf(NewFileName, FileNameLength, TEXT("%s.extracted"), BaseName))) {
                Result = ERROR_INSUFFICIENT_BUFFER;
                break;
            }

            tempFileHandle = FileCreate(NewFileName);
            LocalFree(NewFileName);
            NewFileName = NULL;

            if (tempFileHandle == INVALID_HANDLE_VALUE) {
                Result = GetLastError();
                break;
            }

            MaximumLength = ContainerHeader->DataOffset + sizeof(CDATA_HEADER) + DataHeader->Length - 4;
            CurrentPosition = ContainerHeader->DataOffset + sizeof(CDATA_HEADER);

            DataPtr = (PBYTE)RtlOffsetToPointer(DataHeader, sizeof(CDATA_HEADER));

            ULONG ctr = 0;
            DWORD totalBytesWritten = 0;

            PBYTE ExtractedChunkData = NULL;
            DWORD ExtractedChunkSize = 0;

            if (ExtractImageChunks) {
                ExtractedChunkSize = 10 * 1024 * 1024; // 10 MB initial buffer
                ExtractedChunkData = (PBYTE)LocalAlloc(LMEM_ZEROINIT, ExtractedChunkSize);
                if (!ExtractedChunkData) {
                    Result = GetLastError();
                    wprintf_s(L"%s: Failed to allocate memory for chunk buffer\r\n", __FUNCTIONW__);
                    break;
                }
            }

            while (CurrentPosition < MaximumLength) {
                if (CurrentPosition + sizeof(CHUNK_HEAD) > MaximumLength) {
                    break;
                }

                RtlCopyMemory(&Chunk, DataPtr, sizeof(CHUNK_HEAD));
                Chunk.L0 ^= Chunk.Key;
                Chunk.L1 ^= Chunk.Key;
                Chunk.L2 ^= Chunk.Key;
                ChunkLength = Chunk.L0 + (Chunk.L1 << 8) + (Chunk.L2 << 16);

                if (ChunkLength == 0) {
                    CurrentPosition += sizeof(CHUNK_HEAD);
                    DataPtr = (PBYTE)RtlOffsetToPointer(DataPtr, sizeof(CHUNK_HEAD));
                    continue;
                }

                DecodedBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, ChunkLength);
                if (DecodedBuffer) {
                    RtlCopyMemory(DecodedBuffer, RtlOffsetToPointer(DataPtr, sizeof(CHUNK_HEAD)), ChunkLength);
                    XorMemoryBuffer(DecodedBuffer, Chunk.Key, ChunkLength);
                    totalBytesWritten += FileWrite(DecodedBuffer, ChunkLength, tempFileHandle);

                    if (ExtractImageChunks) {
                        if ((Chunk.Key == DB_EXECUTABLE_IMAGE) ||
                            (Chunk.Key == DB_EXECUTABLE_IMAGE2) ||
                            (Chunk.Key == DB_EXECUTABLE_IMAGE3))
                        {
                            wprintf_s(L"%s: Found executable chunk at position %08IX with size = %lu\r\n", __FUNCTIONW__,
                                CurrentPosition,
                                ChunkLength);

                            if (ctr == 0) {
                                RtlCopyMemory(ExtractedChunkData, DecodedBuffer, ChunkLength);
                                ctr++;
                            }
                            else {

                                PBYTE newBuffer = (PBYTE)LocalReAlloc(ExtractedChunkData,
                                    ExtractedChunkSize + ChunkLength,
                                    LMEM_MOVEABLE | LMEM_ZEROINIT);
                                if (newBuffer) {
                                    ExtractedChunkData = newBuffer;
                                    RtlCopyMemory(ExtractedChunkData + ExtractedChunkSize, DecodedBuffer, ChunkLength);
                                    ExtractedChunkSize += ChunkLength;
                                    ctr++;
                                }
                                else {
                                    wprintf_s(L"%s: Failed to reallocate chunk buffer\r\n", __FUNCTIONW__);
                                }
                            }
                        }
                    }

                    LocalFree(DecodedBuffer);
                    DecodedBuffer = NULL;
                }

                EntryLength = sizeof(CHUNK_HEAD) + ChunkLength;
                CurrentPosition += EntryLength;
                DataPtr = (PBYTE)RtlOffsetToPointer(DataPtr, EntryLength);
            }

            *TotalBytesWritten = totalBytesWritten;
            *TotalBytesRead = (ULONG)CurrentPosition;

            if (ExtractImageChunks && ExtractedChunkData && ExtractedChunkSize > 0) {
                ULONG extractedChunks = 0;
                Result = ExtractImageChunksFromBuffer(szCurrentDirectory,
                    ExtractedChunkData,
                    ExtractedChunkSize,
                    &extractedChunks,
                    __FUNCTIONW__);

                if (ExtractedChunks) {
                    *ExtractedChunks = extractedChunks;
                }

                LocalFree(ExtractedChunkData);
                ExtractedChunkData = NULL;
            }
            else if (!ExtractImageChunks) {
                Result = ERROR_SUCCESS;
            }

        } while (FALSE);

        if (tempFileHandle) {
            if (tempFileHandle != INVALID_HANDLE_VALUE) CloseHandle(tempFileHandle);
        }
        if (ExtractedModule) FreeLibrary(ExtractedModule);
        if (NewFileName) LocalFree(NewFileName);
        if (DecodedBuffer) LocalFree(DecodedBuffer);
        DeleteFile(TempFileName);

        SetCurrentDirectory(szOriginalDirectory);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetCurrentDirectory(szOriginalDirectory);
        return GetExceptionCode();
    }

    return Result;
}

/*
* MergeDeltaFiles
*
* Purpose:
*
* Merge base VDM file with delta file.
*
*/
UINT MergeDeltaFiles(
    _In_ LPCWSTR BaseFileName,
    _In_ LPCWSTR DeltaFileName,
    _Out_ PULONG TotalBytesWritten,
    _In_ BOOLEAN ExtractImageChunks,
    _Out_opt_ PULONG ExtractedChunks
)
{
    UINT Result = ERROR_INTERNAL_ERROR;
    DWORD totalBytesWritten = 0;
    ULONG ctr = 0;

    HANDLE BaseFileHandle = INVALID_HANDLE_VALUE;
    HANDLE DeltaFileHandle = INVALID_HANDLE_VALUE;
    HANDLE OutputFileHandle = INVALID_HANDLE_VALUE;
    PBYTE BaseBuffer = NULL;
    PBYTE DeltaBuffer = NULL;
    PBYTE OutputBuffer = NULL;
    DWORD BaseFileSize = 0;
    DWORD DeltaFileSize = 0;
    DWORD OutputSize = 0;

    WCHAR szCurrentDirectory[MAX_PATH + 1];
    WCHAR szOriginalDirectory[MAX_PATH + 1];
    WCHAR szMergedFileName[MAX_PATH + 1];

    *TotalBytesWritten = 0;
    if (ExtractedChunks)
        *ExtractedChunks = 0;

    __try {

        RtlSecureZeroMemory(szCurrentDirectory, sizeof(szCurrentDirectory));
        RtlSecureZeroMemory(szOriginalDirectory, sizeof(szOriginalDirectory));
        RtlSecureZeroMemory(szMergedFileName, sizeof(szMergedFileName));

        if (GetCurrentDirectory(MAX_PATH, szCurrentDirectory) == 0) {
            return GetLastError();
        }

        StringCchCopy(szOriginalDirectory, MAX_PATH, szCurrentDirectory);

        do {
            BaseFileHandle = FileOpen(BaseFileName, GENERIC_READ);
            if (BaseFileHandle == INVALID_HANDLE_VALUE) {
                Result = GetLastError();
                wprintf_s(L"%s: Failed to open base file, error %u\r\n", __FUNCTIONW__, Result);
                break;
            }

            DeltaFileHandle = FileOpen(DeltaFileName, GENERIC_READ);
            if (DeltaFileHandle == INVALID_HANDLE_VALUE) {
                Result = GetLastError();
                wprintf_s(L"%s: Failed to open delta file, error %u\r\n", __FUNCTIONW__, Result);
                break;
            }

            BaseFileSize = GetFileSize(BaseFileHandle, NULL);
            if (BaseFileSize == INVALID_FILE_SIZE || BaseFileSize == 0) {
                Result = GetLastError();
                if (Result == ERROR_SUCCESS) Result = ERROR_INVALID_DATA;
                wprintf_s(L"%s: Invalid base file size\r\n", __FUNCTIONW__);
                break;
            }

            DeltaFileSize = GetFileSize(DeltaFileHandle, NULL);
            if (DeltaFileSize == INVALID_FILE_SIZE || DeltaFileSize == 0) {
                Result = GetLastError();
                if (Result == ERROR_SUCCESS) Result = ERROR_INVALID_DATA;
                wprintf_s(L"%s: Invalid delta file size\r\n", __FUNCTIONW__);
                break;
            }

            BaseBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, BaseFileSize);
            if (!BaseBuffer) {
                Result = GetLastError();
                wprintf_s(L"%s: Failed to allocate memory for base file\r\n", __FUNCTIONW__);
                break;
            }

            DeltaBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, DeltaFileSize);
            if (!DeltaBuffer) {
                Result = GetLastError();
                wprintf_s(L"%s: Failed to allocate memory for delta file\r\n", __FUNCTIONW__);
                break;
            }

            DWORD bytesRead;
            bytesRead = FileRead(BaseBuffer, BaseFileSize, BaseFileHandle);
            if (bytesRead != BaseFileSize) {
                Result = GetLastError();
                if (Result == ERROR_SUCCESS) Result = ERROR_READ_FAULT;
                wprintf_s(L"%s: Failed to read base file\r\n", __FUNCTIONW__);
                break;
            }

            bytesRead = FileRead(DeltaBuffer, DeltaFileSize, DeltaFileHandle);
            if (bytesRead != DeltaFileSize) {
                Result = GetLastError();
                if (Result == ERROR_SUCCESS) Result = ERROR_READ_FAULT;
                wprintf_s(L"%s: Failed to read delta file\r\n", __FUNCTIONW__);
                break;
            }

            if (FAILED(StringCchPrintf(szMergedFileName, MAX_PATH, L"%s.merged", BaseFileName))) {
                Result = ERROR_INSUFFICIENT_BUFFER;
                wprintf_s(L"%s: Failed to create output filename\r\n", __FUNCTIONW__);
                break;
            }

            OutputFileHandle = FileCreate(szMergedFileName);
            if (OutputFileHandle == INVALID_HANDLE_VALUE) {
                Result = GetLastError();
                wprintf_s(L"%s: Failed to create output file\r\n", __FUNCTIONW__);
                break;
            }

            DWORD index = 0;

            PCSIG_ENTRY deltaBlobEntry = (PCSIG_ENTRY)GetDeltaBlobSig(DeltaBuffer);
            if (!deltaBlobEntry) {
                Result = ERROR_INVALID_DATA;
                wprintf_s(L"%s: Failed to locate delta blob signature\r\n", __FUNCTIONW__);
                break;
            }

            WORD sizeX = 0;
            DWORD cSize = 0;
            DWORD blobSize = GET_SIG_SIZE(deltaBlobEntry);

            PCDELTA_BLOB blob = (PCDELTA_BLOB)deltaBlobEntry->Data;
            wprintf_s(L"\nMerge delta database...");
            wprintf_s(L"\nMergeSize: %lX - CRC: %lX", blob->Size, blob->Checksum);

            PBYTE delta_blob = blob->Data;

            OutputBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, BaseFileSize + DeltaFileSize);
            if (!OutputBuffer) {
                Result = GetLastError();
                wprintf_s(L"%s: Failed to allocate output buffer\r\n", __FUNCTIONW__);
                break;
            }

            DWORD databufSize = 0;

            do {
                if (index + sizeof(WORD) > blobSize) {
                    wprintf_s(L"\nUnexpected end of delta blob data at index %u\r\n", index);
                    Result = ERROR_INVALID_DATA;
                    break;
                }

                sizeX = *(WORD*)(delta_blob + index);
                index += sizeof(WORD);

                if (GET_MSB(sizeX)) {
                    if (index + sizeof(DWORD) > blobSize) {
                        wprintf_s(L"\nUnexpected end of delta blob data at index %u\r\n", index);
                        Result = ERROR_INVALID_DATA;
                        break;
                    }

                    DWORD offset = *(DWORD*)(delta_blob + index);
                    cSize = (sizeX & 0x7FFF) + 6;

                    if (offset + cSize > BaseFileSize) {
                        wprintf_s(L"\nBase file bounds exceeded: offset %u + size %u > %u\r\n",
                            offset, cSize, BaseFileSize);
                        Result = ERROR_INVALID_DATA;
                        break;
                    }

                    //wprintf_s(L"\nAppend 0x%08x bytes from base at offset 0x%08x to the new file", cSize, offset);

                    if (databufSize + cSize > BaseFileSize + DeltaFileSize) {
                        wprintf_s(L"\nOutput buffer bounds exceeded\r\n");
                        Result = ERROR_INSUFFICIENT_BUFFER;
                        break;
                    }

                    RtlCopyMemory(OutputBuffer + databufSize, BaseBuffer + offset, cSize);
                    databufSize += cSize;
                    index += sizeof(DWORD);
                }
                else {
                    if (index + sizeX > blobSize) {
                        wprintf_s(L"\nDelta blob bounds exceeded: index %u + size %u > %u\r\n",
                            index, sizeX, blobSize);
                        Result = ERROR_INVALID_DATA;
                        break;
                    }

                    if (databufSize + sizeX > BaseFileSize + DeltaFileSize) {
                        wprintf_s(L"\nOutput buffer bounds exceeded\r\n");
                        Result = ERROR_INSUFFICIENT_BUFFER;
                        break;
                    }

                    //wprintf_s(L"\nAppend 0x%08x bytes from the current place in delta to the new file", sizeX);
                    RtlCopyMemory(OutputBuffer + databufSize, delta_blob + index, sizeX);
                    databufSize += sizeX;
                    index += sizeX;
                }
            } while (index < blobSize - 8);

            totalBytesWritten = FileWrite(OutputBuffer, databufSize, OutputFileHandle);
            if (totalBytesWritten != databufSize) {
                Result = GetLastError();
                if (Result == ERROR_SUCCESS) Result = ERROR_WRITE_FAULT;
                wprintf_s(L"%s: Failed to write merged data\r\n", __FUNCTIONW__);
                break;
            }

            *TotalBytesWritten = totalBytesWritten;
            OutputSize = databufSize;
            wprintf_s(L"\nWrote %lu bytes to output file\r\n", totalBytesWritten);

            if (ExtractImageChunks && OutputSize > 0) {
                wprintf_s(L"\n%s: Starting image chunks extraction from merged file\r\n", __FUNCTIONW__);

                Result = ExtractImageChunksFromBuffer(szCurrentDirectory,
                    OutputBuffer,
                    OutputSize,
                    &ctr,
                    __FUNCTIONW__);

                if (ExtractedChunks) {
                    *ExtractedChunks = ctr;
                }
            }
            else if (!ExtractImageChunks) {
                Result = ERROR_SUCCESS;
            }

            wprintf_s(L"%s: Successfully merged files to %s\r\n", __FUNCTIONW__, szMergedFileName);

        } while (FALSE);

        if (BaseFileHandle != INVALID_HANDLE_VALUE)
            CloseHandle(BaseFileHandle);

        if (DeltaFileHandle != INVALID_HANDLE_VALUE)
            CloseHandle(DeltaFileHandle);

        if (OutputFileHandle != INVALID_HANDLE_VALUE)
            CloseHandle(OutputFileHandle);

        if (BaseBuffer)
            LocalFree(BaseBuffer);

        if (DeltaBuffer)
            LocalFree(DeltaBuffer);

        if (OutputBuffer)
            LocalFree(OutputBuffer);

        SetCurrentDirectory(szOriginalDirectory);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetCurrentDirectory(szOriginalDirectory);
        return GetExceptionCode();
    }

    return Result;
}

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
    if (ImageBase) {
        NtHeaders = ImageNtHeader(ImageBase);

        //
        // Rough check if this is MRT.
        //
        if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
            if (ExtractContainerOnly) {
                wprintf_s(L"ExtractDataDll: Attempt to extract raw RDMX data from VDM container\r\n");
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
                wprintf_s(L"ExtractDataEXE: Attempt to extract raw RDMX data from MRT container\r\n");
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
    else {
        ShowWin32Error(GetLastError(), __FUNCTIONW__);
    }
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
    _In_ BOOLEAN ExtractImageChunks)
{
    ULONG TotalBytesWritten = 0, NumberOfImageChunks = 0;

    UINT Result = MergeDeltaFiles(
        BaseFileName,
        DeltaFileName,
        &TotalBytesWritten,
        ExtractImageChunks,
        &NumberOfImageChunks);

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
    BOOLEAN fCommand = FALSE, fExtractImageChunks = FALSE, fMergeDelta = FALSE, fExtractContainerOnly = FALSE;
    LPWSTR DeltaFileName = NULL;
    LPWSTR* szArglist = NULL;

    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

    wprintf_s(L"%s build at %s (c) 2019 - 2025 hfiref0x\r\n", WDEXTRACT_VERSION, TEXT(__DATE__));

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
                    else if (DeltaFileName == NULL) {
                        DeltaFileName = szArglist[i];
                    }
                }

                // Check for incompatible flags
                if (fExtractContainerOnly && (fExtractImageChunks || fMergeDelta)) {
                    wprintf_s(L"Error: -ec option is incompatible with -e and -m options\r\n");
                }
                else if (fMergeDelta) {
                    if (DeltaFileName) {
                        MergeDeltaCommand(BaseFileName, DeltaFileName, fExtractImageChunks);
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
        wprintf_s(L"Usage: wdextract file [-e]\n       wdextract file [-ec]\n       wdextract baseFile deltaFile -m [-e]\n       wdextract baseFile -m deltaFile [-e]");
    else
        wprintf_s(L"\r\nBye!");

    return 0;
}
