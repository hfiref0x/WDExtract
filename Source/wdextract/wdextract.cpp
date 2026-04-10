/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2026
*
*  TITLE:       WDEXTRACT.CPP
*
*  VERSION:     1.13
*
*  DATE:        10 Apr 2026
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

#define WDEXTRACT_VERSION           L"wdextract 1.13"
#define WDEXTRACT_COPYRIGHT         L"(c) 2019 - 2026 hfiref0x"
#define SUFFIX_RMDX_CCH             6   // L".rmdx" + null
#define SUFFIX_EXTRACTED_CCH        11  // L".extracted" + null

/*
* ComputeDeltaJamCrc32
*
* Purpose:
*
* Calculate a checksum for a block of data using JAMCRC.
*
*/
DWORD ComputeDeltaJamCrc32(
    _In_reads_bytes_(BufferSize) PBYTE Buffer,
    _In_ DWORD BufferSize
)
{
    DWORD crc, i, j;

    if (Buffer == NULL)
        return 0;

    crc = 0xFFFFFFFF;

    for (i = 0; i < BufferSize; i++) {
        crc ^= Buffer[i];

        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            }
            else {
                crc >>= 1;
            }
        }
    }

    return crc;
}

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

        FileNameLength += SUFFIX_RMDX_CCH;
        OutputFileName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, FileNameLength * sizeof(WCHAR));
        if (OutputFileName == NULL) {
            Result = GetLastError();
            break;
        }

        if (FAILED(StringCchPrintf(OutputFileName, FileNameLength, TEXT("%s.rmdx"), BaseName))) {
            Result = ERROR_INSUFFICIENT_BUFFER;
            break;
        }

        OutputFileHandle = FileCreate(OutputFileName);
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

            IsCompressed = (((ContainerHeader->Options >> 1) & 0xff) != 0);
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

            FileNameLength += SUFFIX_EXTRACTED_CCH;
            NewFileName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, FileNameLength * sizeof(WCHAR));
            if (NewFileName == NULL) {
                Result = GetLastError();
                break;
            }

            if (FAILED(StringCchPrintf(NewFileName, FileNameLength, TEXT("%s.extracted"), BaseName))) {
                Result = ERROR_INSUFFICIENT_BUFFER;
                break;
            }

            OutputFileHandle = FileCreate(NewFileName);
            LocalFree(NewFileName);
            NewFileName = NULL;

            if (OutputFileHandle == INVALID_HANDLE_VALUE) {
                Result = GetLastError();
                break;
            }

            if (!ZLibUnpack(DataHeader, OutputFileHandle, &totalBytesWritten, TotalBytesRead)) {
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
                    Result = ERROR_NOT_ENOUGH_MEMORY;
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

    ULONG ctr = 0;
    DWORD totalBytesWritten = 0;

    PBYTE ExtractedChunkData = NULL;
    DWORD ExtractedChunkSize = 0;

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

        if (GetCurrentDirectory(MAX_PATH, szCurrentDirectory) == 0) {
            return GetLastError();
        }

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

        tempFileHandle = FileCreate(TempFileName);
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

            FileNameLength += SUFFIX_EXTRACTED_CCH;
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

                            PBYTE newBuffer = (PBYTE)LocalReAlloc(ExtractedChunkData,
                                ExtractedChunkSize + ChunkLength,
                                LMEM_ZEROINIT);
                            if (newBuffer) {
                                ExtractedChunkData = newBuffer;
                                RtlCopyMemory(ExtractedChunkData + ExtractedChunkSize, DecodedBuffer, ChunkLength);
                                ExtractedChunkSize += ChunkLength;
                                ctr++;
                            }
                            else {
                                wprintf_s(L"%s: Failed to reallocate chunk buffer\r\n", __FUNCTIONW__);
                                if (ExtractedChunkData) {
                                    LocalFree(ExtractedChunkData);
                                    ExtractedChunkData = NULL;
                                    ExtractedChunkSize = 0;
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

        if (tempFileHandle != INVALID_HANDLE_VALUE) CloseHandle(tempFileHandle);
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
* MergeDeltaBuffer
*
* Purpose:
*
* Merge base VDM file data with delta file data.
*
*/
UINT MergeDeltaBuffer(
    _In_ PBYTE BaseBuffer,
    _In_ DWORD BaseFileSize,
    _In_ PBYTE DeltaBuffer,
    _In_ DWORD DeltaFileSize,
    _In_ BOOLEAN VerifyChecksum,
    _Outptr_result_bytebuffer_maybenull_(*MergedSize) PBYTE* MergedBuffer,
    _Out_ PDWORD MergedSize
)
{
    WORD sizeX;
    UINT Result;
    PCSIG_ENTRY deltaBlobEntry;
    PCDELTA_BLOB blob;
    PBYTE outputBuffer;
    PBYTE deltaBlob;
    DWORD outputCapacity, blobSize, availableSize, index, databufSize;
    DWORD offset, commandSize, copyCommandCount, literalCommandCount;
    DWORD zeroLiteralCommandCount, largestCopyCommand, largestLiteralCommand;

    if (MergedBuffer == NULL || MergedSize == NULL)
        return ERROR_INVALID_PARAMETER;

    *MergedBuffer = NULL;
    *MergedSize = 0;

    if (BaseBuffer == NULL || DeltaBuffer == NULL || BaseFileSize == 0 || DeltaFileSize == 0)
        return ERROR_INVALID_PARAMETER;

    Result = ERROR_INTERNAL_ERROR;
    deltaBlobEntry = (PCSIG_ENTRY)GetDeltaBlobSig(DeltaBuffer, DeltaFileSize);
    if (!deltaBlobEntry) {
        wprintf_s(L"%s: Failed to locate delta blob signature\r\n", __FUNCTIONW__);
        return ERROR_INVALID_DATA;
    }

    blobSize = GET_SIG_SIZE(deltaBlobEntry);
    if (blobSize < sizeof(CDELTA_BLOB)) {
        wprintf_s(L"%s: Invalid delta blob size 0x%08lX (%lu)\r\n",
            __FUNCTIONW__, blobSize, blobSize);
        return ERROR_INVALID_DATA;
    }

    blob = (PCDELTA_BLOB)deltaBlobEntry->Data;
    deltaBlob = blob->Data;
    availableSize = blobSize - FIELD_OFFSET(CDELTA_BLOB, Data);

    wprintf_s(L"%s: Base file size          = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, BaseFileSize, BaseFileSize);
    wprintf_s(L"%s: Delta file size         = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, DeltaFileSize, DeltaFileSize);
    wprintf_s(L"%s: Delta blob entry type   = 0x%02X (%u)\r\n",
        __FUNCTIONW__, deltaBlobEntry->Type, deltaBlobEntry->Type);
    wprintf_s(L"%s: Delta blob size         = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, blobSize, blobSize);
    wprintf_s(L"%s: Delta payload size      = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, availableSize, availableSize);
    wprintf_s(L"%s: Declared merged size    = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, blob->Size, blob->Size);
    wprintf_s(L"%s: Declared checksum       = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, blob->Checksum, blob->Checksum);

    if (blob->Size == 0) {
        wprintf_s(L"%s: Invalid declared merged size\r\n", __FUNCTIONW__);
        return ERROR_INVALID_DATA;
    }

    outputCapacity = BaseFileSize + DeltaFileSize;
    if (outputCapacity < BaseFileSize || outputCapacity < DeltaFileSize) {
        wprintf_s(L"%s: Output capacity overflow\r\n", __FUNCTIONW__);
        return ERROR_ARITHMETIC_OVERFLOW;
    }

    wprintf_s(L"%s: Output capacity         = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, outputCapacity, outputCapacity);

    outputBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, outputCapacity);
    if (outputBuffer == NULL) {
        Result = GetLastError();
        wprintf_s(L"%s: Failed to allocate output buffer, error %u\r\n", __FUNCTIONW__, Result);
        return Result;
    }

    index = 0;
    databufSize = 0;
    copyCommandCount = 0;
    literalCommandCount = 0;
    zeroLiteralCommandCount = 0;
    largestCopyCommand = 0;
    largestLiteralCommand = 0;

    while (index < availableSize) {

        if (availableSize - index < sizeof(WORD)) {
            wprintf_s(L"%s: Unexpected end of delta blob data at index 0x%08lX (%lu), available 0x%08lX (%lu)\r\n",
                __FUNCTIONW__, index, index, availableSize, availableSize);
            Result = ERROR_INVALID_DATA;
            break;
        }

        RtlCopyMemory(&sizeX, deltaBlob + index, sizeof(WORD));
        index += sizeof(WORD);

        if (GET_MSB(sizeX)) {

            copyCommandCount++;

            if (availableSize - index < sizeof(DWORD)) {
                wprintf_s(L"%s: Unexpected end of delta blob offset at index 0x%08lX (%lu), available 0x%08lX (%lu)\r\n",
                    __FUNCTIONW__, index, index, availableSize, availableSize);
                Result = ERROR_INVALID_DATA;
                break;
            }

            RtlCopyMemory(&offset, deltaBlob + index, sizeof(DWORD));
            index += sizeof(DWORD);

            commandSize = (DWORD)((sizeX & DELTA_COPY_LENGTH_MASK) + DELTA_COPY_LENGTH_BIAS);
            if (commandSize > largestCopyCommand)
                largestCopyCommand = commandSize;

            if (offset > BaseFileSize || commandSize > BaseFileSize - offset) {
                wprintf_s(L"%s: Base bounds exceeded: offset 0x%08lX (%lu) + size 0x%08lX (%lu) > base 0x%08lX (%lu)\r\n",
                    __FUNCTIONW__,
                    offset, offset,
                    commandSize, commandSize,
                    BaseFileSize, BaseFileSize);
                Result = ERROR_INVALID_DATA;
                break;
            }

            if (databufSize > outputCapacity || commandSize > outputCapacity - databufSize) {
                wprintf_s(L"%s: Output bounds exceeded: current 0x%08lX (%lu) + size 0x%08lX (%lu) > capacity 0x%08lX (%lu)\r\n",
                    __FUNCTIONW__,
                    databufSize, databufSize,
                    commandSize, commandSize,
                    outputCapacity, outputCapacity);
                Result = ERROR_INSUFFICIENT_BUFFER;
                break;
            }

            RtlCopyMemory(outputBuffer + databufSize, BaseBuffer + offset, commandSize);
            databufSize += commandSize;
        }
        else {

            literalCommandCount++;
            commandSize = (DWORD)sizeX;

            if (commandSize > largestLiteralCommand)
                largestLiteralCommand = commandSize;

            if (commandSize == 0) {
                zeroLiteralCommandCount++;
                wprintf_s(L"%s: Zero-sized literal command at index 0x%08lX (%lu)\r\n",
                    __FUNCTIONW__,
                    (DWORD)(index - (DWORD)sizeof(WORD)),
                    (DWORD)(index - (DWORD)sizeof(WORD)));
                continue;
            }

            if (availableSize - index < commandSize) {
                wprintf_s(L"%s: Delta bounds exceeded: index 0x%08lX (%lu) + size 0x%08lX (%lu) > payload 0x%08lX (%lu)\r\n",
                    __FUNCTIONW__,
                    index, index,
                    commandSize, commandSize,
                    availableSize, availableSize);
                Result = ERROR_INVALID_DATA;
                break;
            }

            if (databufSize > outputCapacity || commandSize > outputCapacity - databufSize) {
                wprintf_s(L"%s: Output bounds exceeded: current 0x%08lX (%lu) + size 0x%08lX (%lu) > capacity 0x%08lX (%lu)\r\n",
                    __FUNCTIONW__,
                    databufSize, databufSize,
                    commandSize, commandSize,
                    outputCapacity, outputCapacity);
                Result = ERROR_INSUFFICIENT_BUFFER;
                break;
            }

            RtlCopyMemory(outputBuffer + databufSize, deltaBlob + index, commandSize);
            databufSize += commandSize;
            index += commandSize;
        }
    }

    wprintf_s(L"%s: Copy commands          = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, copyCommandCount, copyCommandCount);
    wprintf_s(L"%s: Literal commands       = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, literalCommandCount, literalCommandCount);
    wprintf_s(L"%s: Zero literal commands  = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, zeroLiteralCommandCount, zeroLiteralCommandCount);
    wprintf_s(L"%s: Largest copy command   = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, largestCopyCommand, largestCopyCommand);
    wprintf_s(L"%s: Largest literal cmd    = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, largestLiteralCommand, largestLiteralCommand);
    wprintf_s(L"%s: Final payload index    = 0x%08lX (%lu) of 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, index, index, availableSize, availableSize);
    wprintf_s(L"%s: Reconstructed size     = 0x%08lX (%lu)\r\n",
        __FUNCTIONW__, databufSize, databufSize);

    if (Result == ERROR_INTERNAL_ERROR)
        Result = ERROR_SUCCESS;

    if (Result == ERROR_SUCCESS) {
        if (databufSize != blob->Size) {
            wprintf_s(L"%s: Merged output size mismatch: expected 0x%08lX (%lu), got 0x%08lX (%lu)\r\n",
                __FUNCTIONW__,
                blob->Size, blob->Size,
                databufSize, databufSize);
            Result = ERROR_INVALID_DATA;
        }
        else
        {
            wprintf_s(L"%s: Merged output size match: expected 0x%08lX (%lu), got 0x%08lX (%lu)\r\n",
                __FUNCTIONW__,
                blob->Size, blob->Size,
                databufSize, databufSize);

            if (VerifyChecksum) {
                wprintf_s(L"%s: Computing CRC on result buffer\r\n", __FUNCTIONW__);

                DWORD computedChecksum = ComputeDeltaJamCrc32(outputBuffer, databufSize);

                wprintf_s(L"%s: Computed JAMCRC       = 0x%08lX (%lu)\r\n",
                    __FUNCTIONW__, computedChecksum, computedChecksum);
                wprintf_s(L"%s: Declared checksum     = 0x%08lX (%lu)\r\n",
                    __FUNCTIONW__, blob->Checksum, blob->Checksum);

                if (computedChecksum != blob->Checksum) {
                    wprintf_s(L"%s: Checksum mismatch\r\n", __FUNCTIONW__);
                    Result = ERROR_INVALID_DATA;
                }
            }
        }
    }

    if (Result != ERROR_SUCCESS) {
        LocalFree(outputBuffer);
        return Result;
    }

    *MergedBuffer = outputBuffer;
    *MergedSize = databufSize;

    return ERROR_SUCCESS;
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
    _Out_opt_ PULONG ExtractedChunks,
    _In_ BOOLEAN VerifyChecksum
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

            PBYTE mergedBuffer = NULL;
            DWORD mergedSize = 0;

            Result = MergeDeltaBuffer(
                BaseBuffer,
                BaseFileSize,
                DeltaBuffer,
                DeltaFileSize,
                VerifyChecksum,
                &mergedBuffer,
                &mergedSize);

            if (Result != ERROR_SUCCESS) {
                break;
            }

            OutputBuffer = mergedBuffer;
            OutputSize = mergedSize;

            wprintf_s(L"\nMerge delta database...");
            wprintf_s(L"\nWrote candidate merged buffer of 0x%08lX (%lu) bytes\r\n",
                OutputSize, OutputSize);

            totalBytesWritten = FileWrite(OutputBuffer, OutputSize, OutputFileHandle);
            if (totalBytesWritten != OutputSize) {
                Result = GetLastError();
                if (Result == ERROR_SUCCESS) Result = ERROR_WRITE_FAULT;
                wprintf_s(L"%s: Failed to write merged data\r\n", __FUNCTIONW__);
                break;
            }

            *TotalBytesWritten = totalBytesWritten;
            wprintf_s(L"\nWrote 0x%08lX (%lu) bytes to output file\r\n",
                totalBytesWritten, totalBytesWritten);

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

    wprintf_s(L"%s build at %s %s\r\n", WDEXTRACT_VERSION, TEXT(__DATE__), WDEXTRACT_COPYRIGHT);

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
