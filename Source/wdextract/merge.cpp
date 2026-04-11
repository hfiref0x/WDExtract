/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       MERGE.CPP
*
*  VERSION:     1.13
*
*  DATE:        11 Apr 2026
*
*  Merge delta files main logic.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

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
