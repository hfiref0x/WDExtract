/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       EXTRACT.CPP
*
*  VERSION:     1.14
*
*  DATE:        21 Apr 2026
*
*  Extraction main logic.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

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
    _In_ BOOLEAN fNIS
)
{
    BOOLEAN FileNameAvailable;
    ULONG Result = ERROR_SUCCESS;
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
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

        RtlSecureZeroMemory(ImageChunkFileName, MAX_FILENAME_BUFFER_LENGTH);
        StringCchPrintf(ImageChunkFileName, MAX_FILENAME_BUFFER_LENGTH,
            TEXT("%s\\chunks\\%s_%s%u.dll"), CurrentDirectory, szImageName, lpDefaultChunkName, ChunkId);

        FileHandle = FileCreate(ImageChunkFileName);
        if (FileHandle != INVALID_HANDLE_VALUE) {
            if (FileWrite((PBYTE)ChunkPtr, ChunkLength, FileHandle) != ChunkLength) {
                Result = GetLastError();
                if (Result == ERROR_SUCCESS) Result = ERROR_WRITE_FAULT;
            }
            CloseHandle(FileHandle);
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

        if (FAILED(StringCchPrintf(ImageChunkFileName, MAX_FILENAME_BUFFER_LENGTH,
            TEXT("%s\\chunks\\%s%u.dll"), CurrentDirectory, lpDefaultChunkName, ChunkId)))
        {
            return ERROR_INSUFFICIENT_BUFFER;
        }

        FileHandle = FileCreate(ImageChunkFileName);
        if (FileHandle != INVALID_HANDLE_VALUE) {
            if (FileWrite((PBYTE)ChunkPtr, ChunkLength, FileHandle) != ChunkLength) {
                Result = GetLastError();
                if (Result == ERROR_SUCCESS) Result = ERROR_WRITE_FAULT;
            }
            CloseHandle(FileHandle);
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
                        (PUINT)&dwSize) && dwSize > 0)
                    {
                        if (SUCCEEDED(StringCchPrintf(szKey, _countof(szKey),
                            TEXT("\\StringFileInfo\\%04x%04x\\OriginalFileName"),
                            lpTranslate[0].wLanguage, lpTranslate[0].wCodePage)))
                        {
                            if (VerQueryValue(vinfo, szKey, (LPVOID*)&lpOriginalFileName, (PUINT)&dwSize)) {

                                RtlSecureZeroMemory(ImageChunkFileName2, sizeof(ImageChunkFileName2));
                                if (SUCCEEDED(StringCchPrintf(ImageChunkFileName2, MAX_FILENAME_BUFFER_LENGTH,
                                    TEXT("%s\\chunks\\%s_%s%u.dll"), CurrentDirectory, lpOriginalFileName,
                                    lpDefaultChunkName, ChunkId)))
                                {
                                    if (!MoveFileEx(ImageChunkFileName, ImageChunkFileName2,
                                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                                    {
                                        Result = GetLastError();
                                    }
                                }
                                else {
                                    Result = ERROR_INSUFFICIENT_BUFFER;
                                }
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
    CDATA_HEADER_NIS* NisDataHeader = (CDATA_HEADER_NIS*)Container;
    PBYTE pBytes = (PBYTE)&NisDataHeader->Data;
    LPWSTR pConverted = NULL;
    INT nLength;
    PWCHAR CurrentPosition;
    PWCHAR MaximumPosition;
    WCHAR* OpenBlob;
    ULONG ChunkLength;
    WCHAR* ptr;
    DWORD cbBinary;
    BYTE* pbBinary;

    nLength = MultiByteToWideChar(CP_UTF8, 0, (CHAR*)pBytes, -1, NULL, 0);
    if (nLength) {
        pConverted = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, (1 + (SIZE_T)nLength) * sizeof(WCHAR));
        if (pConverted) {

            tl1 = wcslen(OpenElement);
            tl2 = wcslen(CloseElement);

            MultiByteToWideChar(CP_UTF8, 0, (CHAR*)pBytes, -1, pConverted, nLength);

            CurrentPosition = pConverted;
            MaximumPosition = (PWCHAR)(pConverted + wcslen(pConverted)) - tl2;

            while (CurrentPosition < MaximumPosition) {

                OpenBlob = wcsstr(CurrentPosition, OpenElement);
                if (OpenBlob) {

                    OpenBlob += tl1;
                    if (OpenBlob >= MaximumPosition) {
                        break;
                    }

                    ChunkLength = 0;
                    ptr = OpenBlob;
                    while (ptr < MaximumPosition && *ptr != L'<') {
                        ChunkLength++;
                        ptr++;
                    }

                    if (ptr < MaximumPosition && ChunkLength > 0) {

                        cbBinary = 0;
                        CryptStringToBinary(OpenBlob, (DWORD)ChunkLength,
                            CRYPT_STRING_BASE64, NULL, (DWORD*)&cbBinary, NULL, NULL);

                        if (cbBinary) {
                            pbBinary = (BYTE*)LocalAlloc(LMEM_ZEROINIT, cbBinary);
                            if (pbBinary) {

                                if (CryptStringToBinary(OpenBlob, (DWORD)ChunkLength,
                                    CRYPT_STRING_BASE64, pbBinary, &cbBinary, NULL, NULL))
                                {
                                    wprintf_s(L"%s: Found image at position %08IX with size = %lu\r\n", __FUNCTIONW__,
                                        (ULONG_PTR)OpenBlob,
                                        ChunkLength);

                                    ULONG extractResult = ExtractCallback(szCurrentDirectory, pbBinary, cbBinary, ctr, TRUE);
                                    if (extractResult == ERROR_SUCCESS) {
                                        ++ctr;
                                    }
                                    else {
                                        wprintf_s(L"%s: ExtractCallback failed with error %u\r\n", __FUNCTIONW__, extractResult);
                                    }
                                }
                                LocalFree(pbBinary);
                            }
                        }
                    }

                    CurrentPosition = (OpenBlob + ChunkLength);
                    continue;
                }

                CurrentPosition++;
            }

        }
    }

    if (pConverted) LocalFree(pConverted);
    *ExtractedChunks = ctr;

    return ERROR_SUCCESS;
}

/*
* ExtractImageChunksFromBuffer
*
* Purpose:
*
* Extract PE image chunks from memory buffer.
*
*/
UINT ExtractImageChunksFromBuffer(
    _In_ LPWSTR szCurrentDirectory,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize,
    _Out_ PULONG ExtractedChunks,
    _In_opt_ LPCWSTR CallerName
)
{
    UINT Result = ERROR_SUCCESS;
    ULONG ctr = 0, cError;
    LPCWSTR FunctionName = CallerName ? CallerName : __FUNCTIONW__;

    *ExtractedChunks = 0;

    if (BufferSize < sizeof(WORD)) {
        wprintf_s(L"%s: Buffer too small (%lu bytes), skipping extraction\r\n", FunctionName, BufferSize);
        return ERROR_INVALID_DATA;
    }

    if (CreateDirectory(L"chunks", NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (!SetCurrentDirectory(L"chunks")) {
            wprintf_s(L"%s: Failed to change directory to chunks folder\r\n", FunctionName);
            return ERROR_DIRECTORY;
        }
    }
    else {
        wprintf_s(L"%s: Failed to create chunks directory\r\n", FunctionName);
        return ERROR_DIRECTORY;
    }

    if (IsContainerNIS(Buffer)) {
        wprintf_s(L"%s: Container is NIS\r\n", FunctionName);

        Result = ExtractDataXML_BruteForce(szCurrentDirectory,
            Buffer,
            CODEBLOB_OPEN,
            CODEBLOB_CLOSE,
            &ctr);
    }
    else {
        ULONG CurrentPosition = 0;
        ULONG SizeOfImage;
        PBYTE CurrentPtr;

        while (CurrentPosition <= BufferSize - sizeof(WORD)) {
            CurrentPtr = (PBYTE)RtlOffsetToPointer(Buffer, CurrentPosition);

            if ((*(PWORD)(CurrentPtr)) == 'ZM') {
                SizeOfImage = 0;

                if (IsValidImage(CurrentPtr) && GetImageSize(CurrentPtr, &SizeOfImage)) {
                    if (SizeOfImage == 0 || CurrentPosition + SizeOfImage > BufferSize) {
                        CurrentPosition += 1;
                        continue;
                    }

                    wprintf_s(L"%s: Found image at position %08X with size = %lu\r\n", FunctionName,
                        CurrentPosition,
                        SizeOfImage);

                    cError = ExtractCallback(szCurrentDirectory, CurrentPtr, SizeOfImage, ctr, FALSE);
                    if (cError != ERROR_SUCCESS) {
                        ShowWin32Error(cError, L"ExtractCallback()");
                    }
                    else {
                        ++ctr;
                    }

                    CurrentPosition += SizeOfImage;
                    continue;
                }
            }

            CurrentPosition += 1;
        }

        wprintf_s(L"%s: Extracted %lu image chunks\r\n", FunctionName, ctr);
    }

    *ExtractedChunks = ctr;
    return Result;
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
    HRESULT hr;

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

        hr = StringCchCopy(szOriginalDirectory, MAX_PATH, szCurrentDirectory);
        if (FAILED(hr)) {
            return HRESULT_CODE(hr);
        }

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
        if (GetTempPath(MAX_PATH, TempFileName) == 0) {
            return GetLastError();
        }

        hr = StringCchCat(TempFileName, MAX_PATH, TEXT("mrt_vdm.dll"));
        if (FAILED(hr)) {
            return HRESULT_CODE(hr);
        }

        //
        // Save special vdm container to disk into %temp% folder.
        //
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
            //
            // Load special vdm container from %temp%.
            //
            ExtractedModule = LoadLibraryEx(TempFileName, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (ExtractedModule == NULL) {
                Result = GetLastError();
                break;
            }

            //
            // Query from resources and validate vdm container header.
            //
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

            //
            // Prepare base name for extracted and decoded binary.
            //
            RtlSecureZeroMemory(BaseName, sizeof(BaseName));
            hr = StringCchCopy(BaseName, MAX_PATH, FileName);
            if (FAILED(hr)) {
                Result = HRESULT_CODE(hr);
                break;
            }

            Extension = wcsrchr(BaseName, L'.');
            if (Extension) {
                *Extension = L'\0';
            }

            hr = StringCchLength(BaseName, MAX_PATH, &FileNameLength);
            if (FAILED(hr)) {
                Result = HRESULT_CODE(hr);
                break;
            }

            FileNameLength += SUFFIX_EXTRACTED_CCH;
            NewFileName = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, FileNameLength * sizeof(WCHAR));
            if (NewFileName == NULL) {
                Result = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }

            hr = StringCchPrintf(NewFileName, FileNameLength, TEXT("%s.extracted"), BaseName);
            if (FAILED(hr)) {
                Result = ERROR_INSUFFICIENT_BUFFER;
                break;
            }

            //
            // Create new extracted binary.
            //
            tempFileHandle = FileCreate(NewFileName);
            LocalFree(NewFileName);
            NewFileName = NULL;

            if (tempFileHandle == INVALID_HANDLE_VALUE) {
                Result = GetLastError();
                break;
            }

            if (DataHeader->Length < 4) {
                Result = ERROR_INVALID_DATA;
                break;
            }

            MaximumLength = ContainerHeader->DataOffset + sizeof(CDATA_HEADER) + DataHeader->Length - 4;
            CurrentPosition = ContainerHeader->DataOffset + sizeof(CDATA_HEADER);

            DataPtr = (PBYTE)RtlOffsetToPointer(DataHeader, sizeof(CDATA_HEADER));

            ULONG ctr = 0;
            DWORD totalBytesWritten = 0;

            PBYTE ExtractedChunkData = NULL;
            DWORD ExtractedChunkSize = 0;
            DWORD ExtractedChunkCapacity = 0;

            if (ExtractImageChunks) {
                ExtractedChunkCapacity = 10 * 1024 * 1024; //initial buffer size
                ExtractedChunkData = (PBYTE)LocalAlloc(LMEM_ZEROINIT, ExtractedChunkCapacity);
                if (!ExtractedChunkData) {
                    Result = ERROR_NOT_ENOUGH_MEMORY;
                    wprintf_s(L"%s: Failed to allocate memory for chunk buffer\r\n", __FUNCTIONW__);
                    break;
                }
            }

            //
            // Decode MRT special vdm container as .extracted and collect all chunks into dynamic buffer to save them later.
            //
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

                if (CurrentPosition + sizeof(CHUNK_HEAD) + ChunkLength > MaximumLength) {
                    Result = ERROR_INVALID_DATA;
                    break;
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

                            if (ChunkLength > (MAXDWORD - ExtractedChunkSize)) {
                                Result = ERROR_ARITHMETIC_OVERFLOW;
                                LocalFree(DecodedBuffer);
                                DecodedBuffer = NULL;
                                break;
                            }

                            if ((ExtractedChunkCapacity - ExtractedChunkSize) < ChunkLength) {
                                DWORD NewCapacity = ExtractedChunkCapacity + ChunkLength;
                                PBYTE newBuffer = (PBYTE)LocalReAlloc(ExtractedChunkData,
                                    NewCapacity,
                                    LMEM_MOVEABLE | LMEM_ZEROINIT);

                                if (newBuffer) {
                                    ExtractedChunkData = newBuffer;
                                    ExtractedChunkCapacity = NewCapacity;
                                }
                                else {
                                    wprintf_s(L"%s: Failed to reallocate chunk buffer\r\n", __FUNCTIONW__);
                                    LocalFree(DecodedBuffer);
                                    DecodedBuffer = NULL;
                                    Result = ERROR_NOT_ENOUGH_MEMORY;
                                    break;
                                }
                            }

                            RtlCopyMemory(ExtractedChunkData + ExtractedChunkSize, DecodedBuffer, ChunkLength);
                            ExtractedChunkSize += ChunkLength;
                            ctr++;
                        }
                    }

                    LocalFree(DecodedBuffer);
                    DecodedBuffer = NULL;
                }
                else {
                    Result = ERROR_NOT_ENOUGH_MEMORY;
                    break;
                }

                EntryLength = sizeof(CHUNK_HEAD) + ChunkLength;
                CurrentPosition += EntryLength;
                DataPtr = (PBYTE)RtlOffsetToPointer(DataPtr, EntryLength);
            }

            *TotalBytesWritten = totalBytesWritten;
            *TotalBytesRead = (ULONG)CurrentPosition;

            //
            // Process image chunks if requested.
            //
            if (ExtractImageChunks) {
                if (ExtractedChunkData && ExtractedChunkSize > 0) {
                    ULONG extractedChunks = 0;
                    Result = ExtractImageChunksFromBuffer(szCurrentDirectory,
                        ExtractedChunkData,
                        ExtractedChunkSize,
                        &extractedChunks,
                        __FUNCTIONW__);

                    if (ExtractedChunks) {
                        *ExtractedChunks = extractedChunks;
                    }
                }
                else {
                    Result = ERROR_SUCCESS;
                }

                if (ExtractedChunkData) {
                    LocalFree(ExtractedChunkData);
                    ExtractedChunkData = NULL;
                }
            }
            else {
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
