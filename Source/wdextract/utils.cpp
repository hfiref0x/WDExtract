/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       UTILS.CPP
*
*  VERSION:     1.10
*
*  DATE:        16 Jun 2025
*
*  Program global support routines, ZLib, containers.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#define ZLIB_WINAPI

#include "global.h"
#include "zconf.h"
#include "zlib.h"

#define ZLIB_CHUNK 16384
#define MAX_DOS_HEADER (256 * (1024 * 1024))

unsigned char ZLib_in[ZLIB_CHUNK];
unsigned char ZLib_out[ZLIB_CHUNK];

#ifdef _M_IX86
#pragma comment(lib, "zlib/lib/zlibwapi32.lib")
#elif _M_AMD64
#pragma comment(lib, "zlib/lib/zlibwapi64.lib")
#endif

HANDLE FileOpen(LPCWSTR lpFileName, DWORD dwDesiredAccess)
{
    return CreateFile(lpFileName, dwDesiredAccess, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
}

HANDLE FileCreate(LPCWSTR lpFileName)
{
    return CreateFile(lpFileName, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL);
}

ULONG FileWrite(PBYTE InputBuffer, ULONG Size, HANDLE hFile)
{
    DWORD write = 0;
    WriteFile(hFile, InputBuffer, Size, &write, NULL);
    return write;
}

ULONG FileRead(PBYTE OutputBuffer, ULONG Size, HANDLE hFile)
{
    DWORD read = 0;
    if (!ReadFile(hFile, OutputBuffer, Size, &read, NULL))
        return 0;

    return read;
}

/*
* MapContainerFile
*
* Purpose:
*
* Map WD container dll and return pointer to it.
*
*/
PVOID MapContainerFile(
    _In_ LPCWSTR FileName
)
{
    HANDLE hFile, hMapping = NULL;
    PVOID  pvImageBase = NULL;

    hFile = CreateFile(FileName,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        hMapping = CreateFileMapping(hFile,
            NULL,
            PAGE_READONLY | SEC_IMAGE,
            0,
            0,
            NULL);

        if (hMapping != NULL) {

            pvImageBase = MapViewOfFile(hMapping,
                FILE_MAP_READ, 0, 0, 0);

            CloseHandle(hMapping);
        }
        CloseHandle(hFile);
    }
    return pvImageBase;
}

/*
* GetContainerFromResource
*
* Purpose:
*
* Find WD container in resource and return pointer to it.
*
*/
PBYTE GetContainerFromResource(
    _In_ PVOID DllHandle,
    _Out_opt_ PULONG ContainerSize
)
{
    ULONG   dwSize = 0;
    HRSRC   hResInfo = NULL;
    HGLOBAL hResData = NULL;
    PBYTE Data;

    if (ContainerSize)
        *ContainerSize = 0;

    hResInfo = FindResource((HMODULE)DllHandle, MAKEINTRESOURCE(1000), L"RT_RCDATA");
    if (hResInfo == NULL)
        return NULL;

    dwSize = SizeofResource((HMODULE)DllHandle, hResInfo);
    if (dwSize == 0)
        return NULL;

    hResData = LoadResource((HMODULE)DllHandle, hResInfo);
    if (hResData == NULL)
        return NULL;


    Data = (PBYTE)LockResource(hResData);
    if (Data && ContainerSize)
        *ContainerSize = dwSize;

    return Data;
}

/*
* IsValidContainer
*
* Purpose:
*
* Validate WD container, return TRUE on success.
*
*/
BOOLEAN IsValidContainer(
    _In_ PVOID Container,
    _In_ ULONG Size
)
{
    RMDX_HEADER* Header = (RMDX_HEADER*)Container;
    CDATA_HEADER* DataHeader;

    __try {

        if (!Container || Size < sizeof(RMDX_HEADER))
            return FALSE;

        if (Header->Signature != RMDX_MAGIC)
            return FALSE;

        if (Header->DataOffset == 0 || Header->DataSize == 0)
            return FALSE;

        if (Header->DataOffset >= Size)
            return FALSE;

        DataHeader = (PCDATA_HEADER)RtlOffsetToPointer(Header, Header->DataOffset);
        if (DataHeader->Length == 0)
            return FALSE;

        if (Header->DataSize < DataHeader->Length)
            return FALSE;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return TRUE;
}

/*
* IsContainerNIS
*
* Purpose:
*
* Check if this is NIS container, return TRUE on success.
*
*/
BOOLEAN IsContainerNIS(
    _In_ PVOID Container)
{
    CDATA_HEADER_NIS* NisDataHeader;

    __try {

        NisDataHeader = (PCDATA_HEADER_NIS)Container;

        //utf-8
        if ((NisDataHeader->Utf8Marker[0] == 0xef) &&
            (NisDataHeader->Utf8Marker[1] == 0xbb) &&
            (NisDataHeader->Utf8Marker[2] == 0xbf))
            return TRUE;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}

void XorMemoryBuffer(
    _In_ unsigned char* p,
    _In_ unsigned char key,
    _In_ size_t length)
{
    while (length > 0)
    {
        *(p++) ^= key;
        --length;
    }
}

/*
* ZLibUnpack
*
* Purpose:
*
* Unpack zlib compressed WD container.
*
*/
BOOLEAN ZLibUnpack(
    _In_ PCDATA_HEADER DataHeader,
    _In_ HANDLE OutputFileHandle,
    _Out_ PULONG TotalBytesWritten,
    _Out_ PULONG TotalBytesRead
)
{
    int ret;
    unsigned have = 0, got = 0;
    z_stream strm;

    DWORD totalBytesWritten = 0;
    DWORD CurrentPosition = 0;
    DWORD CopyLength;
    DWORD ResourceSize = DataHeader->Length;
    PVOID Data = DataHeader->u1.Data;

    *TotalBytesWritten = 0;
    *TotalBytesRead = 0;

    RtlZeroMemory(&strm, sizeof(strm));
    ret = inflateInit2(&strm, -15);
    if (ret != Z_OK) {
        return FALSE;
    }

    __stosb(ZLib_in, 0, sizeof(ZLib_in));
    __stosb(ZLib_out, 0, sizeof(ZLib_out));

    do {
        CopyLength = ZLIB_CHUNK;
        if (CurrentPosition + CopyLength > ResourceSize)
            CopyLength = ResourceSize - CurrentPosition;

        RtlCopyMemory(ZLib_in, RtlOffsetToPointer(Data, CurrentPosition), (SIZE_T)CopyLength);
        CurrentPosition += CopyLength;

        strm.avail_in = CopyLength;
        if (strm.avail_in == 0)
            break;
        strm.next_in = ZLib_in;

        do {
            strm.avail_out = ZLIB_CHUNK;
            strm.next_out = ZLib_out;
            ret = inflate(&strm, Z_NO_FLUSH);

            if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                inflateEnd(&strm);
                *TotalBytesWritten = totalBytesWritten;
                *TotalBytesRead = CurrentPosition;
                return FALSE;
            }

            have = ZLIB_CHUNK - strm.avail_out;
            if (have > 0) {
                got = FileWrite(ZLib_out, have, OutputFileHandle);
                totalBytesWritten += got;
                if (got != have) {
                    inflateEnd(&strm);
                    *TotalBytesWritten = totalBytesWritten;
                    *TotalBytesRead = CurrentPosition;
                    return FALSE;
                }
            }
        } while (strm.avail_out == 0);

    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);

    *TotalBytesWritten = totalBytesWritten;
    *TotalBytesRead = CurrentPosition;

    return TRUE;
}

/*
* ShowWin32Error
*
* Purpose:
*
* Display detailed last error to user.
*
*/
void ShowWin32Error(
    _In_ DWORD ErrorCode,
    _In_ LPCWSTR Function)
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    SIZE_T bufSize;

    if (FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM | 
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        ErrorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf,
        0, NULL))
    {
        bufSize = (wcslen((LPWSTR)lpMsgBuf) + wcslen((LPWSTR)Function) + 40) * sizeof(WCHAR);
        lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, bufSize);
        if (lpDisplayBuf) {

            StringCchPrintf((LPWSTR)lpDisplayBuf,
                LocalSize(lpDisplayBuf) / sizeof(CHAR),
                L"%s failed with error %u: %s",
                Function, ErrorCode, (LPWSTR)lpMsgBuf);
            wprintf_s(L"%s", (LPWSTR)lpDisplayBuf);

            LocalFree(lpDisplayBuf);
        }
        LocalFree(lpMsgBuf);
    }
}

/*
* GetImageSize
*
* Purpose:
*
* Caclulate image size from header.
*
*/
BOOLEAN GetImageSize(
    _In_ PVOID ImageBase,
    _Out_ PULONG SizeOfImage
)
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    WORD Machine, i;

    ULONG size = 0;

    IMAGE_OPTIONAL_HEADER32* Opt32;
    IMAGE_OPTIONAL_HEADER64* Opt64;
    IMAGE_SECTION_HEADER* SectionTableEntry;
    IMAGE_DATA_DIRECTORY* SecurityDataDirectory;

    if (!ImageBase || !SizeOfImage)
        return FALSE;

    *SizeOfImage = 0;

    __try {

        NtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
        Machine = NtHeaders->FileHeader.Machine;

        Opt32 = (IMAGE_OPTIONAL_HEADER32*)&NtHeaders->OptionalHeader;
        Opt64 = (IMAGE_OPTIONAL_HEADER64*)Opt32;

        if (Machine == IMAGE_FILE_MACHINE_I386) {
            size = Opt32->SizeOfHeaders;
            SecurityDataDirectory = (IMAGE_DATA_DIRECTORY*)&Opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        }
        else {
            size = Opt64->SizeOfHeaders;
            SecurityDataDirectory = (IMAGE_DATA_DIRECTORY*)&Opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        }

        SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
            sizeof(ULONG) +
            sizeof(IMAGE_FILE_HEADER) +
            NtHeaders->FileHeader.SizeOfOptionalHeader);

        i = NtHeaders->FileHeader.NumberOfSections;
        while (i > 0) {
            size += SectionTableEntry->SizeOfRawData;
            i -= 1;
            SectionTableEntry += 1;
        }

        if ((SecurityDataDirectory->VirtualAddress) && (SecurityDataDirectory->Size))
            size += SecurityDataDirectory->Size;

        *SizeOfImage = size;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

/*
* IsValidImage
*
* Purpose:
*
* Check whatever image is in valid PE (I386/AMD64) format.
*
*/
BOOLEAN IsValidImage(
    _In_ PVOID ImageBase
)
{
    WORD Machine, Magic;
    PIMAGE_NT_HEADERS NtHeaders = NULL;

    if (!ImageBase)
        return FALSE;

    __try {
        if (((PIMAGE_DOS_HEADER)ImageBase)->e_magic != IMAGE_DOS_SIGNATURE)
            return FALSE;

        NtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
        if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
            return FALSE;

        Machine = NtHeaders->FileHeader.Machine;

        if ((Machine != IMAGE_FILE_MACHINE_AMD64) &&
            (Machine != IMAGE_FILE_MACHINE_I386))
            return FALSE;

        Magic = NtHeaders->OptionalHeader.Magic;

        if (Machine == IMAGE_FILE_MACHINE_I386) {
            if (Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                return FALSE;
        }
        else {
            if (Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return FALSE;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

#define ALIGN_DOWN(x, align) ((x) &~ ((align) - 1))

DWORD RvaToOffset(
    _In_ PIMAGE_NT_HEADERS NtHeaders,
    _In_ DWORD Rva)
{
    DWORD Offset;
    PIMAGE_SECTION_HEADER SectionTableEntry;
    ULONG i;

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
        if (Rva >= SectionTableEntry->VirtualAddress &&
            Rva < (SectionTableEntry->VirtualAddress + SectionTableEntry->Misc.VirtualSize))
        {
            Offset = Rva - SectionTableEntry->VirtualAddress;
            Offset += ALIGN_DOWN(SectionTableEntry->PointerToRawData, NtHeaders->OptionalHeader.FileAlignment);
            return Offset;
        }
        SectionTableEntry++;
    }

    return 0;
}

/*
* ExtractImageNameFromExport
*
* Purpose:
*
* Query dll name from export table.
*
*/
_Success_(return == TRUE)
BOOLEAN ExtractImageNameFromExport(
    _In_ PVOID ImageBase,
    _Out_ LPWSTR ImageName,
    _In_ ULONG cchImageName
)
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    IMAGE_DATA_DIRECTORY* DataDirectory;
    IMAGE_EXPORT_DIRECTORY* Exports;
    IMAGE_OPTIONAL_HEADER32* Opt32;
    IMAGE_OPTIONAL_HEADER64* Opt64;

    WORD Machine;
    ULONG ExportDirOffset;
    ULONG size = 0;

    ULONG NameOffset;
    CHAR* Name;

    __try {

        NtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
        Machine = NtHeaders->FileHeader.Machine;

        Opt32 = (IMAGE_OPTIONAL_HEADER32*)&NtHeaders->OptionalHeader;
        Opt64 = (IMAGE_OPTIONAL_HEADER64*)Opt32;

        if (Machine == IMAGE_FILE_MACHINE_I386) {
            size = Opt32->SizeOfHeaders;
            DataDirectory = (IMAGE_DATA_DIRECTORY*)&Opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        }
        else {
            size = Opt64->SizeOfHeaders;
            DataDirectory = (IMAGE_DATA_DIRECTORY*)&Opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        }

        if ((DataDirectory->VirtualAddress) && (DataDirectory->Size)) {

            ExportDirOffset = RvaToOffset(NtHeaders, DataDirectory->VirtualAddress);
            if (ExportDirOffset) {
                Exports = (IMAGE_EXPORT_DIRECTORY*)RtlOffsetToPointer(ImageBase, ExportDirOffset);
                if (Exports) {
                    NameOffset = RvaToOffset(NtHeaders, Exports->Name);
                    if (NameOffset) {
                        Name = (CHAR*)RtlOffsetToPointer(ImageBase, NameOffset);
                        MultiByteToWideChar(CP_ACP, 0, Name, -1, ImageName, cchImageName);
                        return TRUE;
                    }
                }
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return FALSE;
}

/*
* GetDeltaBlobSig
*
* Purpose:
*
* Return pointer to the delta blob signature in the delta file.
*
*/
PBYTE GetDeltaBlobSig(
    _In_ PBYTE deltaData
)
{
    PCSIG_ENTRY entry = (PCSIG_ENTRY)deltaData;
    DWORD sigSize = GET_SIG_SIZE(entry);

    return deltaData + sigSize + sizeof(entry->Type) + sizeof(entry->SizeLow) + sizeof(entry->SizeHigh);
}

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
    PWCHAR p = (PWCHAR)&NisDataHeader->Data;
    LPWSTR pConverted = NULL;

    INT nLength = MultiByteToWideChar(CP_ACP, 0, (CHAR*)p, -1, NULL, 0);
    if (nLength) {
        pConverted = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, (1 + (SIZE_T)nLength) * sizeof(WCHAR));
        if (pConverted) {

            tl1 = wcslen(OpenElement);
            tl2 = wcslen(CloseElement);

            MultiByteToWideChar(CP_ACP, 0, (CHAR*)p, -1, pConverted, nLength);

            PWCHAR CurrentPosition = pConverted;
            PWCHAR MaximumPosition = (PWCHAR)(pConverted + wcslen(pConverted)) - tl2;

            while (CurrentPosition < MaximumPosition) {

                WCHAR* OpenBlob = wcsstr(CurrentPosition, OpenElement);
                if (OpenBlob) {

                    OpenBlob += tl1;
                    if (OpenBlob >= MaximumPosition) {
                        break;
                    }

                    ULONG ChunkLength = 0;
                    WCHAR* ptr = OpenBlob;
                    while (ptr < MaximumPosition && *ptr != L'<') {
                        ChunkLength++;
                        ptr++;
                    }

                    if (ptr < MaximumPosition && ChunkLength > 0) {

                        DWORD cbBinary = 0;
                        CryptStringToBinary(OpenBlob, (DWORD)ChunkLength,
                            CRYPT_STRING_BASE64, NULL, (DWORD*)&cbBinary, NULL, NULL);

                        BYTE* pbBinary = (BYTE*)LocalAlloc(LMEM_ZEROINIT, cbBinary);
                        if (pbBinary) {

                            if (CryptStringToBinary(OpenBlob, (DWORD)ChunkLength,
                                CRYPT_STRING_BASE64, pbBinary, &cbBinary, NULL, NULL))
                            {
                                wprintf_s(L"%s: Found image at position %08IX with size = %lu\r\n", __FUNCTIONW__,
                                    (ULONG_PTR)OpenBlob,
                                    ChunkLength);

                                UINT extractResult = ExtractCallback(szCurrentDirectory, pbBinary, cbBinary, ctr, TRUE);
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

        while (CurrentPosition < BufferSize - sizeof(WORD)) {
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
