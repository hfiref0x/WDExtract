/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       UTILS.CPP
*
*  VERSION:     1.03
*
*  DATE:        10 Feb 2020
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
    return CreateFile(lpFileName, dwDesiredAccess, 0, NULL, OPEN_EXISTING, 0, NULL);
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
    _In_ LPWSTR FileName
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
    if (Data) {
        if (ContainerSize)
            *ContainerSize = dwSize;
    }

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

        if (Header->Signature != RMDX_MAGIC)
            return FALSE;

        if (Header->DataOffset == 0 || Header->DataSize == 0)
            return FALSE;

        if ((Size == 0) || (Header->DataOffset >= Size))
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

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
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

            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                *TotalBytesWritten = totalBytesWritten;
                *TotalBytesRead = CurrentPosition;
                return FALSE;
            }
            have = ZLIB_CHUNK - strm.avail_out;
            got = FileWrite(ZLib_out, have, OutputFileHandle);
            totalBytesWritten += got;
            if (got != have) {
                inflateEnd(&strm);
                *TotalBytesWritten = totalBytesWritten;
                *TotalBytesRead = CurrentPosition;
                return FALSE;
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
    _In_ LPCSTR Function)
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;

    if (FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        ErrorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&lpMsgBuf,
        0, NULL))
    {

        lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
            (strlen((LPSTR)lpMsgBuf) + strlen((LPSTR)Function) + 40) * sizeof(CHAR));
        if (lpDisplayBuf) {

            StringCchPrintfA((LPSTR)lpDisplayBuf,
                LocalSize(lpDisplayBuf) / sizeof(CHAR),
                "%s failed with error %u: %s",
                Function, ErrorCode, (LPSTR)lpMsgBuf);
            printf_s("%s", (LPSTR)lpDisplayBuf);

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

    __try {

        *SizeOfImage = 0;

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
    PIMAGE_NT_HEADERS NtHeaders = NULL;

    WORD Machine, Magic;

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

#define ALIGN_DOWN(x, align) (x &~ (align - 1))

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

    i = NtHeaders->FileHeader.NumberOfSections;
    while (i > 0) {
        if (Rva >= SectionTableEntry->VirtualAddress &&
            Rva < (SectionTableEntry->VirtualAddress + SectionTableEntry->Misc.VirtualSize))
        {
            Offset = Rva - SectionTableEntry->VirtualAddress;
            Offset += ALIGN_DOWN(SectionTableEntry->PointerToRawData, NtHeaders->OptionalHeader.FileAlignment);
            return Offset;
        }
        i -= 1;
        SectionTableEntry += 1;
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
                        MultiByteToWideChar(GetACP(), 0, Name, -1, ImageName, cchImageName);
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
