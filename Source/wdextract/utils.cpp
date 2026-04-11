/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2026
*
*  TITLE:       UTILS.CPP
*
*  VERSION:     1.13
*
*  DATE:        10 Apr 2026
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
__declspec(thread) static unsigned char ZLib_in[ZLIB_CHUNK];
__declspec(thread) static unsigned char ZLib_out[ZLIB_CHUNK];

#ifdef _M_IX86
#pragma comment(lib, "zlib/lib/zlibwapi32.lib")
#elif _M_AMD64
#pragma comment(lib, "zlib/lib/zlibwapi64.lib")
#endif

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

    hResInfo = FindResource((HMODULE)DllHandle, CONTAINER_RESOURCE_ID, CONTAINER_RESOURCE_TYPE);
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
    ULONGLONG endOfHeader;

    __try {

        if (!Container || Size < sizeof(RMDX_HEADER))
            return FALSE;

        if (Header->Signature != RMDX_MAGIC)
            return FALSE;

        if (Header->DataOffset == 0 || Header->DataSize == 0)
            return FALSE;

        if (Header->DataOffset >= Size)
            return FALSE;

        endOfHeader = (ULONGLONG)Header->DataOffset + (ULONGLONG)sizeof(CDATA_HEADER);
        if (endOfHeader > (ULONGLONG)Size)
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
                LocalSize(lpDisplayBuf) / sizeof(WCHAR),
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

        NtHeaders = ImageNtHeader(ImageBase);
        if (NtHeaders == NULL) {
            return FALSE;
        }

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
        NtHeaders = ImageNtHeader(ImageBase);
        if (NtHeaders == NULL)
            return FALSE;
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
    _In_ PBYTE deltaData,
    _In_ DWORD deltaDataSize
)
{
    PCSIG_ENTRY entry;
    DWORD sigSize;
    SIZE_T offset;
    SIZE_T entrySize;

    if (!deltaData || deltaDataSize < sizeof(CSIG_ENTRY))
        return NULL;

    __try {

        entry = (PCSIG_ENTRY)deltaData;
        sigSize = GET_SIG_SIZE(entry);
        entrySize = sizeof(entry->Type) + sizeof(entry->SizeLow) + sizeof(entry->SizeHigh) + sigSize;

        if (entrySize > deltaDataSize)
            return NULL;

        if (entry->Type != SIGNATURE_TYPE_DELTA_BLOB_RECINFO)
            return NULL;

        offset = entrySize;
        if (offset + sizeof(CSIG_ENTRY) > deltaDataSize)
            return NULL;

        entry = (PCSIG_ENTRY)(deltaData + offset);
        sigSize = GET_SIG_SIZE(entry);
        entrySize = sizeof(entry->Type) + sizeof(entry->SizeLow) + sizeof(entry->SizeHigh) + sigSize;

        if (offset + entrySize > deltaDataSize)
            return NULL;

        if (entry->Type != SIGNATURE_TYPE_DELTA_BLOB)
            return NULL;

        return (PBYTE)entry;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}
