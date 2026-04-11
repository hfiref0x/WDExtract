/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2026
*
*  TITLE:       UTILS.H
*
*  VERSION:     1.13
*
*  DATE:        11 Apr 2026
*
*  Support routines header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _LANGANDCODEPAGE {
    WORD wLanguage;
    WORD wCodePage;
} LANGANDCODEPAGE, * LPTRANSLATE;

#define MAX_FILENAME_BUFFER_LENGTH 1024

#define CONTAINER_RESOURCE_ID     MAKEINTRESOURCE(1000)
#define CONTAINER_RESOURCE_TYPE   L"RT_RCDATA"

#define DEFAULT_CHUNK_NAME          L"module"
#define DEFAULT_CHUNK_NAME_NIS      L"nis_module"
#define CODEBLOB_OPEN               L"<CodeBlob>"
#define CODEBLOB_CLOSE              L"</CodeBlob>"

#define FileOpen(lpFileName, dwDesiredAccess) \
    CreateFile((lpFileName), (dwDesiredAccess), FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)

#define FileCreate(lpFileName) \
    CreateFile((lpFileName), GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL)

static inline ULONG FileWrite(PBYTE InputBuffer, ULONG Size, HANDLE hFile)
{
    DWORD write = 0;
    WriteFile(hFile, InputBuffer, Size, &write, NULL);
    return write;
}

static inline ULONG FileRead(PBYTE OutputBuffer, ULONG Size, HANDLE hFile)
{
    DWORD read = 0;
    if (!ReadFile(hFile, OutputBuffer, Size, &read, NULL))
        return 0;
    return read;
}

#define RtlOffsetToPointer(Base, Offset) ((PCHAR)( ((PCHAR)(Base)) + ((ULONG_PTR)(Offset)) ))

#define GET_SIG_SIZE(entry) ((entry)->SizeLow | ((entry)->SizeHigh << 8))
#define GET_MSB(num) (((num) & (1 << (sizeof(WORD) * 8 - 1))) != 0)

VOID ShowWin32Error(
    _In_ DWORD ErrorCode,
    _In_ LPCWSTR Function);

PVOID MapContainerFile(
    _In_ LPCWSTR FileName);

PBYTE GetContainerFromResource(
    _In_ PVOID DllHandle,
    _Out_opt_ PULONG ContainerSize);

BOOLEAN IsValidContainer(
    _In_ PVOID Container,
    _In_ ULONG Size);

BOOLEAN IsContainerNIS(
    _In_ PVOID Container);

BOOLEAN IsValidImage(
    _In_ PVOID ImageBase);

BOOLEAN GetImageSize(
    _In_ PVOID ImageBase,
    _Out_ PULONG SizeOfImage);

_Success_(return == TRUE)
BOOLEAN ExtractImageNameFromExport(
    _In_ PVOID ImageBase,
    _Out_ LPWSTR ImageName,
    _In_ ULONG cchImageName);

void XorMemoryBuffer(
    _In_ unsigned char *p,
    _In_ unsigned char key,
    _In_ size_t length);

BOOLEAN ZLibUnpack(
    _In_ PCDATA_HEADER DataHeader,
    _In_ HANDLE OutputFileHandle,
    _Out_ PULONG TotalBytesWritten,
    _Out_ PULONG TotalBytesRead);

PBYTE GetDeltaBlobSig(
    _In_ PBYTE deltaData,
    _In_ DWORD deltaDataSize);

DWORD ComputeDeltaJamCrc32(
    _In_reads_bytes_(BufferSize) PBYTE Buffer,
    _In_ DWORD BufferSize);
