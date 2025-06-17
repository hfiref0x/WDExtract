/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       UTILS.H
*
*  VERSION:     1.10
*
*  DATE:        16 Jun 2025
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

#define DEFAULT_CHUNK_NAME          L"module"
#define DEFAULT_CHUNK_NAME_NIS      L"nis_module"
#define CODEBLOB_OPEN               L"<CodeBlob>"
#define CODEBLOB_CLOSE              L"</CodeBlob>"

HANDLE FileOpen(LPCWSTR lpFileName, DWORD dwDesiredAccess);
HANDLE FileCreate(LPCWSTR lpFileName);
ULONG FileWrite(PBYTE InputBuffer, ULONG Size, HANDLE hFile);
ULONG FileRead(PBYTE OutputBuffer, ULONG Size, HANDLE hFile);
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
    _In_ PBYTE deltaData);

ULONG ExtractCallback(
    _In_ LPWSTR CurrentDirectory,
    _In_ PVOID ChunkPtr,
    _In_ ULONG ChunkLength,
    _In_ ULONG ChunkId,
    _In_ BOOLEAN fNIS);

UINT ExtractImageChunksFromBuffer(
    _In_ LPWSTR szCurrentDirectory,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize,
    _Out_ PULONG ExtractedChunks,
    _In_opt_ LPCWSTR CallerName);
