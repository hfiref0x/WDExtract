/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       UTILS.H
*
*  VERSION:     1.02
*
*  DATE:        22 Apr 2019
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

HANDLE FileOpen(LPCWSTR lpFileName, DWORD dwDesiredAccess);
HANDLE FileCreate(LPCWSTR lpFileName);
ULONG FileWrite(PBYTE InputBuffer, ULONG Size, HANDLE hFile);
ULONG FileRead(PBYTE OutputBuffer, ULONG Size, HANDLE hFile);
#define FileClose(FileHandle) CloseHandle(FileHandle)
#define RtlOffsetToPointer(Base, Offset) ((PCHAR)( ((PCHAR)(Base)) + ((ULONG_PTR)(Offset)) ))

VOID ShowWin32Error(
    _In_ DWORD ErrorCode,
    _In_ LPCSTR Function);

PVOID MapContainerFile(
    _In_ LPWSTR FileName);

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
