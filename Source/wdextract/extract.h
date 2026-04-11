/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       EXTRACT.H
*
*  VERSION:     1.13
*
*  DATE:        11 Apr 2026
*
*  Extraction routines header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

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

UINT ExtractContainerOnly(
    _In_ LPCWSTR FileName,
    _In_ PVOID Container,
    _In_ ULONG ContainerSize);

UINT ExtractDataDll(
    _In_ LPCWSTR FileName,
    _In_ PVOID ImageBase,
    _Out_ PULONG TotalBytesWritten,
    _Out_ PULONG TotalBytesRead,
    _In_ BOOLEAN ExtractImageChunks,
    _Out_opt_ PULONG ExtractedChunks,
    _In_ BOOLEAN ExtractContainerFlag);

UINT ExtractDataEXE(
    _In_ LPCWSTR FileName,
    _In_ PVOID ImageBase,
    _Out_ PULONG TotalBytesWritten,
    _Out_ PULONG TotalBytesRead,
    _In_ BOOLEAN ExtractImageChunks,
    _Out_opt_ PULONG ExtractedChunks,
    _In_ BOOLEAN ExtractContainerFlag);
