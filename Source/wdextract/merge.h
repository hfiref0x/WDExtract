/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       MERGE.H
*
*  VERSION:     1.13
*
*  DATE:        11 Apr 2026
*
*  Merge delta files header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

UINT MergeDeltaBuffer(
    _In_ PBYTE BaseBuffer,
    _In_ DWORD BaseFileSize,
    _In_ PBYTE DeltaBuffer,
    _In_ DWORD DeltaFileSize,
    _In_ BOOLEAN VerifyChecksum,
    _Outptr_result_bytebuffer_maybenull_(*MergedSize) PBYTE* MergedBuffer,
    _Out_ PDWORD MergedSize);

UINT MergeDeltaFiles(
    _In_ LPCWSTR BaseFileName,
    _In_ LPCWSTR DeltaFileName,
    _Out_ PULONG TotalBytesWritten,
    _In_ BOOLEAN ExtractImageChunks,
    _Out_opt_ PULONG ExtractedChunks,
    _In_ BOOLEAN VerifyChecksum);
