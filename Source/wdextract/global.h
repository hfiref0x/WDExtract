/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2026
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.13
*
*  DATE:        10 Apr 2026
*
*  Common include header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#include <Windows.h>
#include <strsafe.h>
#include <dbghelp.h>
#include <wincrypt.h>
#include <intrin.h>
#include "mpengine.h"
#include "utils.h"

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "crypt32.lib")

#define SIGNATURE_TYPE_DELTA_BLOB          0x73
#define SIGNATURE_TYPE_DELTA_BLOB_RECINFO  0x74
#define DELTA_COPY_LENGTH_MASK             0x7FFF
#define DELTA_COPY_LENGTH_BIAS             6
