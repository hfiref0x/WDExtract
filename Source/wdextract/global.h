/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.02
*
*  DATE:        22 Apr 2019
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
#include "mpengine.h"
#include "utils.h"

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "crypt32.lib")
