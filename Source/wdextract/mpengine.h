/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       MPENGINE.H
*
*  VERSION:     1.02
*
*  DATE:        22 Apr 2019
*
*  MpEngine related structures and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define RMDX_MAGIC 'XDMR'

typedef struct _RMDX_HEADER {
    ULONG Signature;        //0
    ULONG Timestamp;        //4
    ULONG Unknown1;         //8
    ULONG Options;          //12 (0C)
    ULONG Unknown2;         //16
    ULONG Unknown3;         //20
    ULONG DataOffset;       //24 (18)
    ULONG DataSize;         //28 (1C)
    //incomplete, irrelevant

} RMDX_HEADER, *PRMDX_HEADER;

typedef struct _CDATA_HEADER {
    ULONG Length;             //0
    ULONG Unknown1;           //4
    union {                   //8
        BYTE Data[1];
        ULONG Unknown2;
    } u1;
} CDATA_HEADER, *PCDATA_HEADER;

typedef struct _CDATA_HEADER_NIS {
    ULONG Unknown0;             //0
    ULONG Unknown1;             //4
    BYTE Utf8Marker[3];         //8
    BYTE Data[1];
} CDATA_HEADER_NIS, *PCDATA_HEADER_NIS;

typedef struct _CHUNK_HEAD {
    BYTE Key;
    BYTE L0;
    BYTE L1;
    BYTE L2;
} CHUNK_HEAD, *PCHUNK_HEAD;

typedef struct _VFS_ENTRY {
    DWORD EntryType;
    DWORD Reserved0;
    FILETIME LastTime1;
    FILETIME LastTime2;
    FILETIME LastTime3;
    ULONG Reserved1;
    ULONG DataLength;
    ULONG Reserved2;
    ULONG Reserved3;
    WCHAR FileName[260];
    ULONG Reserved4;
    ULONG Reserved5;
    ULONG Reserved6;
    ULONG Reserved7;
    ULONG Reserved8;
    ULONG Reserved9;
    ULONG Reserved10;
} VFS_ENTRY, *PVFS_ENTRY;

#define DB_SMART_CODE_SIGNATURE 0x20
#define DB_UNKNOWN_21           0x21
#define DB_BINARY_TROJ_27       0x27
#define DB_TROJ_DOWNLDR_BKDOOR  0x28
#define DB_HTML_SIGNATURE       0x29
#define DB_SIGNAMES_GROUP       0x30
#define DB_BINARY_TROJ_3D       0x3d
#define DB_UNKNOWN_40           0x40
#define DB_URL_SIGNATURE        0x41
#define DB_UNKNOWN_42           0x42
#define DB_UNKNOWN_43           0x43
#define DB_BOOTKIT_SIGNATURE    0x44
#define DB_SMART_SIG            0x49
#define DB_UNKNOWN_50           0x50
#define DB_EXPORTFN_SIG         0x51
#define DB_DOTNET_SIG           0x53
#define DB_UNKNOWN_55           0x55
#define DB_SFXPACK_SIGNATURE    0x56
#define DB_PROCESS_NAME         0x58
#define DB_UNKNOWN_57           0x57
#define DB_MPCONFIG             0x5B
#define DB_SIGNATURE_NAME       0x5c
#define DB_UNKNOWN_5D           0x5d
#define DB_FILEPATH             0x5f
#define DB_FILEPATH3            0x60
#define DB_MIXED_SIGNATURE      0x61
#define DB_REGPATH_SIGNATURE2   0x63
#define DB_UNKNOWN_67           0x67
#define DB_UNKNOWN_6A           0x6A
#define DB_UNKNOWN_6C           0x6C
#define DB_UNKNOWN_70           0x70
#define DB_FILEPATH2            0x71
#define DB_MIXED_SIGNATURE2     0x78
#define DB_EXECUTABLE_IMAGE     0x79
#define DB_UNKNOWN_7A           0x7a
#define DB_EXECUTABLE_IMAGE2    0x7c
#define DB_BINARY_7E            0x7e
#define DB_UNKNOWN_7F           0x7f
#define DB_UNKNOWN_80           0x80
#define DB_FULLPATH_SIG         0x83
#define DB_BINARY_86            0x86
#define DB_UNKNOWN_87           0x87
#define DB_BINARY_SIGNATURE     0x89
#define DB_LINUX_TEXTSIG        0x8c
#define DB_HSTR_SIGNAME         0x8d
#define DB_SCRIPT_SIG           0x8f
#define DB_UNKNOWN_90           0x90
#define DB_CODE_SIGNATURE_95    0x95
#define DB_SIGATTR              0x96
#define DB_SIGNAME_WILDCARD     0x98
#define DB_FAMILY_STRINGS       0x9d
#define DB_CODE_SIGNATURE_A0    0xa0
#define DB_HASH_SIG             0xa6
#define DB_REGPATH_SIGNATURE    0xa9
#define DB_X86_CODE_BLOCK       0xaf
#define DB_FILETYPE_INFO        0xb0
#define DB_SYSFILE_SIG          0xb2
#define DB_HEURISTIC_SIGNAME    0xb4
#define DB_FN_ADDR_AND_HASH     0xb5
#define DB_SIG_GROUP            0xb8
#define DB_UNKNOWN_BA           0xba
#define DB_RESOURCE_TYPE        0xbb
#define DB_UNKNOWN_BC           0xbc
#define DB_SIG_GROUP2           0xbd
#define DB_ANDROID_SIG          0xbe
#define DB_JAVA_SIGNATURE       0xbf
#define DB_PACKER_EP_SIG        0xc0
#define DB_CODE_SIG             0xc1
#define DB_MAGIC_SIG            0xc3
#define DB_EXECUTABLE_IMAGE3    0xc4
#define DB_RANSOM_SIGNATURE     0xc5
#define DB_HEURISTIC_SIGNAME2   0xc7
#define DB_SFXPACK_SIGNATURE2   0xc8
#define DB_HLHIIL_SIGNATURE     0xc9
#define DB_MP_JSINIT            0xca
#define DB_BINARY_SIGNATURE2    0xce
#define DB_UNKNOWN_CF           0xcf
#define DB_SCRIPT_SIGNATURE     0xd0
#define DB_SWF_FEAUTURE         0xd1
#define DB_AUTOIT_SIGNATURE     0xd3
#define DB_GUID                 0xd4
#define DB_SCRIPT_SIGNATURE2    0xd7
#define DB_FN_ADDR_AND_HASH2    0xe1
