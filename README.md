
# WDExtract
## Extract Windows Defender database from vdm files and unpack it

+ This program distributed as-is, without any warranty;
+ No official support, if you like this tool, feel free to contribute.

## Features
* Unpack VDM containers of Windows Defender/Microsoft Security Essentials;
* Decrypt VDM container embedded in Malicious Remotal Tool (MRT.exe);
* Extract all PE images from unpacked/decrypted containers on the fly (-e switch):
   * dump VDLLs (Virtual DLLs);
   * dump VFS (Virtual File System) contents;
   * dump signatures auxilarity images;
   * code can be adapted to dump type specific chunks of database (not implemented);
* Faster than any script.

List of MRT extracted images, (version 5.71.15840.1)
https://gist.githubusercontent.com/hfiref0x/e4b97fb7135c9a6f9f0787c07da0a99d/raw/d91e77f71aa96bdb98d121b1d915dc697ce85e2a/gistfile1.txt

List of WD extracted images, mpasbase.vdm (version 1.291.0.0)
https://gist.githubusercontent.com/hfiref0x/38e7845304d10c284220461c86491bdf/raw/39c999e59ff2a924932fe6db811555161596b4a7/gistfile1.txt

### Usage
wdextract file [-e]
* file - filename of VDM container (*.vdm file or MRT.exe executable);
* -e optional parameter, extract all found PE image chunks found in VDM after unpacking/decrypting (this including VFS components and emulator VDLLs).


# Build

+ Source code written in C;
+ Built with MSVS 2017 with Windows SDK 17763 installed;
+ Can be built with previous versions of MSVS and SDK's.

# Related references and tools
+ PowerShell unpack script for packed VDM containers, https://gist.github.com/mattifestation/3af5a472e11b7e135273e71cb5fed866
+ Windows Defender Emulator Tools, https://github.com/0xAlexei/WindowsDefenderTools
+ Porting Windows Dynamic Link Libraries to Linux, https://github.com/taviso/loadlibrary
+ MpEnum, https://github.com/hfiref0x/MpEnum
+ libmpclient, https://github.com/UldisRinkevichs/libmpclient

# N.B.
No actual dumped/extracted/unpacked binary data included or will be included in this repository.

# 3rd party code usage
Uses ZLIB Data Compression Library (https://github.com/madler/zlib)

# Authors
(c) 2019 WDEXTRACT Project
