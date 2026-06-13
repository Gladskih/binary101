"use strict";

// Microsoft PE format, ".rsrc Section":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
// IMAGE_RESOURCE_DIRECTORY and IMAGE_RESOURCE_DATA_ENTRY are 16 bytes;
// IMAGE_RESOURCE_DIRECTORY_ENTRY is 8 bytes.
export const IMAGE_RESOURCE_DIRECTORY_SIZE = 16;
export const IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = 8;
// Microsoft PE format, "Resource Directory Entries": the high bit distinguishes string-vs-ID
// names and subdirectory-vs-data targets.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
export const RESOURCE_DIRECTORY_HIGH_BIT = 0x80000000;
export const RESOURCE_DIRECTORY_OFFSET_MASK = 0x7fffffff;
