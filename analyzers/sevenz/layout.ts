"use strict";

// 7z DOC/7zFormat.txt defines SignatureHeader as 6 signature bytes, 2 version
// bytes, UInt32 CRC and a 20-byte StartHeader.
// https://www.7-zip.org/sdk.html
export const SEVENZIP_SIGNATURE_HEADER_SIZE = 32n;
export const SEVENZIP_SIGNATURE_HEADER_SIZE_NUMBER = Number(SEVENZIP_SIGNATURE_HEADER_SIZE);
// SignatureHeader field offsets and NID values from 7z DOC/7zFormat.txt.
// https://www.7-zip.org/sdk.html
export const SEVENZIP_SIGNATURE_BYTES = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] as const;
export const SEVENZIP_ARCHIVE_VERSION_MAJOR_OFFSET = 6;
export const SEVENZIP_ARCHIVE_VERSION_MINOR_OFFSET = 7;
export const SEVENZIP_START_HEADER_CRC_OFFSET = 8;
export const SEVENZIP_NEXT_HEADER_OFFSET_OFFSET = 12;
export const SEVENZIP_NEXT_HEADER_SIZE_OFFSET = 20;
export const SEVENZIP_NEXT_HEADER_CRC_OFFSET = 28;
export const SEVENZIP_HEADER_MARKER = 0x01;
export const SEVENZIP_ENCODED_HEADER_MARKER = 0x17;
