"use strict";

// 7z source headers identify LZMA with method ID 0x03 0x01 0x01.
// https://www.7-zip.org/sdk.html
export const SEVENZIP_LZMA_METHOD_ID = "030101";
// LZMA SDK uses five coder property bytes: lc/lp/pb plus dictionary size.
// https://www.7-zip.org/sdk.html
export const SEVENZIP_LZMA_PROPERTY_BYTES = 5;
