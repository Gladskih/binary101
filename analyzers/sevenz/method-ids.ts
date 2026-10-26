"use strict";

// 7z source headers identify LZMA with method ID 0x03 0x01 0x01.
// https://www.7-zip.org/sdk.html
export const SEVENZIP_LZMA_METHOD_ID = "030101";
// CPP/7zip/Compress/Lzma2Register.cpp registers the raw LZMA2 coder as 0x21.
// https://github.com/ip7z/7zip/blob/b88c6bc09339de32f7d18bbab900686b244f42ba/CPP/7zip/Compress/Lzma2Register.cpp
export const SEVENZIP_LZMA2_METHOD_ID = "21";
// LZMA SDK uses five coder property bytes: lc/lp/pb plus dictionary size.
// https://www.7-zip.org/sdk.html
export const SEVENZIP_LZMA_PROPERTY_BYTES = 5;
