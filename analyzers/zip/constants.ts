"use strict";

const EOCD_SIGNATURE = 0x06054b50;
const ZIP64_EOCD_LOCATOR_SIGNATURE = 0x07064b50;
const ZIP64_EOCD_SIGNATURE = 0x06064b50;
const CENTRAL_DIR_SIGNATURE = 0x02014b50;
const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const MIN_EOCD_SIZE = 22;
const MIN_LOCAL_HEADER_SIZE = 30;
const MAX_EOCD_SCAN = 131072;
const MAX_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });

const COMPRESSION_METHODS = new Map<number, string>([
  [0, "Stored"],
  [1, "Shrunk"],
  [6, "Imploded"],
  [8, "Deflated"],
  [9, "Deflate64"],
  [12, "BZIP2"],
  [14, "LZMA"],
  [18, "IBM TERSE"],
  [19, "IBM LZ77 z"],
  [93, "Zstandard"],
  [94, "MP3"],
  [95, "XZ"],
  [96, "JPEG"],
  [97, "WavPack"],
  [98, "PPMd"],
  [99, "AES encrypted"]
]);

export {
  CENTRAL_DIR_SIGNATURE,
  COMPRESSION_METHODS,
  EOCD_SIGNATURE,
  LOCAL_FILE_HEADER_SIGNATURE,
  MAX_CENTRAL_DIRECTORY_BYTES,
  MAX_EOCD_SCAN,
  MIN_EOCD_SIZE,
  MIN_LOCAL_HEADER_SIZE,
  UTF8_DECODER,
  ZIP64_EOCD_LOCATOR_SIGNATURE,
  ZIP64_EOCD_SIGNATURE
};
