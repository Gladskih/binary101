import { crc32 } from "./archive-fixture-helpers.js";

export const createLzmaSevenZipFile = (): Uint8Array => {
  // 7z EncodedHeader -> one raw LZMA stream containing Header [0x01, 0x00].
  // https://github.com/ip7z/7zip/blob/b88c6bc09339de32f7d18bbab900686b244f42ba/DOC/7zFormat.txt
  const packed = Uint8Array.of(0, 0, 0x80, 0x25, 0xa5, 0xef, 255, 255, 0xec, 0xc7, 0, 0);
  const encodedHeader = Uint8Array.of(
    0x17, 0x06, 0, 1, 0x09, packed.length, 0,
    0x07, 0x0b, 1, 0, 1, 0x23, 0x03, 1, 1,
    5, 0x5d, 0, 0, 1, 0, 0x0c, 2, 0, 0
  );
  const bytes = new Uint8Array(32 + packed.length + encodedHeader.length);
  bytes.set([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4]);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(12, BigInt(packed.length), true);
  view.setBigUint64(20, BigInt(encodedHeader.length), true);
  view.setUint32(28, crc32(encodedHeader), true);
  view.setUint32(8, crc32(bytes.subarray(12, 32)), true);
  bytes.set(packed, 32);
  bytes.set(encodedHeader, 32 + packed.length);
  return bytes;
};
