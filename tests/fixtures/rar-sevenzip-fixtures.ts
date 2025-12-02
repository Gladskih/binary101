"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { crc32, encodeVint, encoder, u32le } from "./archive-fixture-helpers.js";

export const createSevenZipFile = () => {
  const header = new Uint8Array(32).fill(0);
  const sig = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
  header.set(sig, 0);
  header[6] = 0; // version major
  header[7] = 4; // version minor
  // next header located immediately after the start header
  const view = new DataView(header.buffer);
  view.setBigUint64(12, 0n, true); // next header offset
  view.setBigUint64(20, 2n, true); // next header size
  const nextHeader = new Uint8Array([0x01, 0x00]); // minimal header + terminator
  const combined = new Uint8Array(header.length + nextHeader.length);
  combined.set(header, 0);
  combined.set(nextHeader, header.length);
  return new MockFile(combined, "sample.7z", "application/x-7z-compressed");
};

export const createRar4File = () => {
  const signature = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
  const LONG_BLOCK = 0x8000;
  const fileData = new Uint8Array([0x48, 0x69]); // "Hi"
  const fileName = encoder.encode("hello.txt");

  const mainHeadSize = 13;
  const mainHeader = [
    0x00,
    0x00, // CRC16 placeholder
    0x73, // HEAD3_MAIN
    0x00,
    0x00, // flags
    mainHeadSize & 0xff,
    (mainHeadSize >> 8) & 0xff,
    0x00,
    0x00, // HighPosAV
    0x00,
    0x00,
    0x00,
    0x00 // PosAV
  ];

  const fileHeadSize = 32 + fileName.length;
  const fileFlags = LONG_BLOCK;
  const fileHeader = [
    0x00,
    0x00, // CRC16 placeholder
    0x74, // HEAD3_FILE
    fileFlags & 0xff,
    (fileFlags >> 8) & 0xff,
    fileHeadSize & 0xff,
    (fileHeadSize >> 8) & 0xff,
    ...u32le(fileData.length),
    ...u32le(fileData.length),
    0x02, // host OS Windows
    ...u32le(crc32(fileData)),
    ...u32le(0), // file time
    20, // UnpVer
    0x30, // Store method
    fileName.length & 0xff,
    (fileName.length >> 8) & 0xff,
    ...u32le(0x20), // file attributes
    ...fileName
  ];

  const endHeader = [0x00, 0x00, 0x7b, 0x00, 0x00, 0x07, 0x00];

  const bytes = new Uint8Array(
    signature.length + mainHeader.length + fileHeader.length + fileData.length + endHeader.length
  );
  let cursor = 0;
  [signature, mainHeader, fileHeader].forEach(part => {
    bytes.set(part, cursor);
    cursor += part.length;
  });
  bytes.set(fileData, cursor);
  cursor += fileData.length;
  bytes.set(endHeader, cursor);

  return new MockFile(bytes, "sample.rar", "application/x-rar-compressed");
};

export const createRar5File = () => {
  const signature = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
  const HFL_DATA = 0x0002;
  const FHFL_CRC32 = 0x0004;

  const fileData = new Uint8Array([0x48, 0x69]); // "Hi"
  const fileName = encoder.encode("note.txt");
  const buildHeader = (headerFields: number[]): number[] => {
    const sizeBytes = encodeVint(headerFields.length);
    const headerBytes = Uint8Array.from([...sizeBytes, ...headerFields]);
    const headerCrc = crc32(headerBytes);
    return [...u32le(headerCrc), ...headerBytes];
  };

  const mainHeader = buildHeader([
    ...encodeVint(1), // main header type
    ...encodeVint(0), // header flags
    ...encodeVint(0) // archive flags
  ]);

  const fileHeader = buildHeader([
    ...encodeVint(2), // file header type
    ...encodeVint(HFL_DATA), // header flags (data area present)
    ...encodeVint(fileData.length), // packed size
    ...encodeVint(FHFL_CRC32), // file flags
    ...encodeVint(fileData.length), // unpacked size
    ...encodeVint(0x20), // file attributes
    ...u32le(crc32(fileData)), // data CRC
    ...encodeVint(0), // compression info (store)
    ...encodeVint(0), // host OS Windows
    ...encodeVint(fileName.length),
    ...fileName
  ]);

  const endHeader = buildHeader([
    ...encodeVint(5), // end of archive
    ...encodeVint(0), // header flags
    ...encodeVint(0) // archive flags
  ]);

  const bytes = new Uint8Array(
    signature.length + mainHeader.length + fileHeader.length + fileData.length + endHeader.length
  );
  let cursor = 0;
  [signature, mainHeader, fileHeader].forEach(part => {
    bytes.set(part, cursor);
    cursor += part.length;
  });
  bytes.set(fileData, cursor);
  cursor += fileData.length;
  bytes.set(endHeader, cursor);

  return new MockFile(bytes, "sample-v5.rar", "application/x-rar-compressed");
};
