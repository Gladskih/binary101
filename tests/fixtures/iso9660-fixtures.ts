"use strict";
import { MockFile } from "../helpers/mock-file.js";
const BLOCK_SIZE = 2048;
const asciiBytes = (value: string): Uint8Array => {
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i += 1) out[i] = value.charCodeAt(i) & 0xff;
  return out;
};
const writeAsciiPadded = (bytes: Uint8Array, offset: number, length: number, value: string): void => {
  bytes.fill(0x20, offset, offset + length);
  const data = asciiBytes(value);
  bytes.set(data.subarray(0, length), offset);
};
const writeUcs2BePadded = (bytes: Uint8Array, offset: number, length: number, value: string): void => {
  bytes.fill(0x00, offset, offset + length);
  const maxChars = Math.floor(length / 2);
  for (let i = 0; i < Math.min(maxChars, value.length); i += 1) {
    const codeUnit = value.charCodeAt(i) & 0xffff;
    bytes[offset + i * 2] = (codeUnit >> 8) & 0xff;
    bytes[offset + i * 2 + 1] = codeUnit & 0xff;
  }
};
const writeUint16Le = (bytes: Uint8Array, offset: number, value: number): void => {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >> 8) & 0xff;
};
const writeUint16Be = (bytes: Uint8Array, offset: number, value: number): void => {
  bytes[offset] = (value >> 8) & 0xff;
  bytes[offset + 1] = value & 0xff;
};
const writeUint32Le = (bytes: Uint8Array, offset: number, value: number): void => {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >> 8) & 0xff;
  bytes[offset + 2] = (value >> 16) & 0xff;
  bytes[offset + 3] = (value >> 24) & 0xff;
};

const writeUint32Be = (bytes: Uint8Array, offset: number, value: number): void => {
  bytes[offset] = (value >> 24) & 0xff;
  bytes[offset + 1] = (value >> 16) & 0xff;
  bytes[offset + 2] = (value >> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
};

const writeBothEndianUint16 = (bytes: Uint8Array, offset: number, value: number): void => {
  writeUint16Le(bytes, offset, value);
  writeUint16Be(bytes, offset + 2, value);
};

const writeBothEndianUint32 = (bytes: Uint8Array, offset: number, value: number): void => {
  writeUint32Le(bytes, offset, value);
  writeUint32Be(bytes, offset + 4, value);
};

const createDirectoryRecord = (opts: {
  extentLba: number;
  dataLength: number;
  flags: number;
  fileIdBytes: Uint8Array;
}): Uint8Array => {
  const fileIdLen = opts.fileIdBytes.length;
  const padding = fileIdLen % 2 === 0 ? 1 : 0;
  const recordLength = 33 + fileIdLen + padding;
  const out = new Uint8Array(recordLength);
  out[0] = recordLength;
  out[1] = 0;
  writeBothEndianUint32(out, 2, opts.extentLba);
  writeBothEndianUint32(out, 10, opts.dataLength);
  out[18] = 125;
  out[19] = 1;
  out[20] = 1;
  out[21] = 0;
  out[22] = 0;
  out[23] = 0;
  out[24] = 0;
  out[25] = opts.flags & 0xff;
  out[26] = 0;
  out[27] = 0;
  writeBothEndianUint16(out, 28, 1);
  out[32] = fileIdLen & 0xff;
  out.set(opts.fileIdBytes, 33);
  if (padding) out[33 + fileIdLen] = 0;
  return out;
};

const asciiId = (value: string): Uint8Array => asciiBytes(value);

const DOT_FILE_ID = new Uint8Array([0x00]);
const DOT_DOT_FILE_ID = new Uint8Array([0x01]);

const createDotDirectoryRecord = (extentLba: number, dataLength: number): Uint8Array =>
  createDirectoryRecord({ extentLba, dataLength, flags: 0x02, fileIdBytes: DOT_FILE_ID });

const createDotDotDirectoryRecord = (extentLba: number, dataLength: number): Uint8Array =>
  createDirectoryRecord({ extentLba, dataLength, flags: 0x02, fileIdBytes: DOT_DOT_FILE_ID });

const ucs2Id = (value: string): Uint8Array => {
  const out = new Uint8Array(value.length * 2);
  for (let i = 0; i < value.length; i += 1) {
    const codeUnit = value.charCodeAt(i) & 0xffff;
    out[i * 2] = (codeUnit >> 8) & 0xff;
    out[i * 2 + 1] = codeUnit & 0xff;
  }
  return out;
};

const createPrimaryVolumeDescriptor = (opts: {
  volumeSpaceBlocks: number;
  pathTableLba: number;
  pathTableSize: number;
  rootDirLba: number;
  rootDirSize: number;
}): Uint8Array => {
  const pvd = new Uint8Array(BLOCK_SIZE);
  pvd[0] = 1;
  pvd.set(asciiBytes("CD001"), 1);
  pvd[6] = 1;
  writeAsciiPadded(pvd, 8, 32, "TESTSYS");
  writeAsciiPadded(pvd, 40, 32, "TESTVOL");
  writeBothEndianUint32(pvd, 80, opts.volumeSpaceBlocks);
  writeBothEndianUint16(pvd, 120, 1);
  writeBothEndianUint16(pvd, 124, 1);
  writeBothEndianUint16(pvd, 128, BLOCK_SIZE);
  writeBothEndianUint32(pvd, 132, opts.pathTableSize);
  writeUint32Le(pvd, 140, opts.pathTableLba);
  writeUint32Be(pvd, 148, opts.pathTableLba);
  const rootRecord = createDirectoryRecord({
    extentLba: opts.rootDirLba,
    dataLength: opts.rootDirSize,
    flags: 0x02,
    fileIdBytes: DOT_FILE_ID
  });
  pvd.set(rootRecord, 156);
  pvd[881] = 1;
  return pvd;
};

const createSupplementaryJolietDescriptor = (opts: {
  volumeSpaceBlocks: number;
  pathTableLba: number;
  pathTableSize: number;
  rootDirLba: number;
  rootDirSize: number;
}): Uint8Array => {
  const svd = new Uint8Array(BLOCK_SIZE);
  svd[0] = 2;
  svd.set(asciiBytes("CD001"), 1);
  svd[6] = 1;
  writeUcs2BePadded(svd, 8, 32, "JOLIETSYS");
  writeUcs2BePadded(svd, 40, 32, "JOLIETVOL");
  writeBothEndianUint32(svd, 80, opts.volumeSpaceBlocks);
  writeAsciiPadded(svd, 88, 32, "%/E");
  writeBothEndianUint16(svd, 120, 1);
  writeBothEndianUint16(svd, 124, 1);
  writeBothEndianUint16(svd, 128, BLOCK_SIZE);
  writeBothEndianUint32(svd, 132, opts.pathTableSize);
  writeUint32Le(svd, 140, opts.pathTableLba);
  writeUint32Be(svd, 148, opts.pathTableLba);
  const rootRecord = createDirectoryRecord({
    extentLba: opts.rootDirLba,
    dataLength: opts.rootDirSize,
    flags: 0x02,
    fileIdBytes: DOT_FILE_ID
  });
  svd.set(rootRecord, 156);
  svd[881] = 1;
  return svd;
};

const createBootRecord = (bootCatalogLba: number): Uint8Array => {
  const br = new Uint8Array(BLOCK_SIZE);
  br[0] = 0;
  br.set(asciiBytes("CD001"), 1);
  br[6] = 1;
  writeAsciiPadded(br, 7, 32, "EL TORITO SPECIFICATION");
  writeAsciiPadded(br, 39, 32, "TESTBOOT");
  writeUint32Le(br, 71, bootCatalogLba);
  return br;
};

const createTerminatorDescriptor = (): Uint8Array => {
  const term = new Uint8Array(BLOCK_SIZE);
  term[0] = 255;
  term.set(asciiBytes("CD001"), 1);
  term[6] = 1;
  return term;
};

export const createIso9660PrimaryFile = (): MockFile => {
  const totalBlocks = 40;
  const bytes = new Uint8Array(totalBlocks * BLOCK_SIZE);

  const pathTableLba = 20;
  const rootDirLba = 21;
  const subDirLba = 22;
  const fileLba = 23;

  const pathTable = new Uint8Array(10);
  pathTable[0] = 1;
  pathTable[1] = 0;
  writeUint32Le(pathTable, 2, rootDirLba);
  writeUint16Le(pathTable, 6, 1);
  pathTable[8] = 0x00;
  pathTable[9] = 0x00;

  bytes.set(createPrimaryVolumeDescriptor({
    volumeSpaceBlocks: totalBlocks,
    pathTableLba,
    pathTableSize: pathTable.length,
    rootDirLba,
    rootDirSize: BLOCK_SIZE
  }), 16 * BLOCK_SIZE);
  bytes.set(createTerminatorDescriptor(), 17 * BLOCK_SIZE);
  bytes.set(pathTable, pathTableLba * BLOCK_SIZE);

  const rootDir = new Uint8Array(BLOCK_SIZE);
  let cursor = 0;
  for (const record of [
    createDotDirectoryRecord(rootDirLba, BLOCK_SIZE),
    createDotDotDirectoryRecord(rootDirLba, BLOCK_SIZE),
    createDirectoryRecord({ extentLba: fileLba, dataLength: 5, flags: 0x00, fileIdBytes: asciiId("HELLO.TXT;1") }),
    createDirectoryRecord({ extentLba: subDirLba, dataLength: BLOCK_SIZE, flags: 0x02, fileIdBytes: asciiId("SUBDIR") })
  ]) {
    rootDir.set(record, cursor);
    cursor += record.length;
  }
  bytes.set(rootDir, rootDirLba * BLOCK_SIZE);

  const subDir = new Uint8Array(BLOCK_SIZE);
  cursor = 0;
  for (const record of [
    createDotDirectoryRecord(subDirLba, BLOCK_SIZE),
    createDotDotDirectoryRecord(rootDirLba, BLOCK_SIZE)
  ]) {
    subDir.set(record, cursor);
    cursor += record.length;
  }
  bytes.set(subDir, subDirLba * BLOCK_SIZE);

  bytes.set(asciiBytes("HELLO"), fileLba * BLOCK_SIZE);

  return new MockFile(bytes, "sample.iso", "application/x-iso9660-image");
};

export const createIso9660JolietFile = (): MockFile => {
  const totalBlocks = 60;
  const bytes = new Uint8Array(totalBlocks * BLOCK_SIZE);

  const primaryPathTableLba = 20;
  const primaryRootDirLba = 21;
  const jolietPathTableLba = 30;
  const jolietRootDirLba = 31;
  const bootCatalogLba = 40;

  const primary = createIso9660PrimaryFile();
  bytes.set(primary.data, 0);

  const primaryPvd = createPrimaryVolumeDescriptor({
    volumeSpaceBlocks: totalBlocks,
    pathTableLba: primaryPathTableLba,
    pathTableSize: 10,
    rootDirLba: primaryRootDirLba,
    rootDirSize: BLOCK_SIZE
  });
  bytes.set(primaryPvd, 16 * BLOCK_SIZE);
  bytes.set(createBootRecord(bootCatalogLba), 17 * BLOCK_SIZE);
  bytes.set(createSupplementaryJolietDescriptor({
    volumeSpaceBlocks: totalBlocks,
    pathTableLba: jolietPathTableLba,
    pathTableSize: 10,
    rootDirLba: jolietRootDirLba,
    rootDirSize: BLOCK_SIZE
  }), 18 * BLOCK_SIZE);
  bytes.set(createTerminatorDescriptor(), 19 * BLOCK_SIZE);

  const jolietPathTable = new Uint8Array(10);
  jolietPathTable[0] = 1;
  jolietPathTable[1] = 0;
  writeUint32Le(jolietPathTable, 2, jolietRootDirLba);
  writeUint16Le(jolietPathTable, 6, 1);
  jolietPathTable[8] = 0x00;
  jolietPathTable[9] = 0x00;
  bytes.set(jolietPathTable, jolietPathTableLba * BLOCK_SIZE);

  const jolietRootDir = new Uint8Array(BLOCK_SIZE);
  let cursor = 0;
  for (const record of [
    createDotDirectoryRecord(jolietRootDirLba, BLOCK_SIZE),
    createDotDotDirectoryRecord(jolietRootDirLba, BLOCK_SIZE),
    createDirectoryRecord({ extentLba: 50, dataLength: 2, flags: 0x00, fileIdBytes: ucs2Id("A.TXT;1") })
  ]) {
    jolietRootDir.set(record, cursor);
    cursor += record.length;
  }
  bytes.set(jolietRootDir, jolietRootDirLba * BLOCK_SIZE);

  bytes.set(asciiBytes("OK"), 50 * BLOCK_SIZE);

  return new MockFile(bytes, "joliet.iso", "application/x-iso9660-image");
};
