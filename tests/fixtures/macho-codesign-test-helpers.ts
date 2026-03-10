"use strict";

import { CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE } from "../../analyzers/macho/commands.js";

const writeBlobHeader = (bytes: Uint8Array, blobOffset: number, magic: number, length: number): void => {
  // CS_Blob starts with big-endian magic/u32 and length/u32.
  const view = new DataView(bytes.buffer, bytes.byteOffset + blobOffset, 8);
  view.setUint32(0, magic, false);
  view.setUint32(4, length, false);
};

const writeSuperBlob = (
  bytes: Uint8Array,
  options: {
    length: number;
    declaredCount?: number;
    entries: Array<{
      type: number;
      blobOffset: number;
    }>;
  }
): void => {
  // CS_SuperBlob extends CS_Blob with count/u32 and (type, offset) index entries.
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  writeBlobHeader(bytes, 0, CSMAGIC_EMBEDDED_SIGNATURE, options.length);
  view.setUint32(8, options.declaredCount ?? options.entries.length, false);
  for (const [index, entry] of options.entries.entries()) {
    const entryOffset = 12 + index * 8;
    view.setUint32(entryOffset, entry.type, false);
    view.setUint32(entryOffset + 4, entry.blobOffset, false);
  }
};

const writeCodeDirectory = (
  bytes: Uint8Array,
  blobOffset: number,
  options: {
    length: number;
    version: number;
    flags?: number;
    hashOffset?: number;
    identOffset?: number;
    nSpecialSlots?: number;
    nCodeSlots?: number;
    codeLimit32?: number;
    hashSize?: number;
    hashType?: number;
    platform?: number;
    pageSizePower?: number;
    scatterOffset?: number;
    teamOffset?: number;
    codeLimit64?: bigint;
    execSegBase?: bigint;
    execSegLimit?: bigint;
    execSegFlags?: bigint;
    runtime?: number;
  }
): void => {
  // CS_CodeDirectory appends fields as the version grows, but the shared prefix
  // layout is fixed in xnu/osfmk/kern/cs_blobs.h.
  const view = new DataView(bytes.buffer, bytes.byteOffset + blobOffset, bytes.byteLength - blobOffset);
  writeBlobHeader(bytes, blobOffset, CSMAGIC_CODEDIRECTORY, options.length);
  view.setUint32(8, options.version, false);
  for (const [fieldOffset, value] of [
    [12, options.flags],
    [16, options.hashOffset],
    [20, options.identOffset],
    [24, options.nSpecialSlots],
    [28, options.nCodeSlots],
    [32, options.codeLimit32],
    [44, options.scatterOffset],
    [48, options.teamOffset],
    [88, options.runtime]
  ] satisfies Array<[number, number | undefined]>) {
    if (value !== undefined) view.setUint32(fieldOffset, value, false);
  }
  for (const [fieldOffset, value] of [
    [36, options.hashSize],
    [37, options.hashType],
    [38, options.platform],
    [39, options.pageSizePower]
  ] satisfies Array<[number, number | undefined]>) {
    if (value !== undefined) view.setUint8(fieldOffset, value);
  }
  for (const [fieldOffset, value] of [
    [56, options.codeLimit64],
    [64, options.execSegBase],
    [72, options.execSegLimit],
    [80, options.execSegFlags]
  ] satisfies Array<[number, bigint | undefined]>) {
    if (value !== undefined) view.setBigUint64(fieldOffset, value, false);
  }
};

export { writeBlobHeader, writeCodeDirectory, writeSuperBlob };
