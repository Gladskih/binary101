"use strict";

import { CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_EMBEDDED_SIGNATURE_OLD } from "./commands.js";
import { bigFromUint32, clampRangeSize, readCommandString, readRange, subView } from "./format.js";
import type { MachOCodeDirectory, MachOCodeSignature, MachOCodeSignatureSlot } from "./types.js";

const parseCodeDirectory = (
  view: DataView,
  offset: number,
  issues: string[]
): MachOCodeDirectory | null => {
  // Field offsets match CS_CodeDirectory in xnu/osfmk/kern/cs_blobs.h.
  if (offset < 0 || offset + 44 > view.byteLength) {
    issues.push("CodeDirectory blob is truncated.");
    return null;
  }
  const length = view.getUint32(offset + 4, false);
  if (offset + length > view.byteLength) {
    issues.push("CodeDirectory length exceeds available code-signing data.");
  }
  const version = view.getUint32(offset + 8, false);
  const flags = view.getUint32(offset + 12, false);
  const identOffset = view.getUint32(offset + 20, false);
  const nSpecialSlots = view.getUint32(offset + 24, false);
  const nCodeSlots = view.getUint32(offset + 28, false);
  const codeLimit32 = view.getUint32(offset + 32, false);
  const hashSize = view.getUint8(offset + 36);
  const hashType = view.getUint8(offset + 37);
  const platform = view.getUint8(offset + 38);
  const pageSizePower = view.getUint8(offset + 39);
  let teamIdentifier: string | null = null;
  let codeLimit = bigFromUint32(codeLimit32);
  let execSegBase: bigint | null = null;
  let execSegLimit: bigint | null = null;
  let execSegFlags: bigint | null = null;
  let runtime: number | null = null;
  // Version gates follow CS_CodeDirectory evolution in xnu/osfmk/kern/cs_blobs.h.
  if (version >= 0x20200 && offset + 52 <= view.byteLength) {
    const teamOffset = view.getUint32(offset + 48, false);
    if (teamOffset > 0) {
      teamIdentifier = readCommandString(subView(view, offset, Math.min(length, view.byteLength - offset)), teamOffset);
    }
  }
  if (version >= 0x20300 && offset + 64 <= view.byteLength) {
    codeLimit = view.getBigUint64(offset + 56, false);
  }
  if (version >= 0x20400 && offset + 88 <= view.byteLength) {
    execSegBase = view.getBigUint64(offset + 64, false);
    execSegLimit = view.getBigUint64(offset + 72, false);
    execSegFlags = view.getBigUint64(offset + 80, false);
  }
  if (version >= 0x20500 && offset + 96 <= view.byteLength) {
    runtime = view.getUint32(offset + 88, false);
  }
  const stringWindow = subView(view, offset, Math.min(length, view.byteLength - offset));
  return {
    version,
    flags,
    hashSize,
    hashType,
    platform: platform || null,
    pageSizeShift: pageSizePower,
    nSpecialSlots,
    nCodeSlots,
    codeLimit,
    identifier: identOffset > 0 ? readCommandString(stringWindow, identOffset) : null,
    teamIdentifier,
    execSegBase,
    execSegLimit,
    execSegFlags,
    runtime
  };
};

const parseCodeSignature = async (
  file: File,
  imageOffset: number,
  imageSize: number,
  loadCommandIndex: number,
  dataoff: number,
  datasize: number
): Promise<MachOCodeSignature> => {
  const issues: string[] = [];
  const availableSize = clampRangeSize(imageSize, dataoff, datasize);
  if (availableSize < datasize) {
    issues.push("Code-signing data extends beyond the Mach-O image.");
  }
  const view = await readRange(file, imageOffset + dataoff, availableSize);
  const base: MachOCodeSignature = {
    loadCommandIndex,
    dataoff,
    datasize,
    magic: null,
    length: null,
    blobCount: null,
    slots: [],
    codeDirectory: null,
    issues
  };
  if (view.byteLength < 8) {
    issues.push("Code-signing data is too short to contain a blob header.");
    return base;
  }
  base.magic = view.getUint32(0, false);
  base.length = view.getUint32(4, false);
  if (base.magic !== CSMAGIC_EMBEDDED_SIGNATURE && base.magic !== CSMAGIC_EMBEDDED_SIGNATURE_OLD) {
    return base;
  }
  if (view.byteLength < 12) {
    issues.push("Code-signing superblob is truncated.");
    return base;
  }
  const blobCount = view.getUint32(8, false);
  base.blobCount = blobCount;
  const availableIndexes = Math.floor(Math.max(0, view.byteLength - 12) / 8);
  if (availableIndexes < blobCount) {
    issues.push(`Code-signing superblob declares ${blobCount} entries but only ${availableIndexes} index records fit.`);
  }
  for (let index = 0; index < Math.min(blobCount, availableIndexes); index += 1) {
    const indexOffset = 12 + index * 8;
    const type = view.getUint32(indexOffset, false);
    const blobOffset = view.getUint32(indexOffset + 4, false);
    let magic: number | null = null;
    let length: number | null = null;
    if (blobOffset + 8 <= view.byteLength) {
      magic = view.getUint32(blobOffset, false);
      length = view.getUint32(blobOffset + 4, false);
      if (type === 0 && magic === CSMAGIC_CODEDIRECTORY) {
        base.codeDirectory = parseCodeDirectory(view, blobOffset, issues);
      }
    } else {
      issues.push(`Code-signing blob index ${index} points outside available data.`);
    }
    const slot: MachOCodeSignatureSlot = {
      type,
      offset: blobOffset,
      magic,
      length
    };
    base.slots.push(slot);
  }
  return base;
};

export { parseCodeSignature };
