"use strict";

import { CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_EMBEDDED_SIGNATURE_OLD } from "./commands.js";
import { bigFromUint32, clampRangeSize, createRangeReader } from "./format.js";
import type { MachOCodeDirectory, MachOCodeSignature, MachOCodeSignatureSlot } from "./types.js";

const codeDirectoryVersionText = (version: number): string => `0x${version.toString(16)}`;
const blobMagicText = (magic: number): string => `0x${magic.toString(16)}`;
// CS_SuperBlob extends the 8-byte CS_Blob header with a 4-byte count field in
// xnu/osfmk/kern/cs_blobs.h, so the fixed header before index entries is 12
// bytes.
const CS_SUPERBLOB_HEADER_SIZE = 12;
const CS_SUPERBLOB_INDEX_SIZE = 8;

const earliestCodeDirectorySize = (version: number): number => {
  // CS_CodeDirectory grows by appending fields. These byte sizes are the
  // offsets of end_earliest / end_withScatter / end_withTeam /
  // end_withCodeLimit64 / end_withExecSeg / end_withPreEncryptOffset /
  // end_withLinkage in xnu/osfmk/kern/cs_blobs.h.
  if (version >= 0x20600) return 108;
  if (version >= 0x20500) return 96;
  if (version >= 0x20400) return 88;
  if (version >= 0x20300) return 64;
  if (version >= 0x20200) return 52;
  if (version >= 0x20100) return 48;
  return 44;
};

const parseCodeDirectory = async (
  reader: ReturnType<typeof createRangeReader>,
  offset: number,
  availableLength: number,
  issues: string[]
): Promise<MachOCodeDirectory | null> => {
  // Field offsets match CS_CodeDirectory in xnu/osfmk/kern/cs_blobs.h.
  const view = await reader.read(offset, Math.min(availableLength, 96));
  if (view.byteLength < 44) {
    issues.push("CodeDirectory blob is truncated.");
    return null;
  }
  const length = view.getUint32(4, false);
  if (length < 44) {
    issues.push("CodeDirectory length is smaller than the fixed header.");
    return null;
  }
  if (availableLength < length) {
    issues.push("CodeDirectory length exceeds available code-signing data.");
  }
  const parseLength = Math.min(availableLength, length);
  const version = view.getUint32(8, false);
  const flags = view.getUint32(12, false);
  const identOffset = view.getUint32(20, false);
  const nSpecialSlots = view.getUint32(24, false);
  const nCodeSlots = view.getUint32(28, false);
  const codeLimit32 = view.getUint32(32, false);
  const hashSize = view.getUint8(36);
  const hashType = view.getUint8(37);
  const platform = view.getUint8(38);
  const pageSizePower = view.getUint8(39);
  let teamIdentifier: string | null = null;
  let codeLimit = bigFromUint32(codeLimit32);
  let execSegBase: bigint | null = null;
  let execSegLimit: bigint | null = null;
  let execSegFlags: bigint | null = null;
  let runtime: number | null = null;
  const minimumStringOffset = earliestCodeDirectorySize(version);
  const readBlobString = async (stringOffset: number, label: string): Promise<string | null> => {
    if (stringOffset === 0) return null;
    if (stringOffset < minimumStringOffset) {
      issues.push(`CodeDirectory ${label} offset ${stringOffset} points inside the fixed header.`);
      return null;
    }
    if (stringOffset >= parseLength) {
      issues.push(`CodeDirectory ${label} offset points outside the blob.`);
      return null;
    }
    const text = await reader.readZeroTerminatedString(offset + stringOffset, parseLength - stringOffset);
    if (text.length === parseLength - stringOffset) {
      issues.push(`CodeDirectory ${label} is not NUL-terminated within the CodeDirectory blob.`);
    }
    return text;
  };
  // Version gates follow CS_CodeDirectory evolution in xnu/osfmk/kern/cs_blobs.h.
  if (version >= 0x20200 && parseLength < 52) {
    issues.push(`CodeDirectory ${codeDirectoryVersionText(version)} is truncated before the team identifier field.`);
  } else if (version >= 0x20200 && view.byteLength >= 52) {
    const teamOffset = view.getUint32(48, false);
    if (teamOffset > 0) {
      teamIdentifier = await readBlobString(teamOffset, "team identifier");
    }
  }
  if (version >= 0x20300 && parseLength < 64) {
    issues.push(`CodeDirectory ${codeDirectoryVersionText(version)} is truncated before the 64-bit code limit.`);
  } else if (version >= 0x20300 && view.byteLength >= 64) {
    codeLimit = view.getBigUint64(56, false);
  }
  if (version >= 0x20400 && parseLength < 88) {
    issues.push(`CodeDirectory ${codeDirectoryVersionText(version)} is truncated before exec segment fields.`);
  } else if (version >= 0x20400 && view.byteLength >= 88) {
    execSegBase = view.getBigUint64(64, false);
    execSegLimit = view.getBigUint64(72, false);
    execSegFlags = view.getBigUint64(80, false);
  }
  if (version >= 0x20500 && parseLength < 96) {
    issues.push(`CodeDirectory ${codeDirectoryVersionText(version)} is truncated before runtime fields.`);
  } else if (version >= 0x20500 && view.byteLength >= 96) {
    runtime = view.getUint32(88, false);
  }
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
    identifier: await readBlobString(identOffset, "identifier"),
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
  const reader = createRangeReader(file, imageOffset + dataoff, availableSize);
  const headerView = await reader.read(0, 8);
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
  if (headerView.byteLength < 8) {
    issues.push("Code-signing data is too short to contain a blob header.");
    return base;
  }
  base.magic = headerView.getUint32(0, false);
  base.length = headerView.getUint32(4, false);
  if (base.magic !== CSMAGIC_EMBEDDED_SIGNATURE && base.magic !== CSMAGIC_EMBEDDED_SIGNATURE_OLD) {
    issues.push(
      `Code-signing data has unexpected top-level magic ${blobMagicText(base.magic)}; expected an embedded signature superblob.`
    );
    return base;
  }
  const declaredLength = base.length || 0;
  if (declaredLength > availableSize) {
    issues.push("Code-signing superblob length exceeds available data.");
  }
  const superblobLength = Math.min(declaredLength, availableSize);
  const superblobHeader = await reader.read(0, Math.min(superblobLength, CS_SUPERBLOB_HEADER_SIZE));
  if (superblobHeader.byteLength < CS_SUPERBLOB_HEADER_SIZE) {
    issues.push("Code-signing superblob is truncated.");
    return base;
  }
  const blobCount = superblobHeader.getUint32(8, false);
  base.blobCount = blobCount;
  const availableIndexes = Math.floor(
    Math.max(0, superblobLength - CS_SUPERBLOB_HEADER_SIZE) / CS_SUPERBLOB_INDEX_SIZE
  );
  const indexTableSize =
    CS_SUPERBLOB_HEADER_SIZE + Math.min(blobCount, availableIndexes) * CS_SUPERBLOB_INDEX_SIZE;
  if (availableIndexes < blobCount) {
    issues.push(`Code-signing superblob declares ${blobCount} entries but only ${availableIndexes} index records fit.`);
  }
  for (let index = 0; index < Math.min(blobCount, availableIndexes); index += 1) {
    const indexOffset = CS_SUPERBLOB_HEADER_SIZE + index * CS_SUPERBLOB_INDEX_SIZE;
    const indexView = await reader.read(indexOffset, CS_SUPERBLOB_INDEX_SIZE);
    const type = indexView.getUint32(0, false);
    const blobOffset = indexView.getUint32(4, false);
    let magic: number | null = null;
    let length: number | null = null;
    if (blobOffset < indexTableSize) {
      issues.push(`Code-signing blob index ${index} points inside the superblob header or index table.`);
    } else {
      const blobAvailableLength = Math.max(0, superblobLength - blobOffset);
      if (blobAvailableLength >= 8) {
        const blobHeader = await reader.read(blobOffset, 8);
        magic = blobHeader.getUint32(0, false);
        length = blobHeader.getUint32(4, false);
        if (length < 8) {
          issues.push(`Code-signing blob index ${index} declares length ${length} smaller than a blob header.`);
        }
        if (length > blobAvailableLength) {
          issues.push(`Code-signing blob index ${index} exceeds the declared superblob bounds.`);
        }
        if (type === 0 && magic === CSMAGIC_CODEDIRECTORY && length >= 8) {
          base.codeDirectory = await parseCodeDirectory(reader, blobOffset, blobAvailableLength, issues);
        }
      } else {
        issues.push(`Code-signing blob index ${index} points outside available data.`);
      }
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
