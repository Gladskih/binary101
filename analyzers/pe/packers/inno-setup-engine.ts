"use strict";

import { crc32 } from "../../crc32.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import { decompressLzmaWithProperties } from "../../sevenz/lzma.js";
import { SEVENZIP_LZMA_PROPERTY_BYTES } from "../../sevenz/method-ids.js";
import type { PeInnoSetupFinding } from "./types.js";

// Legacy Inno blocks use CRC32 + UInt32 StoredSize + one-byte Compressed,
// followed by CRC32-prefixed 4096-byte chunks.
// https://github.com/dscharrer/innoextract/blob/master/src/stream/block.cpp
const BLOCK_HEADER_BYTES = 9;
const BLOCK_DATA_BYTES = 4096;
const BLOCK_CHUNK_BYTES = Uint32Array.BYTES_PER_ELEMENT + BLOCK_DATA_BYTES;
const MAX_PACKED_SETUP_ENGINE_BYTES = 64 * 1024 * 1024;
const DOS_SIGNATURE = 0x5a4d;
const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_SIGNATURE = 0x50450000;

const decodeCallInstructions = (bytes: Uint8Array): void => {
  // Exact inverse of Inno Setup's TransformCallInstructions(..., False, 0).
  // https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Compression.Base.pas
  for (let index = 0; index < bytes.byteLength - 4;) {
    if (bytes[index] !== 0xe8 && bytes[index] !== 0xe9) {
      index += 1;
      continue;
    }
    index += 1;
    if (bytes[index + 3] === 0 || bytes[index + 3] === 0xff) {
      const address = (index + 4) & 0xffffff;
      let relative = (
        (bytes[index] ?? 0) |
        ((bytes[index + 1] ?? 0) << 8) |
        ((bytes[index + 2] ?? 0) << 16)
      ) >>> 0;
      relative = (relative - address) >>> 0;
      if ((relative & 0x800000) !== 0) bytes[index + 3] = (~(bytes[index + 3] ?? 0)) & 0xff;
      bytes[index] = relative & 0xff;
      bytes[index + 1] = (relative >>> 8) & 0xff;
      bytes[index + 2] = (relative >>> 16) & 0xff;
    }
    index += 4;
  }
};

const readPackedStream = async (
  reader: FileRangeReader,
  finding: PeInnoSetupFinding
): Promise<Uint8Array> => {
  const chunkCount = Math.ceil(finding.setupExeStoredSize / BLOCK_CHUNK_BYTES);
  const packedSize = finding.setupExeStoredSize - chunkCount * Uint32Array.BYTES_PER_ELEMENT;
  if (packedSize <= 0) throw new Error("Inno Setup compressed block contains no LZMA data.");
  const packed = new Uint8Array(packedSize);
  let outputOffset = 0;
  let cursor = finding.setupExeOffset + BLOCK_HEADER_BYTES;
  let remaining = finding.setupExeStoredSize;
  while (remaining > 0) {
    if (remaining < Uint32Array.BYTES_PER_ELEMENT + 1) {
      throw new Error("Inno Setup compressed block has a truncated chunk.");
    }
    const dataSize = Math.min(BLOCK_DATA_BYTES, remaining - Uint32Array.BYTES_PER_ELEMENT);
    const chunk = await reader.read(cursor, Uint32Array.BYTES_PER_ELEMENT + dataSize);
    if (chunk.byteLength !== Uint32Array.BYTES_PER_ELEMENT + dataSize) {
      throw new Error("Inno Setup compressed block extends past its validated bounds.");
    }
    const bytes = new Uint8Array(chunk.buffer, chunk.byteOffset + 4, dataSize);
    if (crc32(bytes) !== chunk.getUint32(0, true)) {
      throw new Error("Inno Setup compressed chunk CRC-32 does not match.");
    }
    if (outputOffset > packed.byteLength - dataSize) {
      throw new Error("Inno Setup compressed block size is invalid.");
    }
    packed.set(bytes, outputOffset);
    outputOffset += dataSize;
    cursor += chunk.byteLength;
    remaining -= chunk.byteLength;
  }
  if (outputOffset !== packed.byteLength) throw new Error("Inno Setup compressed block size is invalid.");
  return packed;
};

const validateBlockHeader = async (
  reader: FileRangeReader,
  finding: PeInnoSetupFinding
): Promise<void> => {
  const header = await reader.read(finding.setupExeOffset, BLOCK_HEADER_BYTES);
  if (header.byteLength !== BLOCK_HEADER_BYTES) throw new Error("Inno Setup block header is truncated.");
  const headerBytes = new Uint8Array(header.buffer, header.byteOffset + 4, 5);
  if (crc32(headerBytes) !== header.getUint32(0, true)) {
    throw new Error("Inno Setup block header CRC-32 does not match.");
  }
  if (header.getUint32(4, true) !== finding.setupExeStoredSize || header.getUint8(8) !== 1) {
    throw new Error("Inno Setup block header no longer matches the parsed model.");
  }
};

const hasPeSignature = (bytes: Uint8Array): boolean => {
  if (bytes.byteLength < 0x40) return false;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(0, true) !== DOS_SIGNATURE) return false;
  const peOffset = view.getUint32(DOS_E_LFANEW_OFFSET, true);
  return peOffset >= 0x40 && peOffset <= bytes.byteLength - 4 &&
    view.getUint32(peOffset, false) === PE_SIGNATURE;
};

export const extractInnoSetupEngine = async (
  reader: FileRangeReader,
  finding: PeInnoSetupFinding
): Promise<Uint8Array> => {
  if (finding.setupExeStoredSize > MAX_PACKED_SETUP_ENGINE_BYTES) {
    throw new Error("Inno Setup embedded engine exceeds the browser decode limit.");
  }
  await validateBlockHeader(reader, finding);
  const packed = await readPackedStream(reader, finding);
  if (packed.byteLength < SEVENZIP_LZMA_PROPERTY_BYTES) {
    throw new Error("Inno Setup LZMA stream is truncated.");
  }
  const bytes = await decompressLzmaWithProperties(
    [...packed.subarray(0, SEVENZIP_LZMA_PROPERTY_BYTES)],
    packed.subarray(SEVENZIP_LZMA_PROPERTY_BYTES),
    BigInt(finding.setupExeUnpackedSize)
  );
  if (bytes.byteLength !== finding.setupExeUnpackedSize) {
    throw new Error("Inno Setup embedded engine size does not match the offset table.");
  }
  decodeCallInstructions(bytes);
  if (crc32(bytes) !== finding.setupExeCrc32) {
    throw new Error("Inno Setup embedded engine CRC-32 does not match the offset table.");
  }
  if (!hasPeSignature(bytes)) throw new Error("Inno Setup embedded engine is not a valid PE image.");
  return bytes;
};
