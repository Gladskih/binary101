"use strict";

import { bufferToHex } from "../../../binary-utils.js";
import type { PeValveIntegrityBlock } from "../types.js";

const VALVE_BLOCK_HEADER_SIZE = 0x10;
// Valve Steam executables store ASCII VLV\0, three little-endian dwords,
// then a 128-byte RSA signature.
// Source: https://face.0xff.re/posts/patching-steam-binaries/
const VALVE_SIGNATURE_SIZE = 0x80;
const VALVE_BLOCK_SIZE = VALVE_BLOCK_HEADER_SIZE + VALVE_SIGNATURE_SIZE;

const hasValveMagic = (bytes: Uint8Array): boolean =>
  bytes[0] === 0x56 && bytes[1] === 0x4c && bytes[2] === 0x56 && bytes[3] === 0x00;

const readU32 = (view: DataView, offset: number, fieldName: string, warnings: string[]): number | undefined => {
  if (offset + Uint32Array.BYTES_PER_ELEMENT > view.byteLength) {
    warnings.push(`Valve PE integrity block is truncated before ${fieldName}.`);
    return undefined;
  }
  return view.getUint32(offset, true);
};
const isZeroFilled = (bytes: Uint8Array): boolean => bytes.every(byte => byte === 0);

export const parseValveIntegrityBlock = (stubBytesAfterFixedHeader: Uint8Array): PeValveIntegrityBlock | null => {
  if (!hasValveMagic(stubBytesAfterFixedHeader)) return null;
  const warnings: string[] = [];
  if (stubBytesAfterFixedHeader.length < VALVE_BLOCK_SIZE) {
    warnings.push("Valve PE integrity block is truncated before the PE header.");
  }
  const view = new DataView(
    stubBytesAfterFixedHeader.buffer,
    stubBytesAfterFixedHeader.byteOffset,
    stubBytesAfterFixedHeader.byteLength
  );
  const signatureEnd = VALVE_BLOCK_HEADER_SIZE + VALVE_SIGNATURE_SIZE;
  const signatureHex = stubBytesAfterFixedHeader.byteLength >= signatureEnd
    ? bufferToHex(stubBytesAfterFixedHeader.subarray(VALVE_BLOCK_HEADER_SIZE, signatureEnd))
    : undefined;
  const paddingBytes = stubBytesAfterFixedHeader.subarray(
    Math.min(VALVE_BLOCK_SIZE, stubBytesAfterFixedHeader.length)
  );
  const block: PeValveIntegrityBlock = { paddingSize: paddingBytes.length };
  const version = readU32(view, 0x04, "version", warnings);
  const signedDataSize = readU32(view, 0x08, "signed data size", warnings);
  const timestamp = readU32(view, 0x0c, "timestamp", warnings);
  if (version != null) block.version = version;
  if (signedDataSize != null) block.signedDataSize = signedDataSize;
  if (timestamp != null) block.timestamp = timestamp;
  if (signatureHex) block.signatureHex = signatureHex;
  if (paddingBytes.length) block.paddingZeroFilled = isZeroFilled(paddingBytes);
  if (warnings.length) block.warnings = warnings;
  return block;
};
