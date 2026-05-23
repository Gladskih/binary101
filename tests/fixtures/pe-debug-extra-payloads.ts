"use strict";

import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();
// Microsoft PE/COFF stores IMAGE_DEBUG_DIRECTORY payload pointers as file offsets
// or RVAs; these fixtures keep RVA and file offset identical so parser tests can
// focus on payload semantics.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only
export const EXTRA_DEBUG_PAYLOAD_OFFSET = 8;
export const identityRvaToOff = (value: number): number => value;

export const createExtraDebugPayloadSubject = (
  payload: Uint8Array,
  declaredSize = payload.length
): { file: MockFile; offset: number; declaredSize: number } => {
  const bytes = new Uint8Array(EXTRA_DEBUG_PAYLOAD_OFFSET + payload.length);
  bytes.set(payload, EXTRA_DEBUG_PAYLOAD_OFFSET);
  return {
    file: new MockFile(bytes, "extra-debug-payload.bin"),
    offset: EXTRA_DEBUG_PAYLOAD_OFFSET,
    declaredSize
  };
};

export const encodeNullTerminatedAscii = (value: string): Uint8Array =>
  encoder.encode(`${value}\0`);

export const writeU32 = (bytes: Uint8Array, offset: number, value: number): void => {
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(offset, value, true);
};
