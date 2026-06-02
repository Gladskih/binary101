"use strict";

// Wine's GetFileMUIInfo source models the fixed MUI resource header as 132 bytes.
export const MUI_RESOURCE_HEADER_SIZE = 132;
// Microsoft Resource Utilities print RC Config Version 10000 for current MUI resource data.
export const MUI_RESOURCE_VERSION = 0x00010000;
// MUIRCT output prints FileType 12 for language-specific .mui resource files.
export const LANGUAGE_SPECIFIC_MUI_FILE_TYPE = 0x12;

const alignDword = (value: number): number => (value + 3) & ~3;

const encodeUtf16MultiString = (values: string[]): Uint8Array => {
  const text = `${values.join("\0")}\0`;
  const bytes = new Uint8Array(text.length * Uint16Array.BYTES_PER_ELEMENT);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < text.length; index += 1) {
    view.setUint16(index * Uint16Array.BYTES_PER_ELEMENT, text.charCodeAt(index), true);
  }
  return bytes;
};

const encodeUint32Array = (values: number[]): Uint8Array => {
  const bytes = new Uint8Array(values.length * Uint32Array.BYTES_PER_ELEMENT);
  const view = new DataView(bytes.buffer);
  values.forEach((value, index) => view.setUint32(index * Uint32Array.BYTES_PER_ELEMENT, value, true));
  return bytes;
};

const appendRange = (
  output: Uint8Array,
  fieldOffset: number,
  cursor: number,
  payload: Uint8Array
): number => {
  const view = new DataView(output.buffer);
  output.set(payload, cursor);
  view.setUint32(fieldOffset, cursor, true);
  view.setUint32(fieldOffset + Uint32Array.BYTES_PER_ELEMENT, payload.byteLength, true);
  return alignDword(cursor + payload.byteLength);
};

export const buildMuiResourceConfigurationFixture = (): Uint8Array => {
  const output = new Uint8Array(256).fill(0);
  const view = new DataView(output.buffer);
  let cursor = MUI_RESOURCE_HEADER_SIZE;
  // Microsoft Resource Utilities print MUIRCT Signature fecdfecd.
  view.setUint32(0, 0xfecdfecd, true);
  view.setUint32(8, MUI_RESOURCE_VERSION, true);
  view.setUint32(16, LANGUAGE_SPECIFIC_MUI_FILE_TYPE, true);
  // Service Checksum and Checksum are 16-byte fields in the MUI resource header.
  output.set(Array.from({ length: 16 }, (_, index) => index + 1), 28);
  output.set(Array.from({ length: 16 }, (_, index) => 0xa0 + index), 44);
  // Fixed-header range offsets follow the MUI resource layout used by GetFileMUIInfo.
  cursor = appendRange(output, 68, cursor, encodeUtf16MultiString(["en-US\\fixture.dll.mui"]));
  cursor = appendRange(output, 84, cursor, encodeUtf16MultiString(["MUI"]));
  cursor = appendRange(output, 92, cursor, encodeUint32Array([24]));
  cursor = appendRange(output, 108, cursor, encodeUint32Array([16]));
  cursor = appendRange(output, 116, cursor, encodeUtf16MultiString(["en-US"]));
  view.setUint32(4, cursor, true);
  return output.subarray(0, cursor);
};
