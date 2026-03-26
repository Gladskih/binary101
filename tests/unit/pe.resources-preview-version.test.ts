"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addVersionPreview } from "../../analyzers/pe/resources-preview-version.js";

const DWORD_SIZE = Uint32Array.BYTES_PER_ELEMENT;
const alignDword = (offset: number): number => (offset + DWORD_SIZE - 1) & ~(DWORD_SIZE - 1);

const writeUtf16 = (bytes: Uint8Array, offset: number, text: string): void => {
  for (let index = 0; index < text.length; index += 1) {
    const codeUnit = text.charCodeAt(index);
    bytes[offset + index * 2] = codeUnit & 0xff;
    bytes[offset + index * 2 + 1] = codeUnit >>> 8;
  }
};

const writeVersionPair = (
  view: DataView,
  offset: number,
  major: number,
  minor: number,
  build: number,
  patch: number
): void => {
  view.setUint32(offset, (major << 16) | minor, true);
  view.setUint32(offset + DWORD_SIZE, (build << 16) | patch, true);
};

const createGeneratedVersionPart = (zeroBasedIndex: number): number => zeroBasedIndex + 1;

const createGeneratedVersion = (): {
  major: number;
  minor: number;
  build: number;
  patch: number;
  text: string;
} => {
  const major = createGeneratedVersionPart(0);
  const minor = createGeneratedVersionPart(1);
  const build = createGeneratedVersionPart(2);
  const patch = createGeneratedVersionPart(3);
  return {
    major,
    minor,
    build,
    patch,
    text: `${major}.${minor}.${build}.${patch}`
  };
};

const buildVersionResource = (
  structVersion: number,
  version: { major: number; minor: number; build: number; patch: number }
): Uint8Array => {
  const key = "VS_VERSION_INFO";
  // sizeof(VS_FIXEDFILEINFO) is 13 DWORDs = 52 bytes.
  // Source: https://learn.microsoft.com/en-us/windows/win32/menurc/vs-fixedfileinfo
  const fixedFileInfoSize = 13 * DWORD_SIZE;
  // VS_VERSIONINFO begins with three WORD fields (wLength, wValueLength, wType),
  // followed by the UTF-16 key and its terminating NUL before the DWORD-aligned value.
  const valueStart = alignDword(Uint16Array.BYTES_PER_ELEMENT * (3 + key.length + 1));
  const bytes = new Uint8Array(valueStart + fixedFileInfoSize).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, bytes.length, true);
  view.setUint16(2, fixedFileInfoSize, true);
  writeUtf16(bytes, Uint16Array.BYTES_PER_ELEMENT * 3, key);
  // VS_FIXEDFILEINFO.dwSignature is fixed at 0xFEEF04BD.
  // Source: https://learn.microsoft.com/en-us/windows/win32/menurc/vs-fixedfileinfo
  view.setUint32(valueStart, 0xfeef04bd, true);
  view.setUint32(valueStart + DWORD_SIZE, structVersion, true);
  writeVersionPair(view, valueStart + DWORD_SIZE * 2, version.major, version.minor, version.build, version.patch);
  writeVersionPair(view, valueStart + DWORD_SIZE * 4, version.major, version.minor, version.build, version.patch);
  return bytes;
};

void test("addVersionPreview keeps version preview when VS_FIXEDFILEINFO struct version is non-standard", () => {
  const expectedVersion = createGeneratedVersion();
  const preview = addVersionPreview(buildVersionResource(0, expectedVersion), "VERSION");

  assert.ok(preview);
  assert.strictEqual(preview.preview?.previewKind, "version");
  assert.strictEqual(preview.preview?.versionInfo?.fileVersionString, expectedVersion.text);
  assert.strictEqual(preview.preview?.versionInfo?.productVersionString, expectedVersion.text);
  assert.ok((preview.issues || []).some(issue => /struct version is unexpected/i.test(issue)));
});
