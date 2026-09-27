"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addVersionPreview } from "../../../../../../analyzers/pe/resources/preview/version.js";

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

void test("addVersionPreview keeps version preview without warning on non-standard VS_FIXEDFILEINFO struct version", () => {
  const expectedVersion = createGeneratedVersion();
  const preview = addVersionPreview(buildVersionResource(0, expectedVersion), "VERSION");

  assert.ok(preview);
  assert.strictEqual(preview.preview?.previewKind, "version");
  assert.deepStrictEqual(preview.preview?.versionInfo?.fixedFileInfo, {
    structVersionRaw: 0,
    structVersionMajor: 0,
    structVersionMinor: 0,
    fileFlagsMask: 0,
    fileFlags: 0,
    fileOS: 0,
    fileType: 0,
    fileSubtype: 0,
    fileDateMS: 0,
    fileDateLS: 0
  });
  assert.strictEqual(preview.preview?.versionInfo?.fileVersionString, expectedVersion.text);
  assert.strictEqual(preview.preview?.versionInfo?.productVersionString, expectedVersion.text);
  assert.deepStrictEqual(preview.issues, undefined);
});

void test("preserves every remaining fixed-info DWORD without applying the mask to raw flags", () => {
  const bytes = buildVersionResource(0x10000, createGeneratedVersion());
  const view = new DataView(bytes.buffer);
  const fields = [0x3f, 0x80000001, 0x40004, 3, 4, 0x12345678, 0xabcdef01];
  const valueStart = bytes.length - 52;
  fields.forEach((value, index) => view.setUint32(valueStart + 24 + index * 4, value, true));

  const info = addVersionPreview(bytes, "VERSION")?.preview?.versionInfo?.fixedFileInfo;

  assert.deepEqual([info?.fileFlagsMask, info?.fileFlags, info?.fileOS, info?.fileType,
    info?.fileSubtype, info?.fileDateMS, info?.fileDateLS], fields);
});

void test("warns for all truncated prefixes and respects typed-array byte offsets", () => {
  const bytes = buildVersionResource(0x10000, createGeneratedVersion());
  for (let length = 0; length < bytes.length; length += 1) {
    assert.ok(addVersionPreview(bytes.subarray(0, length), "VERSION")?.issues?.length);
  }
  const padded = new Uint8Array(bytes.length + 2);
  padded.set(bytes, 2);
  assert.equal(addVersionPreview(padded.subarray(2), "VERSION")?.issues, undefined);
  assert.equal(addVersionPreview(bytes, "other"), null);
});

void test("rejects an invalid fixed-info signature or root key", () => {
  const bytes = buildVersionResource(0x10000, createGeneratedVersion());
  new DataView(bytes.buffer).setUint32(bytes.length - 52, 0, true);
  assert.match(addVersionPreview(bytes, "VERSION")?.issues?.[0] ?? "", /signature/);
  bytes[6] = 0;
  assert.match(addVersionPreview(bytes, "VERSION")?.issues?.[0] ?? "", /key/);
});
