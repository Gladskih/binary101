"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateRawSync } from "node:zlib";
import { extractZipEntry } from "../../../../scripts/winapi-metadata/zip-entry.js";

const encoder = new TextEncoder();

const writeU16 = (bytes: number[], value: number): void => {
  bytes.push(value & 0xff, (value >>> 8) & 0xff);
};

const writeU32 = (bytes: number[], value: number): void => {
  bytes.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
};

const writeBytes = (bytes: number[], values: Uint8Array): void => {
  values.forEach(value => bytes.push(value));
};

const createZip = (entryName: string, payload: string, method: 0 | 8): Uint8Array => {
  const nameBytes = encoder.encode(entryName);
  const payloadBytes = encoder.encode(payload);
  const compressedBytes = method === 8 ? deflateRawSync(payloadBytes) : payloadBytes;
  const bytes: number[] = [];
  const localHeaderOffset = bytes.length;
  writeU32(bytes, 0x04034b50);
  writeU16(bytes, 20);
  writeU16(bytes, 0x0800);
  writeU16(bytes, method);
  writeU32(bytes, 0);
  writeU32(bytes, 0);
  writeU32(bytes, compressedBytes.length);
  writeU32(bytes, payloadBytes.length);
  writeU16(bytes, nameBytes.length);
  writeU16(bytes, 0);
  writeBytes(bytes, nameBytes);
  writeBytes(bytes, compressedBytes);
  const centralDirectoryOffset = bytes.length;
  writeU32(bytes, 0x02014b50);
  writeU16(bytes, 20);
  writeU16(bytes, 20);
  writeU16(bytes, 0x0800);
  writeU16(bytes, method);
  writeU32(bytes, 0);
  writeU32(bytes, 0);
  writeU32(bytes, compressedBytes.length);
  writeU32(bytes, payloadBytes.length);
  writeU16(bytes, nameBytes.length);
  writeU16(bytes, 0);
  writeU16(bytes, 0);
  writeU16(bytes, 0);
  writeU16(bytes, 0);
  writeU32(bytes, 0);
  writeU32(bytes, localHeaderOffset);
  writeBytes(bytes, nameBytes);
  const centralDirectorySize = bytes.length - centralDirectoryOffset;
  writeU32(bytes, 0x06054b50);
  writeU16(bytes, 0);
  writeU16(bytes, 0);
  writeU16(bytes, 1);
  writeU16(bytes, 1);
  writeU32(bytes, centralDirectorySize);
  writeU32(bytes, centralDirectoryOffset);
  writeU16(bytes, 0);
  return Uint8Array.from(bytes);
};

void test("extractZipEntry reads deflated and stored entries by exact path", () => {
  assert.equal(
    new TextDecoder().decode(extractZipEntry(createZip("Windows.Win32.winmd", "deflated", 8), "Windows.Win32.winmd")),
    "deflated"
  );
  assert.equal(
    new TextDecoder().decode(extractZipEntry(createZip("stored.txt", "stored", 0), "stored.txt")),
    "stored"
  );
});

void test("extractZipEntry reports missing ZIP structures", () => {
  assert.throws(() => extractZipEntry(Uint8Array.of(1, 2, 3), "Windows.Win32.winmd"), /not found/i);
});
