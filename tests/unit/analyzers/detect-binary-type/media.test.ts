"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType } from "../../../../analyzers/index.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createMp3File } from "../../../fixtures/audio-sample-files.js";
import { createMp4File } from "../../../fixtures/mp4-fixtures.js";
import { createMinimalJavaClassBytes } from "../../../fixtures/java-class-fixtures.js";
import {
  createMachOFile,
  createMachOUniversalFile,
  createTruncatedFatMachOBytes
} from "../../../fixtures/macho-fixtures.js";
import { createWebmFile } from "../../../fixtures/webm-base-fixtures.js";
import { createFlacFile } from "../../../fixtures/flac-fixtures.js";
import { createSampleAsfFile } from "../../../fixtures/asf-fixtures.js";
import { createSliceTrackingFile } from "../../../helpers/slice-tracking-file.js";

void test("detectBinaryType recognises ELF and Mach-O executables", async () => {
  const elf = new Uint8Array(0x20).fill(0);
  elf.set([0x7f, 0x45, 0x4c, 0x46], 0);
  elf[4] = 2;
  elf[5] = 1;
  const elfView = new DataView(elf.buffer);
  elfView.setUint16(0x10, 2, true);
  elfView.setUint16(0x12, 0x3e, true);
  const elfLabel = await detectBinaryType(new MockFile(elf, "elf.bin", "application/octet-stream"));
  assert.strictEqual(elfLabel, "ELF 64-bit LSB executable, x86-64");
  const macho64 = new Uint8Array([0xcf, 0xfa, 0xed, 0xfe]);
  const machoLabel = await detectBinaryType(new MockFile(macho64, "macho", "application/octet-stream"));
  assert.strictEqual(machoLabel, "Mach-O 64-bit");
});

void test("detectBinaryType recognises real Mach-O fixtures", async () => {
  const thinLabel = await detectBinaryType(createMachOFile());
  assert.strictEqual(thinLabel, "Mach-O 64-bit");
  const fatLabel = await detectBinaryType(createMachOUniversalFile());
  assert.strictEqual(fatLabel, "Mach-O universal (Fat)");
});

void test("detectBinaryType keeps truncated fat wrappers visible", async () => {
  const label = await detectBinaryType(new MockFile(createTruncatedFatMachOBytes()));
  assert.strictEqual(label, "Mach-O universal (Fat, truncated)");
});

void test("detectBinaryType does not route Java class files through Mach-O detection", async () => {
  const label = await detectBinaryType(new MockFile(createMinimalJavaClassBytes()));
  assert.strictEqual(label, "Java class file");
});

void test("detectBinaryType rejects MPEG frames embedded after unrelated bytes", async () => {
  const base = createMp3File();
  const prefixed = new Uint8Array(base.data.length + 16);
  prefixed.set(base.data, 16);
  const label = await detectBinaryType(new MockFile(prefixed, "prefixed.bin"));
  assert.strictEqual(label, "Unknown binary type");
});

void test("detectBinaryType reports Matroska/WebM by container signature", async () => {
  const label = await detectBinaryType(createWebmFile());
  assert.strictEqual(label, "Matroska/WebM container");
});

void test("detectBinaryType reports MP4 by ISO-BMFF signature", async () => {
  const label = await detectBinaryType(createMp4File());
  assert.strictEqual(label, "MP4/QuickTime container (ISO-BMFF)");
});

void test("detectBinaryType reports AVIF by ISO-BMFF brand", async () => {
  const bytes = new Uint8Array(12);
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 0x66747970, false);
  view.setUint32(8, 0x61766966, false);
  const label = await detectBinaryType(new MockFile(bytes, "sample.avif", "image/avif"));
  assert.strictEqual(label, "AVIF image (AV1 Image File Format, ISO-BMFF)");
});

void test("detectBinaryType reports ASF by GUID without parsing streams", async () => {
  const label = await detectBinaryType(createSampleAsfFile());
  assert.strictEqual(label, "ASF container (WMA/WMV)");
});

void test("detectBinaryType reports MP3 for minimal single-frame files", async () => {
  const full = createMp3File();
  const singleFrame = full.data.slice(0, full.data.length / 2);
  const label = await detectBinaryType(new MockFile(singleFrame, "single-frame.mp3", "audio/mpeg"));
  assert.strictEqual(label, "MPEG audio stream (MP3/AAC)");
});

void test("detectBinaryType reports FLAC by stream marker without metadata parsing", async () => {
  const label = await detectBinaryType(createFlacFile());
  assert.strictEqual(label, "FLAC audio");
});

void test("detectBinaryType does not mislabel MPEG Program Stream as MP3", async () => {
  const bytes = new Uint8Array(64).fill(0);
  bytes.set([0x00, 0x00, 0x01, 0xba]);
  const label = await detectBinaryType(new MockFile(bytes, "sample.mpg", "video/mpeg"));
  assert.strictEqual(label, "MPEG Program Stream (MPG)");
});

void test("detectBinaryType rejects damaged single-frame MPEG-like streams", async () => {
  const full = createMp3File();
  const firstFrameLength = full.data.length / 2;
  const damaged = new Uint8Array(firstFrameLength + 16);
  damaged.set(full.data.slice(0, firstFrameLength), 0);
  damaged.fill(0, firstFrameLength);
  const label = await detectBinaryType(new MockFile(damaged, "damaged.mp3", "audio/mpeg"));
  assert.strictEqual(label, "Unknown binary type");
});

void test("detectBinaryType avoids full media parsing during signature detection", async () => {
  const sample = createMp4File();
  const tracked = createSliceTrackingFile(sample.data, sample.size, sample.name);
  const label = await detectBinaryType(tracked.file);
  assert.equal(label, "MP4/QuickTime container (ISO-BMFF)");
  assert.deepEqual(tracked.requests, [sample.size]);
});
