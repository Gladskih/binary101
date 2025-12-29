"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType, parseForUi } from "../../analyzers/index.js";
import { createPdfFile } from "../fixtures/document-sample-files.js";
import {
  createBmpFile,
  createGifFile,
  createJpegFile,
  createPngWithIhdr,
  createWebpFile
} from "../fixtures/image-sample-files.js";
import { createLnkFile } from "../fixtures/lnk-sample-file.js";
import { createFlacFile } from "../fixtures/flac-fixtures.js";
import { createRar5File, createSevenZipFile } from "../fixtures/rar-sevenzip-fixtures.js";
import { createDosMzExe } from "../fixtures/dos-sample-file.js";
import { createTarFile } from "../fixtures/tar-fixtures.js";
import { createWebmFile } from "../fixtures/webm-base-fixtures.js";
import { createMkvFile } from "../fixtures/mkv-base-fixtures.js";
import { createAniFile, createAviFile, createWavFile } from "../fixtures/riff-sample-files.js";
import { MockFile } from "../helpers/mock-file.js";

const textEncoder = new TextEncoder();

void test("detectBinaryType recognizes common binary formats", async () => {
  const detections = await Promise.all([
    detectBinaryType(createPngWithIhdr()),
    detectBinaryType(createGifFile()),
    detectBinaryType(createJpegFile()),
    detectBinaryType(createWebpFile()),
    detectBinaryType(createPdfFile()),
    detectBinaryType(createTarFile()),
    detectBinaryType(createSevenZipFile()),
    detectBinaryType(createRar5File()),
    detectBinaryType(createLnkFile()),
    detectBinaryType(createWebmFile()),
    detectBinaryType(createWavFile()),
    detectBinaryType(createAviFile()),
    detectBinaryType(createAniFile()),
    detectBinaryType(new MockFile(textEncoder.encode("plain text sample"), "note.txt", "text/plain")),
    detectBinaryType(createFlacFile()),
    detectBinaryType(createBmpFile()),
    detectBinaryType(createMkvFile())
  ]);

  assert.match(detections[0], /^PNG image/);
  assert.match(detections[1], /^GIF image/);
  assert.match(detections[2], /^JPEG image/);
  assert.match(detections[3], /^WebP image/);
  assert.match(detections[4], /^PDF document/);
  assert.match(detections[5], /tar archive/i);
  assert.match(detections[6], /^7z archive v0\.4/);
  assert.match(detections[7], /^RAR archive/);
  assert.strictEqual(detections[8], "Windows shortcut (.lnk)");
  assert.match(detections[9], /^WebM/);
  assert.match(detections[10], /^WAVE audio/);
  assert.match(detections[11], /^AVI\/DivX video/);
  assert.match(detections[12], /animated cursor/i);
  assert.strictEqual(detections[13], "Text file");
  assert.match(detections[14], /^FLAC audio/);
  assert.match(detections[15], /^BMP bitmap image/);
  assert.match(detections[16], /^Matroska/);
});

void test("detectBinaryType distinguishes DOS MZ executables from PE", async () => {
  const mzFile = createDosMzExe();
  const detection = await detectBinaryType(mzFile);
  assert.strictEqual(detection, "MS-DOS MZ executable");
  const parsed = await parseForUi(mzFile);
  assert.strictEqual(parsed.analyzer, "mz");
  assert.ok(parsed.parsed);
  assert.strictEqual(parsed.parsed.header.e_magic, "MZ");
  assert.ok(Array.isArray(parsed.parsed.stubStrings));
  assert.ok(parsed.parsed.stubStrings.length >= 1);
});

