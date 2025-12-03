"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  detectPdfVersion,
  hasZipEocdSignature,
  refineCompoundLabel,
  refineZipLabel,
  toAsciiFromWholeView
} from "../../analyzers/detection-labels.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);

void test("refineZipLabel recognises common derived formats", () => {
  const docx = new TextEncoder().encode("[Content_Types].xml word/document.xml");
  assert.strictEqual(refineZipLabel(dvFrom(docx)), "Microsoft Word document (DOCX)");
  const apk = new TextEncoder().encode("META-INF/MANIFEST.MF AndroidManifest.xml classes.dex");
  assert.strictEqual(refineZipLabel(dvFrom(apk)), "Android application package (APK)");
});

void test("detectPdfVersion reads version prefix", () => {
  const pdf = new TextEncoder().encode("%PDF-1.5 some text");
  assert.strictEqual(detectPdfVersion(dvFrom(pdf)), "1.5");
  const notPdf = new Uint8Array([0x25, 0x50, 0x44, 0x40]);
  assert.strictEqual(detectPdfVersion(dvFrom(notPdf)), null);
});

void test("refineCompoundLabel distinguishes compound file payloads", () => {
  const base = new Uint8Array(128).fill(0);
  const view = new DataView(base.buffer);
  const payload = "WordDocument";
  [...payload].forEach((ch, i) => view.setUint8(i, ch.charCodeAt(0)));
  assert.strictEqual(refineCompoundLabel(view), "Microsoft Word binary document (DOC)");
});

void test("hasZipEocdSignature scans from the end safely", () => {
  const emptyZip = new Uint8Array(22).fill(0);
  const dv = new DataView(emptyZip.buffer);
  dv.setUint32(0, 0x06054b50, true);
  assert.strictEqual(hasZipEocdSignature(dv), true);
  assert.strictEqual(hasZipEocdSignature(new DataView(new Uint8Array(10).buffer)), false);
});

void test("toAsciiFromWholeView stops at requested length", () => {
  const bytes = new TextEncoder().encode("abcdef");
  assert.strictEqual(toAsciiFromWholeView(dvFrom(bytes), 3), "abc");
});
