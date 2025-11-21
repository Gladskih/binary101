"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType } from "../../analyzers/index.js";
import { MockFile } from "../helpers/mock-file.mjs";

const fromAscii = text => new Uint8Array(Buffer.from(text, "ascii"));

test("detectBinaryType refines ZIP-based document labels", async () => {
  const zipSignature = [0x50, 0x4b, 0x03, 0x04];
  const docxPayload = "[Content_Types].xml word/document.xml";
  const bytes = new Uint8Array(zipSignature.length + docxPayload.length);
  bytes.set(zipSignature, 0);
  bytes.set(fromAscii(docxPayload), zipSignature.length);
  const label = await detectBinaryType(new MockFile(bytes, "docx-like.zip", "application/zip"));
  assert.strictEqual(label, "Microsoft Word document (DOCX)");

  const apkPayload = "[Content_Types].xml META-INF/MANIFEST.MF AndroidManifest.xml classes.dex";
  const apkBytes = new Uint8Array(zipSignature.length + apkPayload.length);
  apkBytes.set(zipSignature, 0);
  apkBytes.set(fromAscii(apkPayload), zipSignature.length);
  const apkLabel = await detectBinaryType(new MockFile(apkBytes, "sample.apk", "application/zip"));
  assert.strictEqual(apkLabel, "Android application package (APK)");
});

test("detectBinaryType refines Compound File formats", async () => {
  const compoundMagic = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  const workbook = "Workbook";
  const bytes = new Uint8Array(compoundMagic.length + workbook.length);
  bytes.set(compoundMagic, 0);
  bytes.set(fromAscii(workbook), compoundMagic.length);
  const label = await detectBinaryType(new MockFile(bytes, "sample.xls", "application/octet-stream"));
  assert.strictEqual(label, "Microsoft Excel binary workbook (XLS)");
});

test("detectBinaryType reports EOCD-only ZIPs and PDF versions", async () => {
  const eocd = new Uint8Array(32).fill(0);
  eocd.set([0x50, 0x4b, 0x05, 0x06], eocd.length - 22);
  const zipLabel = await detectBinaryType(new MockFile(eocd, "eocd.zip", "application/zip"));
  assert.strictEqual(zipLabel, "ZIP archive");

  const pdfBytes = Buffer.from("%PDF-1.5\n", "ascii");
  const pdfLabel = await detectBinaryType(new MockFile(new Uint8Array(pdfBytes), "v15.pdf", "application/pdf"));
  assert.strictEqual(pdfLabel, "PDF document (v1.5)");
});
