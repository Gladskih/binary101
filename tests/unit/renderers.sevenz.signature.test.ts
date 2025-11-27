"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSignatureLayout } from "../../renderers/sevenz/signature.js";

void test("signature section renders header map when startHeader is present", () => {
  const out: string[] = [];
  const sevenZip = {
    is7z: true,
    startHeader: {
      versionMajor: 0,
      versionMinor: 4,
      startHeaderCrc: 0x12345678,
      nextHeaderOffset: 0x20n,
      nextHeaderSize: 0x100n,
      nextHeaderCrc: 0x89abcdef,
      absoluteNextHeaderOffset: 0x1234n
    },
    issues: [] as string[]
  };

  renderSignatureLayout(sevenZip, out);
  const html = out.join("");
  assert.match(html, /Signature header map/);
  assert.match(html, /StartHeaderCRC/);
  assert.match(html, /NextHeaderOffset/);
  assert.match(html, /NextHeaderSize/);
});

void test("signature section renders sensible zero values", () => {
  const out: string[] = [];
  const sevenZip = {
    is7z: true,
    startHeader: {
      versionMajor: 0,
      versionMinor: 4,
      startHeaderCrc: 0,
      nextHeaderOffset: 0n,
      nextHeaderSize: 0n,
      nextHeaderCrc: 0,
      absoluteNextHeaderOffset: 0n
    },
    issues: [] as string[]
  };

  renderSignatureLayout(sevenZip, out);
  const html = out.join("");
  // Offsets should be rendered as zero hex.
  assert.match(html, /0x00000000/);
  // Sizes should be rendered via the value formatter.
  assert.match(html, /0 B \(0 bytes\)/);
});

void test("signature section does not render when startHeader is missing", () => {
  const out: string[] = [];
  const sevenZip = { is7z: true, issues: [] as string[] };
  renderSignatureLayout(sevenZip, out);
  assert.strictEqual(out.length, 0);
});
