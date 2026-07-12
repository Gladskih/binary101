"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeUpxPackerFinding } from "../../../../analyzers/pe/packers/index.js";
import {
  renderUpxFindingDetails,
  upxFilterLabel
} from "../../../../renderers/pe/upx-packer.js";

const createFinding = (): PeUpxPackerFinding => ({
  id: "upx",
  name: "UPX executable packer",
  kind: "executable-packer",
  confidence: "high",
  evidence: ["verified"],
  packedFileSize: 1024,
  packHeaderOffset: 0x1ed,
  packHeader: {
    version: 13,
    format: 9,
    method: 14,
    level: 10,
    unpackedAdler32: 1,
    packedAdler32: 2,
    unpackedSize: 16_866,
    packedSize: 296,
    originalFileSize: 3072,
    filter: 0x26,
    filterParameter: 0,
    filterMru: 0,
    headerSize: 32,
    headerChecksum: 3
  }
});

const rowValue = (html: string, field: string): string =>
  html.match(new RegExp(
    `<th scope="row" class="peUpxTable__field">${field}</th><td[^>]*>([\\s\\S]*?)</td>`
  ))?.[1] ?? "";

void test("renderUpxFindingDetails separates offsets and explains UPX size domains", () => {
  const html = renderUpxFindingDetails(createFinding());

  assert.ok(html.includes(`class="table peUpxTable pePackerFinding__details"`));
  assert.ok(html.includes(`<thead><tr><th>Field</th><th>Value</th><th>Meaning</th></tr></thead>`));
  assert.ok(html.includes(`class="peUpxTable__field">PackHeader offset</th>`));
  assert.ok(html.includes("Packed data start"));
  assert.ok(html.includes("0x0000020d"));
  assert.ok(html.includes("Packed data end"));
  assert.ok(html.includes("0x00000335"));
  assert.doesNotMatch(html, /0x0000020d-0x00000335/);
  assert.ok(html.includes("296 bytes"));
  assert.ok(html.includes(`<td class="peNumeric">296 bytes</td>`));
  assert.ok(html.includes("16.5 KB (16866 bytes)"));
  assert.ok(html.includes("3 KB (3072 bytes)"));
  assert.ok(html.includes("in-memory PE image block"));
});

void test("renderUpxFindingDetails shows all methods as chips and selects the declared method", () => {
  const html = rowValue(renderUpxFindingDetails(createFinding()), "Compression");

  assert.deepEqual(
    Array.from(html.matchAll(/class="opt (?:sel|dim)"[^>]*>([^<]+)<\/span>/g), match => match[1]),
    [
      "NRV2B LE32", "NRV2B 8-bit", "NRV2B LE16",
      "NRV2D LE32", "NRV2D 8-bit", "NRV2D LE16",
      "NRV2E LE32", "NRV2E 8-bit", "NRV2E LE16", "LZMA"
    ]
  );
  assert.match(html, /class="opt sel"[^>]*>LZMA<\/span>/);
});

void test("renderUpxFindingDetails reports whole-file compression and the named filter", () => {
  const html = renderUpxFindingDetails(createFinding());

  assert.ok(html.includes("Packed file size"));
  assert.ok(html.includes("File compression ratio"));
  assert.ok(html.includes("33.3% (66.7% smaller)"));
  assert.doesNotMatch(html, /Payload ratio/);
  assert.ok(html.includes("0x26 — x86 E8/E9 CTO transform (LE byte swap)"));
  assert.ok(html.includes("Call-trick offset selected by UPX"));
});

void test("renderUpxFindingDetails gives compression level its scale", () => {
  const html = renderUpxFindingDetails(createFinding());

  assert.ok(html.includes(`<td class="peNumeric">10 / 10 (--best)</td>`));
  assert.ok(html.includes("UPX packing-time effort preset"));
});

void test("renderUpxFindingDetails shows numbered CLI levels below best", () => {
  const finding = createFinding();
  finding.packHeader.level = 7;

  assert.ok(renderUpxFindingDetails(finding).includes(`7 / 10 (-7)`));
});

void test("renderUpxFindingDetails keeps every field meaning visible", () => {
  const html = renderUpxFindingDetails(createFinding());
  assert.deepEqual(
    Array.from(
      html.matchAll(/<th scope="row" class="peUpxTable__field">([^<]+)<\/th>/g),
      match => match[1]
    ),
    [
      "PackHeader offset", "Packed data start", "Packed data end", "UPX format",
      "UPX version", "Compression", "Compression level", "Packed block size",
      "Unpacked block size", "Packed file size", "Original file size",
      "File compression ratio", "Filter", "Filter CTO"
    ]
  );
  const expected = [
    "File offset of the validated UPX PackHeader.",
    "First compressed payload byte, immediately after PackHeader.",
    "Exclusive end offset of the compressed payload.",
    "Executable-format identifier recorded in PackHeader; the active chip is validated.",
    "PackHeader format-version byte, not the UPX release number.",
    "Declared method; the selected chip is the method that successfully decoded the payload.",
    "UPX packing-time effort preset; level 10 corresponds to --best and may be slow.",
    "Compressed payload bytes covered by the packed Adler-32.",
    "Decompressed in-memory PE image block; virtual layout and UPX reconstruction data are included.",
    "Complete analyzed file, including the UPX loader, PE headers, and any trailing data.",
    "Size of the input PE file on disk before UPX packing.",
    "Current packed file size divided by original file size; this is UPX's whole-file ratio.",
    "Reversible executable-code preprocessing applied before compression.",
    "Call-trick offset selected by UPX for the executable filter."
  ];

  assert.deepEqual(expected.filter(text => html.includes(text)), expected);
  assert.equal(html.match(/<td class="peNumeric">/g)?.length, 11);
  assert.ok(html.includes(
    `<th scope="row" class="peUpxTable__field">Filter</th>` +
    `<td>0x26 — x86 E8/E9 CTO transform (LE byte swap)</td>`
  ));
  assert.ok(html.includes(
    `<th scope="row" class="peUpxTable__field">Filter CTO</th>` +
    `<td class="peNumeric">0 (0x00)</td>`
  ));
  assert.ok(html.endsWith(`</tbody></table></div>`));
});

void test("renderUpxFindingDetails names every supported PE format", () => {
  assert.deepEqual([9, 21, 36, 43, 44].map(format => {
    const finding = createFinding();
    finding.packHeader.format = format;
    return rowValue(renderUpxFindingDetails(finding), "UPX format")
      .match(/class="opt sel"[^>]*>([^<]+)<\/span>/)?.[1];
  }), [
    "9 PE32/i386",
    "21 PE/CE ARM",
    "36 PE32+/AMD64",
    "43 PE32+/ARM64",
    "44 PE32+/ARM64EC"
  ]);
});

void test("renderUpxFindingDetails shows every PE format option", () => {
  const html = rowValue(renderUpxFindingDetails(createFinding()), "UPX format");

  assert.deepEqual(
    Array.from(html.matchAll(/class="opt (?:sel|dim)"[^>]*>([^<]+)<\/span>/g), match => match[1]),
    [
      "9 PE32/i386", "21 PE/CE ARM", "36 PE32+/AMD64",
      "43 PE32+/ARM64", "44 PE32+/ARM64EC"
    ]
  );
});

void test("renderUpxFindingDetails distinguishes exact bytes from binary units", () => {
  const finding = createFinding();
  finding.packHeader.packedSize = 1024;
  finding.packHeader.unpackedSize = 2048;

  const html = renderUpxFindingDetails(finding);

  assert.ok(html.includes("1 KB (1024 bytes)"));
  assert.doesNotMatch(html, />1024 bytes<\/td>/);
});

void test("renderUpxFindingDetails labels unknown future formats", () => {
  const finding = createFinding();
  finding.packHeader.format = 0xff;

  assert.match(
    rowValue(renderUpxFindingDetails(finding), "UPX format"),
    /class="opt sel"[^>]*>255 Unknown format<\/span>/
  );
});

void test("renderUpxFindingDetails reports files larger than their original input", () => {
  const finding = createFinding();
  finding.packedFileSize = 4096;

  assert.ok(renderUpxFindingDetails(finding).includes("133.3% (33.3% larger)"));
});

void test("upxFilterLabel preserves unknown filter identifiers", () => {
  assert.equal(upxFilterLabel(0xff), "Unknown UPX filter");
});

void test("upxFilterLabel names every mapped PE-relevant upstream filter", () => {
  assert.deepEqual(
    [
      0x00, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
      0x24, 0x25, 0x26, 0x36, 0x46, 0x49, 0x50
    ].map(upxFilterLabel),
    [
      "No filter",
      "x86 E8 call transform",
      "x86 E9 jump transform",
      "x86 E8/E9 call/jump transform",
      "x86 E8 call transform (LE byte swap)",
      "x86 E9 jump transform (LE byte swap)",
      "x86 E8/E9 call/jump transform (LE byte swap)",
      "x86 E8 CTO transform (LE byte swap)",
      "x86 E9 CTO transform (LE byte swap)",
      "x86 E8/E9 CTO transform (LE byte swap)",
      "x86 E8/E9 CTO/JMP transform (LE byte swap)",
      "x86 E8/E9 CTO/JMP multi-block transform",
      "x86 E8/E9/Jcc CTO transform",
      "ARM 24-bit branch transform (LE)"
    ]
  );
});
