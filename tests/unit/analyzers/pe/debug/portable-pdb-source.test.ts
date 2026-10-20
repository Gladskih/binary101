import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateRawSync } from "node:zlib";
import { analyzePortablePdbSource } from "../../../../../analyzers/pe/debug/portable-pdb-source.js";

const sourceBlob = (bytes: Uint8Array, size: number): Uint8Array => {
  const result = new Uint8Array(4 + bytes.length);
  new DataView(result.buffer).setInt32(0, size, true);
  result.set(bytes, 4);
  return result;
};

void test("Portable PDB embedded source analyzes uncompressed and raw Deflate source", async () => {
  const bytes = new TextEncoder().encode("first\r\nsecond\nthird\rfourth");
  const issues: string[] = [];

  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(bytes, 0), issues),
    { storage: "raw", bytes: bytes.length, lines: 4, encoding: "UTF-8" });
  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(deflateRawSync(bytes), bytes.length), issues),
    { storage: "deflate", bytes: bytes.length, lines: 4, encoding: "UTF-8" });
  assert.deepEqual(issues, []);
});

void test("Portable PDB embedded source counts newlines across read windows", async () => {
  const bytes = new TextEncoder().encode(`${"a".repeat(65535)}\r\n\ud83d\ude00`);
  const issues: string[] = [];

  assert.equal((await analyzePortablePdbSource(sourceBlob(bytes, 0), issues))?.lines, 2);
  assert.deepEqual(issues, []);
});

void test("Portable PDB embedded source recognizes UTF-16 byte order marks", async () => {
  const issues: string[] = [];

  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(Uint8Array.of(255, 254, 65, 0, 10, 0), 0), issues),
    { storage: "raw", bytes: 6, lines: 2, encoding: "UTF-16LE" });
  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(Uint8Array.of(254, 255, 0, 65), 0), issues),
    { storage: "raw", bytes: 4, lines: 1, encoding: "UTF-16BE" });
  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(Uint8Array.of(239, 187, 191), 0), issues),
    { storage: "raw", bytes: 3, lines: 0, encoding: "UTF-8" });
  assert.deepEqual(issues, []);
});

void test("Portable PDB embedded source leaves unknown encodings explicit", async () => {
  const issues: string[] = [];

  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(Uint8Array.of(255), 0), issues),
    { storage: "raw", bytes: 1, lines: null, encoding: null });
  assert.match(issues.join(" | "), /encoding/);
});

void test("Portable PDB embedded source diagnoses corrupt, truncated and future formats", async () => {
  const issues: string[] = [];

  assert.equal(await analyzePortablePdbSource(Uint8Array.of(0), issues), null);
  assert.equal(await analyzePortablePdbSource(sourceBlob(new Uint8Array(), -1), issues), null);
  assert.equal(await analyzePortablePdbSource(sourceBlob(Uint8Array.of(255), 3), issues), null);
  assert.equal(await analyzePortablePdbSource(sourceBlob(deflateRawSync("too long"), 1), issues), null);
  assert.match(issues.join(" | "), /truncated/);
  assert.match(issues.join(" | "), /future/);
  assert.match(issues.join(" | "), /decompress/);
});

void test("Portable PDB embedded source handles empty content", async () => {
  const issues: string[] = [];

  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(new Uint8Array(), 0), issues),
    { storage: "raw", bytes: 0, lines: 0, encoding: "UTF-8" });
  assert.deepEqual(issues, []);
});

[[255, 254, 0, 216], [255, 254, 0, 0, 0], [0, 0, 254, 255, 0, 17, 0, 0],
  [255, 254, 0, 0, 0, 216, 0, 0]].forEach(bytes => {
  void test(`Portable PDB source leaves unsupported or malformed Unicode encoding explicit: ${bytes}`, async () => {
    const issues: string[] = [];

    assert.equal((await analyzePortablePdbSource(sourceBlob(Uint8Array.from(bytes), 0), issues))?.encoding, null);
    assert.match(issues.join(" | "), /encoding/);
  });
});

void test("Portable PDB source reads BOM-marked UTF-32 in either byte order", async () => {
  const issues: string[] = [];

  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(Uint8Array.of(
    255, 254, 0, 0, 0, 246, 1, 0, 13, 0, 0, 0, 10, 0, 0, 0), 0), issues),
  { storage: "raw", bytes: 16, lines: 2, encoding: "UTF-32LE" });
  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(Uint8Array.of(
    0, 0, 254, 255, 0, 0, 0, 65), 0), issues),
  { storage: "raw", bytes: 8, lines: 1, encoding: "UTF-32BE" });
  assert.deepEqual(await analyzePortablePdbSource(sourceBlob(Uint8Array.of(255, 254, 0, 0), 0), issues),
    { storage: "raw", bytes: 4, lines: 0, encoding: "UTF-32LE" });
  assert.deepEqual(issues, []);
});

void test("Portable PDB source keeps multibyte UTF-8 across read windows", async () => {
  const bytes = new TextEncoder().encode(`${"a".repeat(65535)}\ud83d\ude00`);
  const issues: string[] = [];

  assert.equal((await analyzePortablePdbSource(sourceBlob(bytes, 0), issues))?.lines, 1);
  assert.deepEqual(issues, []);
});
