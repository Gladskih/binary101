import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWevtSection } from "../../../../../../analyzers/pe/resources/preview/wevt-sections.js";

const levelFixture = (): Uint8Array => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("LEVL"));
  view.setUint32(4, 24, true); view.setUint32(8, 1, true);
  view.setUint32(12, 4, true); view.setUint32(16, 55, true);
  view.setUint32(20, 96, true); view.setUint32(96, 16, true);
  bytes.set(new TextEncoder().encode("E\0r\0r\0o\0r\0"), 100);
  return bytes;
};

void test("reads an OPCO table away from the start of the manifest", () => {
  const bytes = levelFixture();
  const view = new DataView(bytes.buffer);
  bytes.set(bytes.subarray(0, 24), 32);
  bytes.set(new TextEncoder().encode("OPCO"), 32);
  view.setUint32(40, 1, true); view.setUint32(44, 9, true);
  view.setUint32(48, 0xffffffff, true); view.setUint32(52, 0, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 32, 128, issues).metadata,
    [{ kind: "OPCO", id: "9", name: null, messageId: null }]);
  assert.deepEqual(issues, []);
});

void test("checks all conditions for a zero-size metadata table", () => {
  const bytes = levelFixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 0, true); view.setUint32(8, 0, true);
  assert.deepEqual(parseWevtSection(bytes, 0, 128, []), { metadata: [], templates: [] });
  bytes.set(new TextEncoder().encode("OPCO"));
  const opcodeIssues: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 0, 128, opcodeIssues),
    { metadata: [], templates: [] });
  assert.deepEqual(opcodeIssues, []);
  bytes.set(new TextEncoder().encode("TASK"));
  const invalidKind: string[] = [];
  parseWevtSection(bytes, 0, 128, invalidKind);
  assert.deepEqual(invalidKind, ["WEVT TASK section size is invalid."]);
  bytes.set(new TextEncoder().encode("LEVL"));
  view.setUint32(8, 1, true);
  const invalidCount: string[] = [];
  parseWevtSection(bytes, 0, 128, invalidCount);
  assert.deepEqual(invalidCount, ["WEVT LEVL section size is invalid."]);
  view.setUint32(8, 0, true); view.setUint32(4, 4, true);
  const invalidLength: string[] = [];
  parseWevtSection(bytes, 0, 128, invalidLength);
  assert.deepEqual(invalidLength, ["WEVT LEVL section size is invalid."]);
});

void test("rejects even but too-short names and names outside the manifest", () => {
  const bytes = levelFixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(96, 4, true);
  const shortIssues: string[] = [];
  assert.equal(parseWevtSection(bytes, 0, 128, shortIssues).metadata[0]?.name, null);
  assert.deepEqual(shortIssues, ["WEVT UTF-16 name is invalid or truncated."]);
  view.setUint32(20, 124, true); view.setUint32(124, 8, true);
  const overrunIssues: string[] = [];
  assert.equal(parseWevtSection(bytes, 0, 128, overrunIssues).metadata[0]?.name, null);
  assert.deepEqual(overrunIssues, ["WEVT UTF-16 name is invalid or truncated."]);
});

void test("truncates embedded NUL in a UTF-16 name", () => {
  const bytes = levelFixture();
  bytes.set(new TextEncoder().encode("A\0\0\0X\0"), 100);
  assert.equal(parseWevtSection(bytes, 0, 128, []).metadata[0]?.name, "A");
});

void test("rejects a field array that overruns the manifest", () => {
  const bytes = new Uint8Array(52);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("TTBL"));
  view.setUint32(4, 52, true); view.setUint32(8, 1, true);
  bytes.set(new TextEncoder().encode("TEMP"), 12);
  view.setUint32(16, 40, true); view.setUint32(20, 1, true);
  view.setUint32(28, 44, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 0, 52, issues).templates[0]?.fields, []);
  assert.deepEqual(issues, ["WEVT TEMP field descriptors are truncated."]);
});

void test("counts metadata entries relative to a nonzero table offset", () => {
  const bytes = levelFixture();
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("OPCO"), 32);
  view.setUint32(36, 24, true); view.setUint32(40, 2, true);
  view.setUint32(44, 9, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 32, 128, issues).metadata,
    [{ kind: "OPCO", id: "9", name: null, messageId: 0 }]);
  assert.deepEqual(issues, ["WEVT OPCO definitions are truncated."]);
});

void test("decodes a BinXML fragment inside a TEMP definition", () => {
  const bytes = new Uint8Array(80);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("TTBL"));
  view.setUint32(4, 80, true); view.setUint32(8, 1, true);
  bytes.set(new TextEncoder().encode("TEMP"), 12);
  view.setUint32(16, 68, true);
  // MS-EVEN6 §2.2.12: fragment, empty <A/>, NameHash(A) = 0x41.
  bytes.set([0x0f, 1, 1, 0, 0x01, 0xff, 0xff, 9, 0, 0, 0,
    0x41, 0, 1, 0, 0x41, 0, 0, 0, 0x03], 52);
  const issues: string[] = [];
  assert.deepEqual(parseWevtSection(bytes, 0, 80, issues).templates[0]?.xmlTree,
    { name: "A", attributes: [], text: null, children: [] });
  assert.deepEqual(issues, []);
});
