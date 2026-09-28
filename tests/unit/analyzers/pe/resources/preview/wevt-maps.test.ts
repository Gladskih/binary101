import assert from "node:assert/strict";
import { test } from "node:test";
import { parseWevtMaps } from "../../../../../../analyzers/pe/resources/preview/wevt-maps.js";
import { addWevtTemplatePreview } from "../../../../../../analyzers/pe/resources/preview/wevt-template.js";

const valueMapFixture = (): Uint8Array => {
  // libfwevt sections 6 and 6.2: MAPS header, then one 24-byte VMAP with one entry.
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("MAPS"));
  view.setUint32(4, 36, true); view.setUint32(8, 1, true);
  bytes.set(new TextEncoder().encode("VMAP"), 12);
  view.setUint32(16, 24, true); view.setUint32(20, 96, true);
  view.setUint32(24, 1, true); view.setUint32(28, 7, true);
  view.setUint32(32, 42, true);
  view.setUint32(96, 12, true);
  bytes.set(new TextEncoder().encode("M\0a\0p\0\0\0"), 100);
  return bytes;
};

void test("reads a VMAP name, values and message IDs", () => {
  const issues: string[] = [];
  const maps = parseWevtMaps(valueMapFixture(), 0, 36, 128, issues);
  assert.deepEqual(maps, [{ offset: 12, kind: "VMAP", name: "Map",
    entries: [{ value: 7, messageId: 42 }] }]);
  assert.deepEqual(issues, []);
});

void test("reads an offset for every map in the layout seen in wevtsvc.dll", () => {
  const bytes = new Uint8Array(96);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("MAPS"));
  view.setUint32(4, 68, true); view.setUint32(8, 2, true);
  view.setUint32(12, 44, true); view.setUint32(16, 20, true);
  bytes.set(new TextEncoder().encode("VMAP"), 20);
  view.setUint32(24, 24, true); view.setUint32(32, 1, true);
  view.setUint32(36, 7, true);
  bytes.set(new TextEncoder().encode("VMAP"), 44);
  view.setUint32(48, 24, true); view.setUint32(56, 1, true);
  view.setUint32(60, 8, true);
  const issues: string[] = [];
  const maps = parseWevtMaps(bytes, 0, 68, 96, issues);
  assert.deepEqual(maps.map(map => [map.offset, map.entries[0]?.value]), [[20, 7], [44, 8]]);
  assert.deepEqual(issues, []);
});

void test("reports a truncated VMAP entry array", () => {
  const bytes = valueMapFixture();
  new DataView(bytes.buffer).setUint32(24, 2, true);
  const issues: string[] = [];
  assert.equal(parseWevtMaps(bytes, 0, 36, 128, issues)[0]?.entries.length, 1);
  assert.deepEqual(issues, ["WEVT VMAP entries are truncated."]);
});

void test("rejects invalid map offsets and bounds", () => {
  const bytes = valueMapFixture();
  const view = new DataView(bytes.buffer);
  bytes.copyWithin(16, 12, 36);
  view.setUint32(4, 40, true);
  view.setUint32(8, 2, true);
  view.setUint32(12, 0xffffffff, true);
  const issues: string[] = [];
  assert.equal(parseWevtMaps(bytes, 0, 40, 128, issues).length, 1);
  assert.ok(issues.includes("WEVT map definition offset is invalid."));
});

void test("identifies BMAP without guessing its undocumented entries", () => {
  const bytes = valueMapFixture();
  bytes.set(new TextEncoder().encode("BMAP"), 12);
  const issues: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 36, 128, issues),
    [{ offset: 12, kind: "BMAP", name: null, entries: [] }]);
  assert.deepEqual(issues, ["WEVT BMAP entry layout is not documented."]);
});

void test("attaches MAPS definitions to the provider preview", () => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("CRIM"));
  view.setUint32(4, 128, true); view.setUint32(12, 1, true);
  view.setUint32(32, 40, true);
  bytes.set(new TextEncoder().encode("WEVT"), 40);
  view.setUint32(44, 28, true); view.setUint32(52, 1, true);
  view.setUint32(60, 72, true);
  bytes.set(new TextEncoder().encode("MAPS"), 72);
  view.setUint32(76, 36, true); view.setUint32(80, 1, true);
  bytes.set(new TextEncoder().encode("VMAP"), 84);
  view.setUint32(88, 24, true); view.setUint32(96, 1, true);
  view.setUint32(100, 7, true); view.setUint32(104, 42, true);
  const result = addWevtTemplatePreview(bytes, "WEVT_TEMPLATE");
  assert.deepEqual(result?.preview?.wevtTemplate?.providers[0]?.maps,
    [{ offset: 84, kind: "VMAP", name: null, entries: [{ value: 7, messageId: 42 }] }]);
  assert.equal(result?.issues, undefined);
});

void test("rejects truncated and invalid public MAPS ranges", () => {
  const bytes = valueMapFixture();
  const issues: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, -1, 36, 128, issues), []);
  assert.deepEqual(parseWevtMaps(bytes, 0.5, 36, 128, issues), []);
  assert.deepEqual(parseWevtMaps(bytes, 0, 11, 128, issues), []);
  assert.deepEqual(parseWevtMaps(bytes, 0, 36, 129, issues), []);
  assert.deepEqual(parseWevtMaps(bytes, 0, 0xffffffff, 128, issues), []);
  assert.equal(issues.length, 5);
});

void test("warns on a malformed VMAP size and an unknown map signature", () => {
  const bytes = valueMapFixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(16, 15, true);
  const invalidSize: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 36, 128, invalidSize), []);
  assert.deepEqual(invalidSize, ["WEVT VMAP size is invalid."]);
  bytes[12] = 0;
  const unknown: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 36, 128, unknown), []);
  assert.deepEqual(unknown, ["WEVT map definition signature is unknown."]);
});

void test("warns when a VMAP string offset is outside the resource", () => {
  const bytes = valueMapFixture();
  new DataView(bytes.buffer).setUint32(20, 0xffffffff, true);
  const issues: string[] = [];
  assert.equal(parseWevtMaps(bytes, 0, 36, 128, issues)[0]?.name, null);
  assert.deepEqual(issues, ["WEVT map name offset is invalid."]);
});

void test("checks VMAP name lengths and terminates at NUL", () => {
  const bytes = valueMapFixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(96, 4, true);
  const tooShort: string[] = [];
  assert.equal(parseWevtMaps(bytes, 0, 36, 128, tooShort)[0]?.name, null);
  assert.deepEqual(tooShort, ["WEVT map name is invalid or truncated."]);
  view.setUint32(96, 7, true);
  const odd: string[] = [];
  assert.equal(parseWevtMaps(bytes, 0, 36, 128, odd)[0]?.name, null);
  assert.deepEqual(odd, ["WEVT map name is invalid or truncated."]);
  view.setUint32(96, 12, true);
  bytes.set(new TextEncoder().encode("A\0\0\0X\0\0\0"), 100);
  assert.equal(parseWevtMaps(bytes, 0, 36, 128, [])[0]?.name, "A");
});

void test("checks a VMAP name range before reading it", () => {
  const bytes = valueMapFixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(20, 124, true);
  view.setUint32(124, 8, true);
  const issues: string[] = [];
  assert.equal(parseWevtMaps(bytes, 0, 36, 128, issues)[0]?.name, null);
  assert.deepEqual(issues, ["WEVT map name is invalid or truncated."]);
});

void test("reads two value entries and absent message sentinel", () => {
  const bytes = valueMapFixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 44, true); view.setUint32(16, 32, true);
  view.setUint32(24, 2, true);
  view.setUint32(36, 8, true); view.setUint32(40, 0xffffffff, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 44, 128, issues)[0]?.entries,
    [{ value: 7, messageId: 42 }, { value: 8, messageId: null }]);
  assert.deepEqual(issues, []);
});

void test("rejects invalid MAPS directory count and VMAP header", () => {
  const bytes = valueMapFixture();
  const view = new DataView(bytes.buffer);
  view.setUint32(8, 100, true);
  const directoryIssues: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 36, 128, directoryIssues), []);
  assert.deepEqual(directoryIssues, ["WEVT MAPS definition offsets are truncated."]);
  view.setUint32(8, 1, true);
  view.setUint32(4, 20, true);
  const headerIssues: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 20, 128, headerIssues), []);
  assert.deepEqual(headerIssues, ["WEVT VMAP header is truncated."]);
});

void test("checks both full and implied map offset layouts", () => {
  const bytes = new Uint8Array(96);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("MAPS"));
  view.setUint32(4, 64, true); view.setUint32(8, 2, true);
  view.setUint32(12, 40, true);
  bytes.set(new TextEncoder().encode("VMAP"), 16);
  view.setUint32(20, 24, true);
  bytes.set(new TextEncoder().encode("VMAP"), 40);
  view.setUint32(44, 24, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 64, 96, issues).map(map => map.offset), [16, 40]);
  assert.deepEqual(issues, []);
});

void test("walks three implied map offsets", () => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("MAPS"));
  view.setUint32(4, 92, true); view.setUint32(8, 3, true);
  view.setUint32(12, 44, true); view.setUint32(16, 68, true);
  bytes.set(new TextEncoder().encode("VMAP"), 20);
  view.setUint32(24, 24, true);
  bytes.set(new TextEncoder().encode("VMAP"), 44);
  view.setUint32(48, 24, true);
  bytes.set(new TextEncoder().encode("VMAP"), 68);
  view.setUint32(72, 24, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 92, 128, issues).map(map => map.offset),
    [20, 44, 68]);
  assert.deepEqual(issues, []);
});

void test("walks three explicit map offsets", () => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("MAPS"));
  view.setUint32(4, 96, true); view.setUint32(8, 3, true);
  view.setUint32(12, 24, true); view.setUint32(16, 48, true);
  view.setUint32(20, 72, true);
  bytes.set(new TextEncoder().encode("VMAP"), 24);
  view.setUint32(28, 24, true);
  bytes.set(new TextEncoder().encode("VMAP"), 48);
  view.setUint32(52, 24, true);
  bytes.set(new TextEncoder().encode("VMAP"), 72);
  view.setUint32(76, 24, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 96, 128, issues).map(map => map.offset),
    [24, 48, 72]);
  assert.deepEqual(issues, []);
});

void test("accepts exact minimal headers and rejects adjacent smaller sizes", () => {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("MAPS"));
  view.setUint32(4, 12, true);
  assert.deepEqual(parseWevtMaps(bytes, 0, 12, 32, []), []);
  view.setUint32(8, 1, true);
  bytes.set(new TextEncoder().encode("VMAP"), 12);
  view.setUint32(16, 16, true);
  assert.deepEqual(parseWevtMaps(bytes, 0, 28, 32, []),
    [{ offset: 12, kind: "VMAP", name: null, entries: [] }]);
  view.setUint32(16, 15, true);
  const issues: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 28, 32, issues), []);
  assert.deepEqual(issues, ["WEVT VMAP size is invalid."]);
});

void test("rejects fractional and negative MAPS lengths", () => {
  const bytes = valueMapFixture();
  const fractional: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, 36.5, 128, fractional), []);
  assert.deepEqual(fractional, ["WEVT MAPS section is invalid or truncated."]);
  const negative: string[] = [];
  assert.deepEqual(parseWevtMaps(bytes, 0, -1, 128, negative), []);
  assert.deepEqual(negative, ["WEVT MAPS section is invalid or truncated."]);
});
