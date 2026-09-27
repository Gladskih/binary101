import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeRegistryText, decodeRegistryTextChunks } from "../../../../../../analyzers/pe/resources/preview/registry-text.js";

// BOM/code-unit byte oracles: https://www.unicode.org/faq/utf_bom.html
// Code-page identifiers: https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
// Character mappings are independently sourced in the table below, not production constants.
async function* byteChunks(data: number[]): AsyncGenerator<Uint8Array> {
  for (const byte of data) yield new Uint8Array([byte]);
}

for (const [bytes, codePage, expected] of [
  [[0xef, 0xbb, 0xbf, 0xd0, 0x9f], 1252, { text: "П", encoding: "utf-8" }],
  [[0xff, 0xfe, 0x3d, 0xd8, 0x00, 0xde], 65001, { text: "😀", encoding: "utf-16le" }],
  [[0xfe, 0xff, 0xd8, 0x3d, 0xde, 0x00], 65001, { text: "😀", encoding: "utf-16be" }],
  [[0x82, 0xa0], 932, { text: "あ", encoding: "shift_jis" }],
  [[], 0, { text: "", encoding: "windows-1252" }],
  [[65, 0, 0], 65001, { text: "A", encoding: "utf-8" }]
] as const) {
  void test(`streamed code page ${codePage} decodes split BOMs and code units ${bytes}`, async () => {
    const issues: string[] = [];
    assert.deepEqual(await decodeRegistryTextChunks(byteChunks([...bytes]), codePage, issues), expected);
    assert.deepEqual(issues, []);
  });
}

void test("streamed diagnostics inspect bytes and suffixes after the first window", async () => {
  const issues: string[] = [];
  assert.equal((await decodeRegistryTextChunks(byteChunks([65, 65, 65, 0xe9]), 0, issues)).text, "AAAé");
  assert.deepEqual(issues, ["ATL RGS: ANSI code page is unspecified; Windows-1252 fallback is uncertain."]);
  const trailing: string[] = [];
  assert.equal((await decodeRegistryTextChunks(byteChunks([65, 0, 0, 66]), 65001, trailing)).text, "A");
  assert.deepEqual(trailing, ["ATL RGS: non-padding data follows a NUL terminator; analysis stopped there."]);
});

void test("BOM takes precedence over ANSI metadata and UTF-16 variants decode", () => {
  assert.deepEqual(decodeRegistryText(new Uint8Array([255, 254, 65, 0]), 1251, []),
    { text: "A", encoding: "utf-16le" });
  assert.deepEqual(decodeRegistryText(new Uint8Array([254, 255, 0, 65]), 1251, []),
    { text: "A", encoding: "utf-16be" });
  assert.equal(decodeRegistryText(new Uint8Array([239, 187, 191, 65]), 1251, []).text, "A");
  assert.equal(decodeRegistryText(new Uint8Array([65, 0]), 1200, []).text, "A");
  assert.equal(decodeRegistryText(new Uint8Array([0, 65]), 1201, []).text, "A");
});
void test("ANSI code pages preserve non-ASCII strings", () => {
  assert.equal(decodeRegistryText(new Uint8Array([0xcf, 0xf0]), 1251, []).text, "Пр");
  assert.equal(decodeRegistryText(new Uint8Array([0xe9]), 1252, []).text, "é");
  assert.equal(decodeRegistryText(new Uint8Array([65]), 20127, []).text, "A");
  assert.equal(decodeRegistryText(new Uint8Array(), 0, []).text, "");
});
void test("unknown ANSI encoding is marked uncertain only when it affects non-ASCII data", () => {
  const issues: string[] = [];
  decodeRegistryText(new Uint8Array([0xe9]), 0, issues);
  decodeRegistryText(new Uint8Array([0xe9]), 42, issues);
  assert.match(issues.join(" "), /unspecified/);
  assert.match(issues.join(" "), /unsupported code page 42/);
  assert.equal(decodeRegistryText(new Uint8Array([65]), 42, []).text, "A");
});
void test("invalid bytes, odd UTF-16 lengths and embedded NULs produce warnings", () => {
  const issues: string[] = [];
  decodeRegistryText(new Uint8Array([255]), 65001, issues);
  decodeRegistryText(new Uint8Array([65, 0, 66]), 1200, issues);
  assert.equal(decodeRegistryText(new Uint8Array([65, 0, 66]), 65001, issues).text, "A");
  assert.match(issues.join(" "), /invalid encoded/);
  assert.match(issues.join(" "), /truncated UTF-16/);
  assert.match(issues.join(" "), /non-padding/);
  const paddingIssues: string[] = [];
  assert.equal(decodeRegistryText(new Uint8Array([65, 0, 0]), 65001, paddingIssues).text, "A");
  assert.deepEqual(paddingIssues, []);
  const odd: string[] = [];
  decodeRegistryText(new Uint8Array([65, 0, 66]), 1200, odd);
  assert.deepEqual(odd, ["ATL RGS: truncated UTF-16 code unit.", "ATL RGS: invalid encoded text."]);
});

void test("non-ASCII bytes in a declared US-ASCII resource are diagnosed", () => {
  const issues: string[] = [];
  decodeRegistryText(new Uint8Array([0xe9]), 20127, issues);
  assert.match(issues.join(" "), /non-ASCII/);
});

void test("partial BOM prefixes do not override explicit UTF-8 metadata", () => {
  assert.equal(decodeRegistryText(new Uint8Array([0xff, 65]), 65001, []).encoding, "utf-8");
  assert.equal(decodeRegistryText(new Uint8Array([65, 0xfe]), 65001, []).encoding, "utf-8");
  assert.equal(decodeRegistryText(new Uint8Array([0xfe, 65]), 65001, []).encoding, "utf-8");
  assert.equal(decodeRegistryText(new Uint8Array([65, 0xff]), 65001, []).encoding, "utf-8");
  assert.equal(decodeRegistryText(new Uint8Array([0xef, 65, 0xbf]), 1252, []).encoding, "windows-1252");
  assert.equal(decodeRegistryText(new Uint8Array([65, 0xbb, 0xbf]), 1252, []).encoding, "windows-1252");
  assert.equal(decodeRegistryText(new Uint8Array([0xef, 0xbb, 65]), 1252, []).encoding, "windows-1252");
});

void test("encoding diagnostics distinguish ASCII, mixed ANSI, empty NUL and even UTF-16", () => {
  const issues: string[] = [];
  assert.equal(decodeRegistryText(new Uint8Array([0x80, 65]), 0, issues).text, "€A");
  assert.equal(issues.length, 1);
  assert.equal(decodeRegistryText(new Uint8Array([0, 65]), 65001, issues).text, "");
  assert.match(issues.join(" "), /non-padding/);
  const valid: string[] = [];
  decodeRegistryText(new Uint8Array([65, 0]), 1200, valid);
  decodeRegistryText(new Uint8Array([65, 0x80]), 20127, valid);
  assert.equal(valid.length, 1);
  assert.match(valid[0] ?? "", /non-ASCII/);
});

// Microsoft code-page mapping tables, checked against Unicode's published copies:
// https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1250.TXT
// Other CP*.TXT files use the same directory, except CP874 in ../PC/.
for (const [codePage, bytes, expected] of [
  [1250, [0xa5], "Ą"], [1251, [0xcf], "П"], [1252, [0x80], "€"],
  [1253, [0xc1], "Α"], [1254, [0xd0], "Ğ"], [1255, [0xe0], "א"],
  [1256, [0xc7], "ا"], [1257, [0xc0], "Ą"], [1258, [0xcc], "\u0300"],
  [874, [0xa1], "ก"], [932, [0x82, 0xa0], "あ"], [936, [0xd6, 0xd0], "中"],
  [949, [0xb0, 0xa1], "가"], [950, [0xa4, 0xa4], "中"],
  [65001, [0xd0, 0x9f], "П"]
] as const) {
  void test(`code page ${codePage} uses its published character mapping`, () => {
    const issues: string[] = [];
    assert.equal(decodeRegistryText(new Uint8Array(bytes), codePage, issues).text, expected);
    assert.deepEqual(issues, []);
  });
}
