import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeTextResource, addStringTablePreview, addHtmlPreview } from
  "../../../../../../analyzers/pe/resources/preview/text.js";

void test("honors an explicit Windows code page", () => {
  // CP1251 bytes for Привет; Microsoft Code Page Identifiers, 1251 = Windows Cyrillic.
  const result = decodeTextResource(Uint8Array.from([0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2]), 1251);

  assert.equal(result.text, "Привет");
  assert.equal(result.encoding, "windows-1251");
  assert.equal(result.error, undefined);
});

void test("reports incomplete string blocks while retaining readable entries", () => {
  // RT_STRING always contains sixteen length-prefixed strings, including empty ones.
  // https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types#string-table-resources
  const result = addStringTablePreview(new Uint8Array([0, 0]), "STRING", 1);

  assert.deepEqual(result?.preview?.stringTable, [{ id: 0, text: "" }]);
  assert.match(result?.issues?.join(" ") ?? "", /16/);
});

void test("accepts a literal Unicode replacement character and gives BOM priority", () => {
  const literal = decodeTextResource(new TextEncoder().encode("\ufffd"), 65001);
  const bom = decodeTextResource(Uint8Array.of(0xef, 0xbb, 0xbf, 65), 99999);

  assert.equal(literal.error, undefined);
  assert.equal(literal.text, "\ufffd");
  assert.equal(bom.error, undefined);
  assert.equal(bom.text, "A");
});

void test("rejects invalid bytes in explicitly declared ASCII", () => {
  assert.ok(decodeTextResource(Uint8Array.of(128), 20127).error);
});

// Microsoft Code Page Identifiers / WHATWG Encoding labels. ASCII A is shared by these
// legacy encodings; the declared label remains part of the preview contract.
for (const [page, encoding] of new Map([
  [65001, "UTF-8"], [20127, "US-ASCII"], [874, "windows-874"], [932, "shift_jis"],
  [936, "gbk"], [949, "euc-kr"], [950, "big5"], [1250, "windows-1250"],
  [1251, "windows-1251"], [1252, "windows-1252"], [1253, "windows-1253"],
  [1254, "windows-1254"], [1255, "windows-1255"], [1256, "windows-1256"],
  [1257, "windows-1257"], [1258, "windows-1258"]
])) {
  void test(`retains the declared Windows code page ${page}`, () => {
    const result = decodeTextResource(Uint8Array.of(65, 0, 66), page);

    assert.equal(result.text, "A");
    assert.equal(result.encoding, encoding);
    assert.equal(result.terminated, true);
    assert.equal(result.error, undefined);
  });
}

void test("decodes aligned UTF-16 terminators and both byte orders", () => {
  const little = decodeTextResource(Uint8Array.of(65, 0, 0, 0, 66, 0), 1200);
  const big = decodeTextResource(Uint8Array.of(0, 65, 0, 0, 0, 66), 1201);

  assert.deepEqual(little, { text: "A", encoding: "UTF-16LE", terminated: true });
  assert.deepEqual(big, { text: "A", encoding: "UTF-16BE", terminated: true });
  assert.equal(decodeTextResource(Uint8Array.of(255, 254, 65, 0), 1251).text, "A");
  assert.equal(decodeTextResource(Uint8Array.of(254, 255, 0, 65), 1251).text, "A");
});

void test("reports malformed text and unknown code pages without mistaking valid replacement characters", () => {
  assert.ok(decodeTextResource(Uint8Array.of(255), 65001).error);
  assert.ok(decodeTextResource(Uint8Array.of(65), 1200).error);
  assert.match(String(decodeTextResource(Uint8Array.of(65), 99999).error), /99999/);
  assert.equal(decodeTextResource(Uint8Array.of(65), undefined).text, "A");
  assert.deepEqual(decodeTextResource(new Uint8Array(), 65001),
    { text: "", encoding: "", terminated: false });
});

void test("detects trailing and truncated counted string data", () => {
  const complete = new Uint8Array(32);
  const trailing = new Uint8Array(33);
  const truncated = Uint8Array.of(1, 0, 65);

  assert.equal(addStringTablePreview(complete, "STRING", 1)?.issues, undefined);
  assert.match(addStringTablePreview(trailing, "STRING", 1)?.issues?.join(" ") ?? "", /trailing/);
  assert.match(addStringTablePreview(truncated, "STRING", 1)?.issues?.join(" ") ?? "", /unexpectedly/);
  assert.equal(addStringTablePreview(complete, "STRING", null)?.preview?.stringTable?.[0]?.id, null);
});

void test("uses aligned terminators without treating half a UTF-16 code unit as a terminator", () => {
  assert.equal(decodeTextResource(Uint8Array.of(0, 1, 65, 0), 1200).text, "\u0100A");
  assert.equal(decodeTextResource(Uint8Array.of(0), 65001).terminated, true);
  assert.equal(decodeTextResource(Uint8Array.of(65), 65001).terminated, false);
  assert.ok(decodeTextResource(Uint8Array.of(65, 128), 20127).error);
  assert.equal(decodeTextResource(Uint8Array.of(0xef, 65, 0xbf), 1252).encoding, "windows-1252");
  assert.equal(decodeTextResource(Uint8Array.of(65, 0xbb, 0xbf), 1252).encoding, "windows-1252");
});

void test("retains counted strings and computes their IDs independently of text termination", () => {
  const data = new Uint8Array(38);
  data.set([3, 0, 65, 0, 0, 0, 66, 0]);
  const strings = addStringTablePreview(data, "STRING", 2)?.preview?.stringTable;

  assert.equal(strings?.length, 16);
  assert.deepEqual(strings?.[0], { id: 16, text: "A\0B" });
  assert.deepEqual(strings?.[1], { id: 17, text: "" });
  assert.equal(addStringTablePreview(data, "OTHER", 2), null);
  assert.match(addStringTablePreview(new Uint8Array(), "STRING", 1)?.issues?.join(" ") ?? "", /small/);
});

void test("does not accept partial BOM byte matches", () => {
  assert.equal(decodeTextResource(Uint8Array.of(255, 65), 1252).encoding, "windows-1252");
  assert.equal(decodeTextResource(Uint8Array.of(65, 254), 1252).encoding, "windows-1252");
  assert.equal(decodeTextResource(Uint8Array.of(254, 65), 1252).encoding, "windows-1252");
  assert.equal(decodeTextResource(Uint8Array.of(65, 255), 1252).encoding, "windows-1252");
  assert.equal(decodeTextResource(Uint8Array.of(239, 187, 65), 1252).encoding, "windows-1252");
  assert.equal(decodeTextResource(Uint8Array.of(65, 0, 0, 1), 1200).text, "A\u0100");
  assert.equal(decodeTextResource(Uint8Array.of(65, 0, 0, 1), 1200).terminated, false);
});
void test("keeps invalid decoding diagnostics and termination metadata", () => {
  const result = decodeTextResource(Uint8Array.of(255,0), 65001);
  assert.equal(result.text, "");
  assert.equal(result.encoding, "UTF-8");
  assert.equal(result.terminated, true);
  assert.ok(result.error instanceof Error);
  assert.match(String(decodeTextResource(Uint8Array.of(128),20127).error), /non-ASCII/);
  assert.match(addStringTablePreview(Uint8Array.of(99,0),"STRING",1)?.issues?.join(" ") ?? "", /No strings/);
  const partial = addStringTablePreview(Uint8Array.of(0,0,99,0,65),"STRING",1);
  assert.equal(partial?.issues?.some(issue=>issue.includes("trailing")),false);
});
void test("shows HTML exclusively as escaped-source data with descriptive fields", () => {
  const result = addHtmlPreview(new TextEncoder().encode(" \n<html>x</html>\0tail"),"HTML",65001);
  assert.equal(result?.preview?.previewKind,"html");
  assert.equal(result?.preview?.textPreview," \n<html>x</html>");
  assert.equal(result?.preview?.textEncoding,"UTF-8");
  assert.deepEqual(result?.preview?.previewFields,[{label:"Type",value:"HTML"},
    {label:"Safety",value:"Shown as escaped source; HTML is not executed."}]);
  assert.match(result?.issues?.join(" ") ?? "",/NUL/);
  assert.equal(addHtmlPreview(new TextEncoder().encode("text <html>"),"HTML",65001),null);
  assert.equal(addHtmlPreview(new Uint8Array(),"HTML",65001),null);
  assert.equal(addHtmlPreview(new Uint8Array(),"OTHER",65001),null);
  assert.match(addHtmlPreview(Uint8Array.of(255),"HTML",65001)?.issues?.join(" ") ?? "",/decoded/);
});

void test("preserves unterminated malformed-text metadata and dispatches only HTML resources", () => {
  assert.equal(decodeTextResource(Uint8Array.of(255),65001).terminated,false);
  const html = new TextEncoder().encode("<html/>");
  assert.equal(addHtmlPreview(html,"OTHER",65001),null);
  assert.equal(addHtmlPreview(html,"HTML",65001)?.issues,undefined);
  const strings = new Uint8Array(34);
  strings.set([1,0,0,216]); // Unpaired high surrogate in a counted UTF-16 string.
  assert.equal(addStringTablePreview(strings,"STRING",1)?.preview?.stringTable?.[0]?.text,"\ufffd");
});
