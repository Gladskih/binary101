import assert from "node:assert/strict";
import { test } from "node:test";
import { parseXrefTable, xrefKeyword } from "../../../../analyzers/pdf/xref-table.js";

void test("xref and trailer keywords are anchored to their expected byte boundaries", () => {
  assert.equal(xrefKeyword.test("prefixxref\n"), false);
  assert.equal(xrefKeyword.test("xrefExtra\n"), false);
  assert.equal(xrefKeyword.test("xref\r"), true);
  const issues: string[] = [];
  const table = parseXrefTable("xref\nxtrailer<< /Size 2 >>", 19, 2, issues);
  assert.deepEqual(table, { kind: "table", offset: 19, sections: [], entries: null, trailer: null });
  assert.deepEqual(issues, ["Cross-reference table at 19: missing trailer or malformed subsection."]);
});

void test("classic xref accepts CR and CRLF row endings and only uses PDF whitespace", () => {
  const issues: string[] = [];
  const table = parseXrefTable(
    "xref\r0 \t1 \r0000000000 65535 f \r1 1\r\n0000001234 00020 n\r\ntrailer<< /Size 2 >>", 0, 2, issues);
  assert.deepEqual(table.sections, [{ start: 0, count: 1 }, { start: 1, count: 1 }]);
  assert.deepEqual(table.entries, [
    { kind: "free", objectNumber: 0, nextFree: 0, generation: 65535 },
    { kind: "direct", objectNumber: 1, offset: 1234, generation: 20 }
  ]);
  assert.deepEqual(issues, []);
});

void test("classic xref spends the section budget across all subsections", () => {
  const issues: string[] = [];
  const table = parseXrefTable(
    "xref\n0 1\n0000000000 65535 f \n1 2\n0000001234 00020 n \n0000001235 00000 n \ntrailer<< /Size 3 >>",
    19, 2, issues);
  assert.deepEqual(table, { kind: "table", offset: 19, sections: [], entries: null, trailer: null });
  assert.deepEqual(issues, ["Cross-reference table at 19: xref entry limit reached."]);
});

for (const [subsection, reason] of [
  ["0 1x", "missing trailer or malformed subsection"],
  ["0 0", "invalid subsection bounds"],
  ["9007199254740992 1", "invalid subsection bounds"]
] as const) {
  void test("classic xref rejects malformed subsection line " + subsection, () => {
    const issues: string[] = [];
    const table = parseXrefTable("xref\n" + subsection + "\ntrailer << /Size 3 >>", 19, 2, issues);
    assert.equal(table.entries, null);
    assert.deepEqual(issues, ["Cross-reference table at 19: " + reason + "."]);
  });
}
