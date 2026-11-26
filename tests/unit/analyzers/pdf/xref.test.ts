"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { readRevisions } from "../../../../analyzers/pdf/xref.js";

const tableText = [
  "xref",
  "0 2",
  "0000000000 65535 f ",
  "0000000017 00000 n ",
  "trailer",
  "<< /Size 2 >>",
  "startxref",
  "0"
].join("\n");

const open = (text: string) => {
  const file = new File([text], "xref.pdf");
  return createFileRangeReader(file, 0, file.size);
};

void test("readRevisions reads table sections and trailer", async () => {
  const issues: string[] = [];
  const { revisions, index } = await readRevisions(open(tableText), 0, issues);
  assert.equal(revisions[0]?.primary.kind, "table");
  assert.deepEqual(revisions[0]?.primary.sections, [{ start: 0, count: 2 }]);
  assert.equal(revisions[0]?.primary.trailer?.size, 2);
  assert.deepEqual(index.get(1), { kind: "direct", objectNumber: 1, generation: 0, offset: 17 });
  assert.deepEqual(index.get(0), { kind: "free", objectNumber: 0, generation: 65535, nextFree: 0 });
  assert.deepEqual(issues, []);
});

void test("readRevisions reports errors for out-of-bounds offsets", async () => {
  const issues: string[] = [];
  const result = await readRevisions(open("short"), 5, issues);
  assert.deepEqual(result.revisions, []);
  assert.deepEqual(issues, ["Cross-reference offset 5 points outside the file."]);
});

void test("readRevisions keeps raw entries above /Size out of the object index", async () => {
  const issues: string[] = [];
  const { revisions, index } = await readRevisions(open(tableText.replace("/Size 2", "/Size 1")),
    0, issues);
  assert.equal(revisions[0]?.primary.entries?.length, 2);
  assert.equal(index.has(1), false);
  assert.match(issues.join("\n"), /inconsistent \/Size/);
});

const withPreviousSections = (count: number): { text: string; offset: number } => {
  let text = tableText;
  let offset = 0;
  for (let i = 1; i < count; i += 1) {
    const next = text.length + 1;
    text += "\n" + tableText.replace("/Size 2", "/Size 2 /Prev " + offset);
    offset = next;
  }
  return { text, offset };
};

void test("readRevisions stops at the revision chain budget", async () => {
  const issues: string[] = [];
  const { text, offset } = withPreviousSections(33);
  const result = await readRevisions(open(text), offset, issues);
  assert.equal(result.revisions.length, 32);
  assert.match(issues.join("\n"), /revision limit/);
});

void test("readRevisions stops at a cyclic supplemental offset", async () => {
  const issues: string[] = [];
  const { revisions } = await readRevisions(open(tableText.replace("/Size 2", "/Size 2 /XRefStm 0")),
    0, issues);
  assert.equal(revisions.length, 1);
  assert.equal(revisions[0]?.supplement, undefined);
  assert.deepEqual(issues, ["Cross-reference cycle at /XRefStm offset 0."]);
});

const update = (trailer: string): { text: string; offset: number } => {
  const base = tableText + "\n";
  return { text: base + "xref\n0 1\n0000000000 65535 f \ntrailer\n" + trailer, offset: base.length };
};

void test("a malformed supplemental offset cannot uncover entries from an earlier revision", async () => {
  const { text, offset } = update("<< /Size 2 /Prev 0 /XRefStm -1 >>");
  const issues: string[] = [];
  const result = await readRevisions(open(text), offset, issues);
  assert.equal(result.revisions.length, 1);
  assert.equal(result.index.has(1), false);
  assert.deepEqual(issues, ["Invalid /XRefStm byte offset in trailer."]);
});

void test("an unreadable supplemental stream stops revision lookup", async () => {
  const { text, offset } = update("<< /Size 2 /Prev 0 /XRefStm 1 >>");
  const issues: string[] = [];
  const result = await readRevisions(open(text), offset, issues);
  assert.equal(result.revisions.length, 1);
  assert.equal(result.index.has(1), false);
  assert.deepEqual(issues, ["Unable to read /XRefStm at offset 1."]);
});

void test("older entries cannot exceed the latest trailer Size", async () => {
  const { text, offset } = update("<< /Size 1 /Prev 0 >>");
  const issues: string[] = [];
  const result = await readRevisions(open(text), offset, issues);
  assert.equal(result.revisions.length, 2);
  assert.equal(result.index.has(1), false);
  assert.deepEqual(issues, []);
});

void test("a complete chain at the revision limit has no truncation warning", async () => {
  const { text, offset } = withPreviousSections(32);
  const issues: string[] = [];
  const result = await readRevisions(open(text), offset, issues);
  assert.equal(result.revisions.length, 32);
  assert.deepEqual(issues, []);
});

const hybridWithLargePreviousSection = (): { file: File; offset: number } => {
  const base = "xref\n0 99998\n" + "0000000000 65535 f \n".repeat(99_998) +
    "trailer\n<< /Size 99998 >>\n";
  const supplement = "100001 0 obj\n<< /Type /XRef /Size 100002 /Index [99998 2] /W [1 1 1] /Length 6 >>" +
    "\nstream\n" + "\0".repeat(6) + "\nendstream\nendobj\n";
  const update = "xref\n100000 1\n0000000000 65535 f \ntrailer\n" +
    "<< /Size 100002 /Prev 0 /XRefStm " + base.length + " >>";
  return { file: new File([base, supplement, update], "large-hybrid.pdf"), offset: base.length + supplement.length };
};

void test("primary tables and hybrid streams both consume the revision chain's entry budget", async () => {
  const { file, offset } = hybridWithLargePreviousSection();
  const issues: string[] = [];
  const result = await readRevisions(createFileRangeReader(file, 0, file.size), offset, issues);
  assert.equal(result.revisions[0]?.supplement?.entries?.length, 2);
  assert.equal(result.revisions[1]?.primary.entries, null);
  assert.equal(result.index.size, 3);
  assert.deepEqual(issues, ["Cross-reference table at 0: xref entry limit reached."]);
});

for (const [original, replacement, message] of [
  ["0 2", "0 100001", /entry limit/],
  ["0 2", "0 3", /truncated entry/],
  ["0 2", "9007199254740990 2", /subsection bounds/],
  ["xref", "xrefExtra", /cross-reference information/],
  ["65535", "65536", /invalid generation/],
  ["trailer", "1 1\n0000000017 00000 n \ntrailer", /overlapping subsections/],
  ["<< /Size 2 >>", "not a dictionary", /malformed trailer dictionary/]
] as const) {
  void test("readRevisions records " + message, async () => {
    const issues: string[] = [];
    await readRevisions(open(tableText.replace(original, replacement)), 0, issues);
    assert.match(issues.join("\n"), message);
  });
}
