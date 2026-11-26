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
  const result = await readRevisions(open("short"), 100, issues);
  assert.deepEqual(result.revisions, []);
  assert.ok(issues.some(msg => msg.includes("outside the file")));
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
  assert.match(issues.join("\n"), /cycle at \/XRefStm/);
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
