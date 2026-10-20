import assert from "node:assert/strict";
import { test } from "node:test";
import { summarizeSequencePoints } from "../../../../../analyzers/pe/debug/portable-pdb-points.js";

void test("sequence points count visible and hidden mappings and document changes", () => {
  // PortablePdb-Metadata.md: local signature, first IL delta, line/column deltas,
  // absolute first visible position; subsequent zero IL delta switches documents.
  const issues: string[] = [];
  const result = summarizeSequencePoints(Uint8Array.from([
    0, 0, 0, 5, 10, 1, 1, 0, 0, 0, 2, 1, 0, 2, 2, 0
  ]), 1, 2, issues);

  assert.deepEqual(result, { visible: 2, hidden: 1 });
  assert.deepEqual(issues, []);
});

void test("sequence points warn on truncated compressed integers", () => {
  const issues: string[] = [];
  const result = summarizeSequencePoints(Uint8Array.from([0, 0, 0x80]), 1, 1, issues);

  assert.deepEqual(result, { visible: 0, hidden: 0 });
  assert.match(issues.join(" | "), /truncated/i);
});

const validPoints = [
  { name: "empty", bytes: [], document: 1, visible: 0, hidden: 0 },
  { name: "zero source line", bytes: [0, 0, 0, 1, 0, 0], document: 1, visible: 1, hidden: 0 },
  { name: "zero multiline end column", bytes: [0, 0, 1, 0x7f, 1, 1],
    document: 1, visible: 1, hidden: 0 },
  { name: "maximum source line", bytes: [0, 0, 0, 1, 0xdf, 0xff, 0xff, 0xff, 0],
    document: 1, visible: 1, hidden: 0 },
  { name: "initial document record", bytes: [0, 1, 0, 0, 0], document: 0, visible: 0, hidden: 1 },
  { name: "hidden before visible", bytes: [0, 0, 0, 0, 1, 0, 5, 10, 1], document: 1, visible: 1, hidden: 1 },
  { name: "negative deltas", bytes: [0, 0, 0, 5, 10, 10, 1, 1, 0x7f, 0x7f, 0x7f],
    document: 1, visible: 2, hidden: 0 },
  // ECMA-335 II.23.2 signed -1 in two-byte and four-byte representations.
  { name: "two-byte signed delta", bytes: [0, 0, 1, 0xbf, 0xff, 10, 2], document: 1, visible: 1, hidden: 0 },
  { name: "four-byte signed delta", bytes: [0, 0, 1, 0xdf, 0xff, 0xff, 0xff, 10, 2],
    document: 1, visible: 1, hidden: 0 }
];
validPoints.forEach(subject => {
  void test(`sequence points support ${subject.name}`, () => {
    const issues: string[] = [];
    const result = summarizeSequencePoints(Uint8Array.from(subject.bytes), subject.document, 1, issues);

    assert.deepEqual(result, { visible: subject.visible, hidden: subject.hidden });
    assert.deepEqual(issues, []);
  });
});

const invalidPoints = [
  { name: "missing points", bytes: [0], document: 1, pattern: /no sequence points/ },
  { name: "nil document", bytes: [0, 0, 0, 0, 0], document: 0, pattern: /document index/ },
  { name: "invalid initial document", bytes: [0, 0, 0, 0], document: 2, pattern: /document index/ },
  { name: "invalid changed document", bytes: [0, 0, 0, 0, 0, 2], document: 1, pattern: /document index/ },
  { name: "invalid source column", bytes: [0, 0, 0, 1, 10, 0xc0, 1, 0, 0],
    document: 1, pattern: /source position/ },
  { name: "negative end column", bytes: [0, 0, 1, 0x7f, 10, 0], document: 1, pattern: /source position/ },
  { name: "hidden line marker", bytes: [0, 0, 0, 1, 0xc0, 0xfe, 0xef, 0xee, 0],
    document: 1, pattern: /source position/ },
  { name: "IL offset overflow", bytes: [0, 0xdf, 0xff, 0xff, 0xff, 0, 0, 1, 0, 0],
    document: 1, pattern: /IL offset is out of range/ },
  { name: "negative source line", bytes: [0, 0, 0, 1, 0, 0, 1, 0, 1, 0x7f, 0],
    document: 1, pattern: /source position/ },
  { name: "negative source column", bytes: [0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0x7f],
    document: 1, pattern: /source position/ },
  { name: "source line range overflow", bytes: [0, 0, 1, 0, 0xdf, 0xff, 0xff, 0xff, 0],
    document: 1, pattern: /source position/ },
  { name: "hidden end line marker", bytes: [0, 0, 1, 0, 0xc0, 0xfe, 0xef, 0xed, 0],
    document: 1, pattern: /source position/ },
  { name: "end column overflow", bytes: [0, 0, 0, 1, 1, 0xc0, 0, 0xff, 0xff],
    document: 1, pattern: /source position/ }
];
invalidPoints.forEach(subject => {
  void test(`sequence points diagnose ${subject.name}`, () => {
    const issues: string[] = [];
    summarizeSequencePoints(Uint8Array.from(subject.bytes), subject.document, 1, issues);

    assert.match(issues.join(" | "), subject.pattern);
  });
});
