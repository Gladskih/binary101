import assert from "node:assert/strict";
import { test } from "node:test";
import { readPageGeometry, readUserUnit } from "../../../../analyzers/pdf/page-geometry.js";

const parent = { mediaBox: [0, 0, 20, 50] as [number, number, number, number],
  cropBox: null, rotation: 180 };

void test("inherits null entries and accepts clockwise and counterclockwise quarter turns", () => {
  const issues: string[] = [];
  assert.deepEqual(readPageGeometry(new Map([["MediaBox", "null"], ["Rotate", "-90"]]),
    parent, issues), { ...parent, rotation: -90 });
  assert.deepEqual(issues, []);
});

void test("keeps invalid geometry unknown and reports each bad field", () => {
  const issues: string[] = [];
  const fields = new Map([["MediaBox", "[0 20 40]"], ["CropBox", "[1 /Fake 4 4]"], ["Rotate", "45"]]);
  assert.deepEqual(readPageGeometry(fields, parent, issues),
    { mediaBox: null, cropBox: null, rotation: null });
  assert.equal(readUserUnit("0", issues), null);
  assert.deepEqual(issues, ["/MediaBox is not a supported four-number page rectangle.",
    "/CropBox is not a supported four-number page rectangle.",
    "Page tree /Rotate is not an integer multiple of 90.", "Page /UserUnit is not a positive number."]);
});

void test("UserUnit accepts positive PDF real syntax and defaults to one when unspecified", () => {
  assert.equal(readUserUnit(undefined, []), 1);
  assert.equal(readUserUnit("null", []), 1);
  assert.equal(readUserUnit("+.5", []), 0.5);
  assert.equal(readUserUnit("1e2", []), null);
  assert.equal(readUserUnit("9".repeat(350), []), null);
});

void test("handles fractional coordinates and rejects malformed box and rotation tokens", () => {
  const issues: string[] = [];
  const fields = new Map([["MediaBox", "[.15 -.32 3.45 5.67]"], ["CropBox", "34 0 R"], ["Rotate", "/Wrong"]]);
  assert.deepEqual(readPageGeometry(fields, parent, issues),
    { mediaBox: [0.15, -0.32, 3.45, 5.67], cropBox: null, rotation: null });
  assert.deepEqual(issues, ["/CropBox is not a supported four-number page rectangle.",
    "Page tree /Rotate is not an integer multiple of 90."]);
});
