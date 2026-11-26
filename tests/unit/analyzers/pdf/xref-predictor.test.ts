import assert from "node:assert/strict";
import { test } from "node:test";
import { readXrefPredictor, undoXrefPredictor } from "../../../../analyzers/pdf/xref-predictor.js";

void test("unfilters all PNG row filters in a single stream", () => {
  const encoded = Uint8Array.of(0, 3, 7, 1, 4, 5, 2, 1, 3, 3, 1, 9, 4, 7, 8);
  const predictor = readXrefPredictor("<< /Predictor 15 /Columns 2 >>", 2);
  const decoded = undoXrefPredictor(encoded, predictor, 10);
  assert.deepEqual([...decoded], [3, 7, 4, 9, 5, 12, 3, 16, 10, 24]);
});

void test("unfilters TIFF horizontal differences including byte wrap", () => {
  const predictor = readXrefPredictor("<< /Predictor 2 /Columns 3 >>", 3);
  const decoded = undoXrefPredictor(Uint8Array.of(250, 10, 20, 1, 2, 3), predictor, 6);
  assert.deepEqual([...decoded], [250, 4, 24, 1, 3, 6]);
});

for (const [token, message] of [
  ["4 0 R", /invalid \/DecodeParms/],
  ["<< /Predictor 8 >>", /unsupported predictor/],
  ["<< /Predictor 15 /Columns 0 >>", /geometry/],
  ["<< /Predictor 2 /Colors 2 >>", /geometry/],
  ["<< /Predictor 2 /BitsPerComponent 1 >>", /geometry/]
] as const) {
  void test("rejects " + token + " as predictor parameters", () => {
    assert.throws(() => readXrefPredictor(token, 2), message);
  });
}

void test("rejects partial predictor rows and unknown PNG row tags", () => {
  const predictor = readXrefPredictor("<< /Predictor 15 /Columns 2 >>", 2);
  assert.throws(() => undoXrefPredictor(Uint8Array.of(1, 5, 6), predictor, 3), /row layout/);
  assert.throws(() => undoXrefPredictor(Uint8Array.of(5, 5, 6), predictor, 2), /row filter/);
});

void test("raw xref stream bytes use predictor 1 for explicit and default decode parameters", () => {
  const bytes = Uint8Array.of(1, 0, 2, 4);
  for (const token of ["<< >>", "<< /Predictor 1 >>", undefined, "null"]) {
    const predictor = readXrefPredictor(token, 2);
    assert.deepEqual(predictor, { operation: 1, columns: 2 });
    assert.deepEqual(undoXrefPredictor(bytes, predictor, 4), bytes);
  }
});

void test("PNG predictor 10 uses a leading filter byte and handles row boundaries", () => {
  const bytes = Uint8Array.of(0, 12, 66, 0, 88, 2);
  assert.deepEqual([...undoXrefPredictor(bytes, readXrefPredictor("<< /Predictor 10 /Columns 2 >>", 2), 4)],
    [12, 66, 88, 2]);
});

void test("Paeth predicts separate left, above and upper-left values", () => {
  // PNG 9.4: Paeth gives ties to the left, then above, and otherwise the upper-left sample.
  const predictor = readXrefPredictor("<< /Predictor 14 /Columns 2 >>", 2);
  assert.deepEqual([...undoXrefPredictor(Uint8Array.of(0, 2, 4, 4, 2, 1), predictor, 4)], [2, 4, 4, 5]);
  assert.deepEqual([...undoXrefPredictor(Uint8Array.of(0, 2, 1, 4, 2, 1), predictor, 4)], [2, 1, 4, 5]);
  assert.deepEqual([...undoXrefPredictor(Uint8Array.of(0, 3, 1, 4, 1, 1), predictor, 4)], [3, 1, 4, 2]);
  assert.deepEqual([...undoXrefPredictor(Uint8Array.of(0, 3, 0, 4, 3, 1), predictor, 4)], [3, 0, 6, 4]);
});
