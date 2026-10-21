import assert from "node:assert/strict";
import { test } from "node:test";
import { validateAmd64RuntimeFunction } from "../../../../../../analyzers/pe/exception/amd64/runtime-function-validation.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { legacyU32 } from "../../../../../fixtures/pe-legacy-codeview.js";

const image = () => new MockFile(new Uint8Array(128));
const map = (rva: number) => rva;
const table = (unwind = 16) => new MockFile(Uint8Array.from(
  [4, 8, 77, 8, 12, unwind].flatMap(legacyU32)));

void test("AMD64 validation resolves an indirect row through its separate bounded table source", async () => {
  const result = await validateAmd64RuntimeFunction(image(), 4, 8, 77, 64, 24, map, table());

  assert.deepEqual(result, { issue: null, unwindInfoRva: 16 });
});

void test("AMD64 validation can read an ordinary image table when no separate source is supplied", async () => {
  const bytes = image().data.slice();
  bytes.set(legacyU32(16), 84);

  assert.deepEqual(await validateAmd64RuntimeFunction(new MockFile(bytes), 4, 8, 77, 64, 24, map),
    { issue: null, unwindInfoRva: 16 });
});

void test("AMD64 validation does not invent a low-RVA table extent when its origin is unknown", async () => {
  assert.deepEqual(await validateAmd64RuntimeFunction(image(), 4, 8, 16, undefined, 24, map, table()),
    { issue: null, unwindInfoRva: 16 });
});

for (const [begin, end, unwind, expected] of [
  [8, 8, 16, /BeginAddress/], [4, 8, 0, /zero/], [4, 8, 128, /outside the file/],
  [4, 8, 64, /back into/], [4, 8, 89, /outside the RUNTIME_FUNCTION/], [4, 8, 61, /outside the RUNTIME_FUNCTION/],
  [4, 8, 67, /start of a RUNTIME_FUNCTION/], [128, 132, 16, /BeginAddress.*outside/],
  [4, 129, 16, /EndAddress.*outside/]
] as const) {
  void test(`AMD64 invalid row ${begin}/${end}/${unwind} reports its specific failure`, async () => {
    const result = await validateAmd64RuntimeFunction(image(), begin, end, unwind, 64, 24, map, table());

    assert.equal(result.unwindInfoRva, null);
    assert.match(result.issue ?? "", expected);
  });
}

for (const [missing, field] of [[4, "BeginAddress"], [7, "EndAddress"], [16, "UnwindData"]] as const) {
  void test(`AMD64 validation reports unmapped image reference ${missing}`, async () => {
    const result = await validateAmd64RuntimeFunction(image(), 4, 8, 16, 64, 24,
      rva => rva === missing ? null : rva, table());

    assert.equal(result.unwindInfoRva, null);
    assert.match(result.issue ?? "", new RegExp(`${field} .*does not map`));
    assert.ok(result.issue?.includes(`0x${missing.toString(16)}`));
  });
}

for (const [offset, expected] of [[-1, /outside the file/], [0, null]] as const) {
  void test(`AMD64 validation checks mapped physical file offset ${offset}`, async () => {
    const result = await validateAmd64RuntimeFunction(image(), 4, 8, 16, undefined, 24,
      rva => rva === 4 ? offset : rva, table());

    assert.equal(result.issue === null, expected === null);
    assert.match(result.issue ?? "", expected ?? /^$/);
  });
}

void test("AMD64 validation diagnoses an unknown indirect origin without interpreting arbitrary image bytes", async () => {
  const result = await validateAmd64RuntimeFunction(image(), 4, 8, 77, undefined, 24, map, table());

  assert.equal(result.unwindInfoRva, null);
  assert.match(result.issue ?? "", /origin is unknown/);
});

void test("AMD64 validation terminates indirect cycles", async () => {
  const result = await validateAmd64RuntimeFunction(image(), 4, 8, 77, 64, 24, map, table(77));

  assert.equal(result.unwindInfoRva, null);
  assert.match(result.issue ?? "", /cycle/);
});

void test("AMD64 validation rejects a truncated indirect target", async () => {
  const result = await validateAmd64RuntimeFunction(image(), 4, 8, 77, 64, 24, map,
    new MockFile(table().data.slice(0, 23)));

  assert.equal(result.unwindInfoRva, null);
  assert.match(result.issue ?? "", /could not be read/);
});
