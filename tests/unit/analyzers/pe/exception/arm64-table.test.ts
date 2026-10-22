import assert from "node:assert/strict";
import { test } from "node:test";
import { parseArm64ExceptionTable, parseArm64ExceptionDirectory } from "../../../../../analyzers/pe/exception/arm64.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createArm64LinkChain } from "../../../../fixtures/pe-arm64-links.js";

for (const machine of [0xaa64, 0xa641, 0xa64e]) {
  void test(`ARM64 machine ${machine} decodes a raw copy without an origin`, async () => {
    const { parseExceptionDebugInfo } = await import("../../../../../analyzers/pe/debug/exception.js");
    const { file, directory, code } = createArm64LinkChain(0);
    const parsed = await parseExceptionDebugInfo(file, rva => rva, 0, directory.rva,
      directory.size, machine, assert.fail);

    assert.deepEqual(parsed?.beginRvas, [code]);
    assert.deepEqual(parsed?.rangeLengths, [4]);
    assert.deepEqual(parsed?.issues, []);
  });
}

for (const origin of [undefined, 64]) {
  void test(`ARM64 table resolves parent links with origin ${origin}`, async () => {
    const { file, directory, code } = createArm64LinkChain(1);
    const source = new MockFile(file.data.subarray(directory.rva, directory.rva + directory.size));
    const parsed = await parseArm64ExceptionTable(file, source, directory.size, rva => rva, origin);

    assert.deepEqual(parsed.beginRvas, [code, code + 4]);
    assert.deepEqual(parsed.rangeLengths, [4]);
    assert.equal(parsed.chainedUnwindInfoCount, 1);
    assert.deepEqual(parsed.issues, []);
  });
}

for (const [size, expected] of [
  [NaN, ["Exception directory size is not a multiple of ARM64 .pdata entry size (8 bytes).",
    "RUNTIME_FUNCTION entry count is invalid.", "Exception directory does not contain a complete ARM64 .pdata entry."]],
  [Infinity, ["Exception directory size is not a multiple of ARM64 .pdata entry size (8 bytes).",
    "RUNTIME_FUNCTION entry count is invalid.", "Exception directory does not contain a complete ARM64 .pdata entry."]],
  [7, ["Exception directory size is smaller than one ARM64 .pdata entry (8 bytes)."]],
  [8, ["Exception directory is truncated; some ARM64 .pdata entries are missing.",
    "Exception directory does not contain a complete ARM64 .pdata entry."]],
  [9, ["Exception directory size is not a multiple of ARM64 .pdata entry size (8 bytes).",
    "Exception directory is truncated; some ARM64 .pdata entries are missing.",
    "Exception directory does not contain a complete ARM64 .pdata entry."]],
  [16, ["Exception directory is truncated; some ARM64 .pdata entries are missing.",
    "Exception directory does not contain a complete ARM64 .pdata entry."]]
] as const) {
  void test(`ARM64 table diagnoses an empty source with declared size ${size}`, async () => {
    const file = new MockFile(new Uint8Array(0));
    const parsed = await parseArm64ExceptionTable(file, file, size, () => null);

    assert.equal(parsed.functionCount, 0);
    assert.deepEqual(parsed.issues, expected);
  });
}

for (const [rva, size, mapped, expected] of [
  [0, 0, 0, null], [0, 8, 0, ["Exception directory has a non-zero size but RVA is 0."]],
  [8, 8, null, ["Exception directory RVA could not be mapped to a file offset."]],
  [8, 8, -1, ["Exception directory location is outside the file."]],
  [8, 8, 16, ["Exception directory location is outside the file."]],
  [8, 0, 0, ["Exception directory size is smaller than one ARM64 .pdata entry (8 bytes)."]]
] as const) {
  void test(`ARM64 directory validates location ${rva}, ${size}, ${mapped}`, async () => {
    const file = new MockFile(new Uint8Array(16));
    const parsed = await parseArm64ExceptionDirectory(file,
      [{ name: "EXCEPTION", rva, size }], () => mapped);

    assert.equal(parsed?.functionCount ?? 0, 0);
    assert.deepEqual(parsed?.issues ?? null, expected);
  });
}

void test("ARM64 directory with no EXCEPTION entry is absent", async () => {
  assert.equal(await parseArm64ExceptionDirectory(new MockFile(new Uint8Array(0)), [], () => null), null);
});

void test("ARM64 table reports descending starts once and retains valid rows", async () => {
  const { file, directory, code } = createArm64LinkChain(0);
  const bytes = new Uint8Array(24);
  const view = new DataView(bytes.buffer);
  [code + 8, 5, code + 4, 5, code, 5].forEach((word, index) => view.setUint32(index * 4, word, true));
  const parsed = await parseArm64ExceptionTable(new MockFile(new Uint8Array(file.size + 8)),
    new MockFile(bytes), 24, rva => rva, directory.rva);

  assert.deepEqual(parsed.beginRvas, [code + 8, code + 4, code]);
  assert.deepEqual(parsed.issues, ["ARM64 .pdata entries are not sorted by function start RVA."]);
});

void test("ARM64 table preserves unsupported xdata versions with a visible diagnostic", async () => {
  const bytes = new Uint8Array(64);
  const view = new DataView(bytes.buffer);
  view.setUint32(8, 32, true);
  view.setUint32(12, 48, true);
  view.setUint32(48, 1 | (1 << 18) | (1 << 27), true);
  const file = new MockFile(bytes);
  const parsed = await parseArm64ExceptionTable(file, new MockFile(bytes.subarray(8, 16)), 8, rva => rva);

  assert.equal(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.issues, ["1 ARM64 .xdata record(s) have an unexpected version."]);
});

void test("ARM64 raw-copy UI fixture parses through real PE headers and debug dispatch", async () => {
  const { createPeWithRawArm64ExceptionCopy } = await import("../../../../fixtures/pe-debug-file.js");
  const { parsePeHeaders } = await import("../../../../../analyzers/pe/core/index.js");
  const { parseDebugDirectory } = await import("../../../../../analyzers/pe/debug/directory.js");
  const file = createPeWithRawArm64ExceptionCopy();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const parsed = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);

  assert.equal(parsed.entries[0]?.exception?.functionCount, 2);
  assert.equal(parsed.entries[0]?.exception?.invalidEntryCount, 0);
  assert.deepEqual(parsed.entries[0]?.exception?.rangeLengths, [4, 4]);
  assert.equal(parsed.warning, null);
});

void test("ARM64 directory selects EXCEPTION after unrelated directories and accepts file offset zero", async () => {
  const bytes = new Uint8Array(64);
  new DataView(bytes.buffer).setUint32(0, 32, true);
  new DataView(bytes.buffer).setUint32(4, 5, true);
  const parsed = await parseArm64ExceptionDirectory(new MockFile(bytes),
    [{ name: "DEBUG", rva: 40, size: 8 }, { name: "EXCEPTION", rva: 8, size: 8 }],
    rva => rva >= 8 && rva < 16 ? rva - 8 : rva);

  assert.deepEqual(parsed?.beginRvas, [32]);
  assert.deepEqual(parsed?.issues, []);
});

void test("ARM64 equal function starts are sorted", async () => {
  const { file, directory } = createArm64LinkChain(1);
  const bytes = file.data.slice();
  const view = new DataView(bytes.buffer);
  view.setUint32(directory.rva + 8, view.getUint32(directory.rva, true), true);
  const parsed = await parseArm64ExceptionDirectory(new MockFile(bytes), [directory], rva => rva);

  assert.deepEqual(parsed?.issues, []);
});

void test("ARM64 debug dispatch forwards a known origin when the original parent row is unavailable", async () => {
  const { parseExceptionDebugInfo } = await import("../../../../../analyzers/pe/debug/exception.js");
  const { file, directory, code } = createArm64LinkChain(1);
  const bytes = Uint8Array.from([...file.data,
    ...file.data.subarray(directory.rva, directory.rva + directory.size)]);
  const parsed = await parseExceptionDebugInfo(new MockFile(bytes), rva => rva >= code ? rva : null,
    0, file.size, directory.size, 0xaa64, assert.fail, directory);

  assert.equal(parsed?.invalidEntryCount, 0);
  assert.equal(parsed?.chainedUnwindInfoCount, 1);
  assert.deepEqual(parsed?.issues, []);
});
