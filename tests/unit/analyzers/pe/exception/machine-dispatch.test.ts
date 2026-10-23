import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExceptionDirectory } from "../../../../../analyzers/pe/exception/index.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createReadyToRunX86Fixture } from "../../../../helpers/pe-ready-to-run-x86-fixture.js";

const rvaToOff = (rva: number): number => rva;

void test("exception dispatch does not borrow x86 ReadyToRun metadata for AMD64", async () => {
  const fixture = createReadyToRunX86Fixture();
  const parsed = await parseExceptionDirectory(new MockFile(fixture.bytes),
    [{ name: "EXCEPTION", rva: fixture.runtimeFunctionRva, size: 16 }], rvaToOff, 0x8664, fixture.readyToRun);

  assert.equal(parsed?.format, "amd64");
});

void test("exception dispatch retains the ARMNT parser", async () => {
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  view.setUint32(8, 17, true); // Thumb start marker.
  view.setUint32(12, 5 | 1 << 13, true); // Packed length=1 halfword, return by 16-bit branch.
  const parsed = await parseExceptionDirectory(new MockFile(bytes),
    [{ name: "EXCEPTION", rva: 8, size: 8 }], rvaToOff, 0x1c4);

  assert.equal(parsed?.format, "armnt");
  assert.deepEqual(parsed?.beginRvas, [16]);
});

for (const machine of [0xa641, 0xa64e]) {
  void test(`parseExceptionDirectory routes machine ${machine.toString(16)} through ARM64`, async () => {
    const bytes = new Uint8Array(32);
    const view = new DataView(bytes.buffer);
    view.setUint32(8, 16, true);
    view.setUint32(12, 5, true); // ARM64 packed flag=1, function length=1 instruction.
    const parsed = await parseExceptionDirectory(new MockFile(bytes),
      [{ name: "EXCEPTION", rva: 8, size: 8 }], rvaToOff, machine);

    assert.equal(parsed?.format, "arm64");
    assert.deepEqual(parsed?.beginRvas, [16]);
  });
}

for (const directories of [[], [{ name: "OTHER", rva: 8, size: 8 }], [{ name: "EXCEPTION", rva: 0, size: 0 }]]) {
  void test(`unsupported exception machines preserve absent directories: ${JSON.stringify(directories)}`, async () => {
    const parsed = await parseExceptionDirectory(new MockFile(new Uint8Array(16)), directories, rvaToOff, 0xebc);

    assert.equal(parsed, null);
  });
}

for (const [rva, size, message] of [[0, 8, "Exception directory has a non-zero size but RVA is 0."],
  [8, 0, "Exception directory decoding is not implemented for machine 0xebc."],
  [8, 8, "Exception directory decoding is not implemented for machine 0xebc."]] as const) {
  void test(`unsupported exception machines diagnose directory ${rva}/${size}`, async () => {
    const parsed = await parseExceptionDirectory(new MockFile(new Uint8Array(16)),
      [{ name: "EXCEPTION", rva, size }], rvaToOff, 0xebc);

    assert.deepEqual(parsed?.issues, [message]);
  });
}
