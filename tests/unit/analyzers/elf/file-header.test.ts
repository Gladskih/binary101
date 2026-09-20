import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfFileHeader, isSupportedElfIdent } from "../../../../analyzers/elf/file-header.js";
import { createElfFile } from "../../../fixtures/elf-sample-file.js";

// e_machine offset: https://gabi.xinuos.com/elf/02-eheader.html
// Values: gABI Appendix A and Linux elf-em.h.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf-em.h
for (const [code, name] of [[257, "65816"], [258, "LOONGARCH"],
  [0x9026, "ALPHA (legacy/unofficial)"], [0x5441, "CYGNUS_FRV (legacy/unofficial)"],
  [65535, null]] as const) {
  void test(`decodes machine ${code} without changing its numeric value`, async () => {
    const bytes = new Uint8Array(await createElfFile().arrayBuffer());
    new DataView(bytes.buffer).setUint16(18, code, true);

    const result = (await readElfFileHeader(new File([bytes], "machine.elf")))!;

    assert.equal(result.header.machine, code);
    assert.equal(result.header.machineName, name);
  });
}

void test("reads the file header independently of the header tables", async () => {
  const result = (await readElfFileHeader(createElfFile()))!;
  assert.equal(result.header.entry, 0x400000n);
  assert.deepEqual(result.sections, []);
  assert.deepEqual(result.programHeaders, []);
  assert.deepEqual(result.issues, []);
  assert.equal(isSupportedElfIdent(result.ident), true);
  assert.equal(isSupportedElfIdent({ ...result.ident, classByte: 0 }), false);
  assert.equal(isSupportedElfIdent({ ...result.ident, dataByte: 0 }), false);
});

void test("returns a diagnostic header for truncated ELF64 and rejects short non-ELF data", async () => {
  const bytes = new Uint8Array(await createElfFile().arrayBuffer());
  const short = await readElfFileHeader(new File([bytes.subarray(0, 52)], "truncated"));
  assert.match(short!.issues.join(" "), /header is truncated/);
  assert.equal(short!.header.ehsize, 0);
  assert.equal(await readElfFileHeader(new File([bytes.subarray(0, 16)], "ident")), null);
  bytes[0] = 0;
  assert.equal(await readElfFileHeader(new File([bytes], "bad-magic")), null);
});
