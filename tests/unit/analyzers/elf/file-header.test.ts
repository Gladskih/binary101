import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfFileHeader, isSupportedElfIdent } from "../../../../analyzers/elf/file-header.js";
import { createElfFile } from "../../../fixtures/elf-sample-file.js";
import { parseForUi } from "../../../../analyzers/parse-for-ui.js";

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

    assert.ok(!("incompleteHeader" in result));
    assert.equal(result.header.machine, code);
    assert.equal(result.header.machineName, name);
  });
}

void test("reads the file header independently of the header tables", async () => {
  const result = (await readElfFileHeader(createElfFile()))!;
  assert.ok(!("incompleteHeader" in result));
  assert.equal(result.header.entry, 0x400000n);
  assert.deepEqual(result.sections, []);
  assert.deepEqual(result.programHeaders, []);
  assert.deepEqual(result.issues, []);
  assert.equal(isSupportedElfIdent(result.ident), true);
  assert.equal(isSupportedElfIdent({ ...result.ident, classByte: 0 }), false);
  assert.equal(isSupportedElfIdent({ ...result.ident, dataByte: 0 }), false);
});

void test("preserves available fields when an ELF64 header is truncated", async () => {
  const bytes = new Uint8Array(await createElfFile().arrayBuffer());
  const short = await readElfFileHeader(new File([bytes.subarray(0, 52)], "truncated"));

  assert.ok(short && "incompleteHeader" in short);
  assert.match(short.issues.join(" "), /header is truncated/);
  assert.equal(short.header.entry, 0x400000n);
  assert.equal(short.header.ehsize, undefined);
  assert.equal(short.header.flags, 0);
});

void test("recognizes a complete e_ident without reading beyond it", async () => {
  const identification = createElfFile().slice(0, 16);
  const short = await readElfFileHeader(new File([identification], "ident"));

  assert.ok(short && "incompleteHeader" in short);
  assert.equal(short.ident.classByte, 2);
  assert.equal(short.header.type, undefined);
  assert.equal(short.header.machine, undefined);
  assert.equal(await readElfFileHeader(new File([identification.slice(0, 15)], "short")), null);
});

void test("ELF32 big-endian prefixes retain complete words and skip the trailing partial field", async () => {
  const bytes = new Uint8Array(35);
  const view = new DataView(bytes.buffer);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 1, 2, 1]);
  view.setUint16(16, 1);
  view.setUint16(18, 8);
  view.setUint32(20, 1);
  view.setUint32(24, 0x12345678);
  view.setUint32(28, 52);
  bytes.set([0x12, 0x34, 0x56], 32);
  const short = await readElfFileHeader(new File([bytes], "elf32"));

  assert.ok(short && "incompleteHeader" in short);
  assert.equal(short.header.type, 1);
  assert.equal(short.header.machine, 8);
  assert.equal(short.header.entry, 0x12345678n);
  assert.equal(short.header.phoff, 52n);
  assert.equal(short.header.shoff, undefined);
});

void test("rejects a truncated header whose ELF magic is absent", async () => {
  const bytes = new Uint8Array(await createElfFile().slice(0, 52).arrayBuffer());
  bytes[0] = 0;

  assert.equal(await readElfFileHeader(new File([bytes], "bad-magic")), null);
});

void test("parseForUi retains a truncated ELF header with its recorded machine", async () => {
  const result = await parseForUi(new File([createElfFile().slice(0, 20)], "elf-prefix"));

  assert.equal(result.analyzer, "elf");
  assert.ok("incompleteHeader" in result.parsed);
  assert.equal(result.parsed.header.machine, 62);
  assert.equal(result.parsed.header.entry, undefined);
  assert.match(result.parsed.issues.join(" "), /ELF64 header is truncated/);
});
