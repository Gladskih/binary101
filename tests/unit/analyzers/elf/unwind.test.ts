import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfUnwind } from "../../../../analyzers/elf/unwind.js";
import { evaluateElfCfi } from "../../../../analyzers/elf/cfi-state.js";
import { elfSegmentUnwindFixture, elfUnwindFixture } from "../../../fixtures/elf-unwind.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

void test("decodes CIE and FDE structures and CFI instructions", async () => {
  const fixture = elfUnwindFixture();
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.cies[0]?.augmentation, "zR");
  assert.equal(result[0]?.cies[0]?.dataAlignment, -8n);
  assert.equal(result[0]?.cies[0]?.returnRegister, 16n);
  assert.equal(result[0]?.fdes[0]?.start?.address, 8192n);
  assert.equal(result[0]?.fdes[0]?.range, 32n);
  assert.equal(result[0]?.fdes[0]?.cieOffset, 0);
  assert.deepEqual(result[0]?.cies[0]?.instructions[0]?.operands, [7n, 8n]);
  assert.deepEqual(result[0]?.fdes[0]?.instructions[1]?.operands, [6n, 2n]);
  assert.deepEqual(result[0]?.issues, []);
});

void test("decodes big endian unwind records", async () => {
  const fixture = elfUnwindFixture("big");
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.fdes[0]?.start?.address, 8192n);
  assert.deepEqual(result[0]?.issues, []);
});

for (const order of ["little", "big"] as const) {
  void test(`finds .eh_frame via PT_GNU_EH_FRAME in a sectionless ${order}-endian ELF`, async () => {
    const fixture = elfSegmentUnwindFixture(order);
    const [unwind] = await parseElfUnwind(fixture.file(), fixture.elf);

    assert.equal(unwind?.sectionIndex, null);
    assert.equal(unwind.programHeaderIndex, 1);
    assert.equal(unwind.cies.length, 1);
    assert.equal(unwind.fdes[0]?.start?.address, 8192n);
    assert.deepEqual(unwind.issues, []);
  });
}

void test("warns when .eh_frame reaches the PT_LOAD boundary without a terminator", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.programHeaders[0]!.filesz = 44n; // Exactly one CIE and FDE fit before the boundary.

  const [unwind] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(unwind?.fdes.length, 1);
  assert.match(unwind.issues.join(" "), /No .eh_frame terminator/);
});

void test("rejects .eh_frame in the zero-filled part of PT_LOAD", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.programHeaders[0]!.memsz += 16n;
  fixture.view.setInt32(132, 5, true);

  const [unwind] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.deepEqual(unwind?.fdes, []);
  assert.match(unwind.issues.join(" "), /file-backed PT_LOAD mapping/);
});

void test("warns when PT_GNU_EH_FRAME omits the frame pointer", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.bytes[129] = 0xff;

  const [unwind] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.deepEqual(unwind?.cies, []);
  assert.match(unwind.issues.join(" "), /does not supply an .eh_frame address/);
});

void test("uses the .eh_frame displacement within PT_LOAD", async () => {
  const fixture = elfSegmentUnwindFixture();
  Object.assign(fixture.elf.programHeaders[0]!, { offset: 48n, vaddr: 4080n, filesz: 88n, memsz: 88n });
  const [unwind] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(unwind?.fdes[0]?.start?.address, 8192n);
  assert.deepEqual(unwind.issues, []);
});

for (const [name, change] of [
  ["outside mapped bytes", { vaddr: 4097n }],
  ["only mapped by PT_NOTE", { type: 4 }],
  ["outside the memory extent", { memsz: 32n }],
  ["outside the file", { offset: 1000n }]
] as const) {
  void test(`rejects sectionless unwind ${name}`, async () => {
    const fixture = elfSegmentUnwindFixture();
    Object.assign(fixture.elf.programHeaders[0]!, change);
    const [unwind] = await parseElfUnwind(fixture.file(), fixture.elf);

    assert.equal(unwind?.fdes.length, 0);
    assert.match(unwind.issues.join(" "), /file-backed PT_LOAD mapping/);
  });
}

void test("warns when load segments disagree about where .eh_frame is stored", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.programHeaders.push({ ...fixture.elf.programHeaders[0]!, index: 2, offset: 192n });
  const [unwind] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(unwind?.fdes.length, 0);
  assert.match(unwind.issues.join(" "), /unambiguous file-backed PT_LOAD mapping/);
});

void test("a truncated PT_GNU_EH_FRAME range reports an issue without opening frames", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.programHeaders[1]!.filesz = BigInt(fixture.bytes.length);
  const [unwind] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.deepEqual(unwind?.cies, []);
  assert.match(unwind.issues.join(" "), /.eh_frame_hdr is truncated/);
});

void test("warns for truncated records", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.sections[1]!.size = 30n;
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.cies.length, 1);
  assert.equal(result[0]?.fdes.length, 0);
  assert.match(result[0]!.issues.join(" "), /truncated/);
});

void test("warns for invalid CIE references", async () => {
  const fixture = elfUnwindFixture();
  fixture.view.setUint32(88, 100, true);
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.fdes.length, 0);
  assert.match(result[0]!.issues.join(" "), /CIE/);
});

void test("warns for unsupported CIE revisions and augmentation", async () => {
  const fixture = elfUnwindFixture();
  fixture.bytes[72] = 9;
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /version/);
  fixture.bytes[72] = 1;
  fixture.bytes[74] = 88;
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /augmentation/);
});

void test("warns on unknown CFI instructions", async () => {
  const fixture = elfUnwindFixture();
  fixture.bytes[101] = 0x3f;
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.match(result[0]!.issues.join(" "), /CFI/);
});

void test("CFI recovery stops at the last known location before an unsupported AArch64 opcode", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.header.machine = 183;
  // Unassigned extended opcode in the Arm DWARF ABI and DWARF 5 Table 7.24.
  fixture.bytes[102] = 0x3f;

  const [section] = await parseElfUnwind(fixture.file(), fixture.elf);
  const evaluation = evaluateElfCfi(section!.cies[0]!, section!.fdes[0]!);

  assert.deepEqual(evaluation.rows.map(row => row.location), [8192n]);
  assert.match(evaluation.issues.join(" "), /FDE.*incomplete.*0x2001/i);
});

void test("AArch64 CFI records PC signing, restores the state, and handles signed factored offsets", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.header.machine = 183;
  fixture.bytes[76] = 4; // CIE code alignment, so an SLEB128 -1 moves back by 4.
  fixture.view.setUint32(84, 24, true); // Extend FDE to fit this instruction sequence.
  fixture.bytes.set([0x41, 0x2c, 0x0a, 0x41, 0x2c, 0x41, 0x0b, 0x41, 0x2b, 2, 0x7f], 101);

  const [section] = await parseElfUnwind(fixture.file(), fixture.elf);
  const evaluation = evaluateElfCfi(section!.cies[0]!, section!.fdes[0]!);

  assert.deepEqual(section!.issues, []);
  assert.deepEqual(evaluation.issues, []);
  assert.deepEqual(evaluation.rows.map(row => [row.location, row.returnAddressState]), [
    [8192n, "unsigned"], [8196n, { signingPc: 8196n }], [8200n, "unsigned"],
    [8204n, { signingPc: 8196n }], [8208n, { signingPc: 8204n }]
  ]);
});

void test("AArch64 CFI stops before a reserved return-address state", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.header.machine = 183;
  fixture.bytes.set([0x41, 0x2b, 3, 0], 101); // Arm DWARF ABI reserves state 3.

  const [section] = await parseElfUnwind(fixture.file(), fixture.elf);
  const evaluation = evaluateElfCfi(section!.cies[0]!, section!.fdes[0]!);

  assert.deepEqual(evaluation.rows.map(row => row.location), [8192n]);
  assert.match(evaluation.issues.join(" "), /invalid CFI instruction AARCH64_set_ra_state/);
});

void test("an incomplete CIE cannot supply initial rules to a complete FDE", async () => {
  const fixture = elfUnwindFixture();
  fixture.bytes[81] = 0x3f; // Unassigned extended CFI opcode in DWARF 5 Table 7.24.

  const [section] = await parseElfUnwind(fixture.file(), fixture.elf);
  const evaluation = evaluateElfCfi(section!.cies[0]!, section!.fdes[0]!);

  assert.deepEqual(evaluation.rows, []);
  assert.match(evaluation.issues.join(" "), /CIE.*incomplete/i);
});

void test("eh_frame set_loc uses the CIE's PC-relative four-byte encoding on ELF64", async () => {
  const fixture = elfUnwindFixture();
  // LLVM libunwind DwarfParser.hpp reads DW_CFA_set_loc in the CIE pointer encoding.
  // The signed four-byte displacement is relative to the operand at section offset 38.
  fixture.bytes[101] = 1;
  fixture.view.setInt32(102, 8200 - (4096 + 38), true);

  const [section] = await parseElfUnwind(fixture.file(), fixture.elf);
  const fde = section!.fdes[0]!;

  assert.deepEqual(section!.issues, []);
  assert.deepEqual(fde.instructions[0]?.operands, [8200n]);
  assert.deepEqual(evaluateElfCfi(section!.cies[0]!, fde).rows.map(row => row.location), [8192n, 8200n]);
});

void test("reads debug_frame CIE identifiers and absolute CIE offsets", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.sections[1]!.name = ".debug_frame";
  fixture.view.setUint32(68, 0xffffffff, true);
  fixture.view.setUint32(88, 0, true);
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.cies.length, 1);
  assert.equal(result[0]?.fdes[0]?.cieOffset, 0);
  assert.deepEqual(result[0]?.issues, []);
});

void test("reports unavailable compressed and relocated unwind data", async () => {
  const fixture = elfUnwindFixture();
  fixture.elf.sections[1]!.flags = 0x800n;
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /Compressed/);
  fixture.elf.sections[1]!.flags = 0n;
  fixture.elf.sections.push(relocationSection(2, { type: 4, info: 1 }));
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /relocations/);
});

void test("rejects reserved record lengths and section ranges outside the file", async () => {
  const fixture = elfUnwindFixture();
  fixture.view.setUint32(64, 0xfffffff0, true);
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /Reserved/);
  fixture.elf.sections[1]!.offset = 1n << 60n;
  assert.match((await parseElfUnwind(fixture.file(), fixture.elf))[0]!.issues.join(" "), /outside/);
});

void test("reads an extended-length eh_frame CIE", async () => {
  const fixture = elfUnwindFixture();
  fixture.bytes.copyWithin(80, 72, 84);
  fixture.view.setUint32(64, 0xffffffff, true);
  fixture.view.setBigUint64(68, 16n, true);
  fixture.view.setUint32(76, 0, true);
  fixture.elf.sections[1]!.size = 28n;
  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.equal(result[0]?.cies[0]?.augmentation, "zR");
  assert.deepEqual(result[0]?.issues, []);
});
