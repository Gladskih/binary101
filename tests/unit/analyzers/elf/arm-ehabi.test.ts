import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfArmEhabi } from "../../../../analyzers/elf/arm-ehabi.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

const fixture = () => {
  const source = relocationFixture(32);
  source.elf.header.machine = 40; // EM_ARM, Arm ELF ABI.
  source.elf.header.type = 2;
  source.elf.sections = [relocationSection(1, { type: 0x70000001, offset: 64n,
    addr: 0x1040n, size: 16n }), relocationSection(2, { name: ".ARM.extab", offset: 128n,
    addr: 0x1080n, size: 16n })];
  source.word(64, 0x7fffffc0n); // PREL31: function at 0x1000, before exidx.
  source.word(68, 0x80a9b0b0n); // Inline compact personality 0: pop r4,r5,lr; finish.
  source.word(72, 0x7fffffc8n);
  source.word(76, 1n); // EXIDX_CANTUNWIND.
  return source;
};

void test("decodes linked exidx addresses, compact bytecode and CANTUNWIND", async () => {
  const source = fixture();
  const table = (await parseElfArmEhabi(source.file(), source.elf))[0]!;
  assert.deepEqual(table.issues, []);
  assert.equal(table.entries[0]?.functionAddress, 0x1000n);
  assert.equal(table.entries[0]?.personality, 0);
  assert.equal(table.entries[0]?.instructions[0]?.text, "pop {r4, r5, r14}");
  assert.equal(table.entries[1]?.instructions[0]?.text, "cannot unwind");
});

void test("follows extab PREL31 and reads long compact programs", async () => {
  const source = fixture();
  source.word(68, 0x3cn); // extab at 0x1080, relative to word at 0x1044.
  source.word(128, 0x81010000n); // Personality 1, one additional opcode word.
  source.word(132, 0xa9b0b0b0n);
  const entry = (await parseElfArmEhabi(source.file(), source.elf))[0]!.entries[0]!;
  assert.equal(entry.tableAddress, 0x1080n);
  assert.equal(entry.personality, 1);
  assert.deepEqual(entry.instructions.map(item => item.text),
    ["vsp += 4", "vsp += 4", "pop {r4, r5, r14}", "finish"]);
  assert.deepEqual(entry.issues, []);
});

void test("reports unresolved relocations, bad formats and unavailable extab", async () => {
  const source = fixture();
  source.elf.header.type = 1;
  let entry = (await parseElfArmEhabi(source.file(), source.elf))[0]!.entries[0]!;
  assert.equal(entry.functionAddress, null);
  assert.match(entry.issues.join(" "), /relocation/);
  source.elf.header.type = 2;
  source.word(68, 0x83000000n);
  entry = (await parseElfArmEhabi(source.file(), source.elf))[0]!.entries[0]!;
  assert.match(entry.issues.join(" "), /personality/);
  source.word(68, 0x10000n);
  entry = (await parseElfArmEhabi(source.file(), source.elf))[0]!.entries[0]!;
  assert.match(entry.issues.join(" "), /outside/);
});

void test("validates index bounds, compression and ordering", async () => {
  const source = fixture();
  source.word(72, 0x7fffffb0n);
  source.elf.sections[0]!.size = 17n;
  let table = (await parseElfArmEhabi(source.file(), source.elf))[0]!;
  assert.match(table.issues.join(" "), /multiple of 8/);
  assert.match(table.issues.join(" "), /order/);
  source.elf.sections[0]!.flags = 0x800n;
  table = (await parseElfArmEhabi(source.file(), source.elf))[0]!;
  assert.match(table.issues.join(" "), /compressed/);
  source.elf.header.machine = 62;
  assert.deepEqual(await parseElfArmEhabi(source.file(), source.elf), []);
});
void test("reads big-endian segment indexes without section headers", async () => {
  const source = fixture();
  source.elf.littleEndian = false;
  source.elf.sections = [];
  source.view.setUint32(64, 0x7fffffc0, false);
  source.view.setUint32(68, 0x80a9b0b0, false);
  source.elf.programHeaders = [{ index: 0, type: 0x70000001, typeName: null, offset: 64n,
    vaddr: 0x1040n, paddr: 0n, filesz: 8n, memsz: 8n, flags: 4, flagNames: [], align: 4n }];
  const table = (await parseElfArmEhabi(source.file(), source.elf))[0]!;
  assert.equal(table.source, "Segment #0");
  assert.equal(table.entries[0]?.functionAddress, 4096n);
  assert.equal(table.entries[0]?.instructions[0]?.text, "pop {r4, r5, r14}");
});

void test("bounds shared extab descriptions at the next referenced table", async () => {
  const source = fixture();
  source.elf.sections[0]!.size = 24n;
  source.word(68, 0x3cn);
  source.word(76, 0x34n); // Same extab as the preceding index entry.
  source.word(80, 0x7fffffc8n);
  source.word(84, 0x30n); // Next extab begins four bytes after the first.
  source.word(128, 0x8101b0b0n); // Its claimed extra word would consume the next extab.
  source.word(132, 0x80b0b0b0n);
  const entries = (await parseElfArmEhabi(source.file(), source.elf))[0]!.entries;
  assert.match(entries[0]!.issues.join(" "), /Truncated/);
  assert.deepEqual(entries[1]!.issues, entries[0]!.issues);
  assert.equal(entries[2]?.instructions[0]?.text, "finish");
});

void test("rejects unaligned extab pointers and reserved function address bits", async () => {
  const source = fixture();
  source.word(64, 0x80000000n);
  source.word(68, 0x3dn);
  const entry = (await parseElfArmEhabi(source.file(), source.elf))[0]!.entries[0]!;
  assert.match(entry.issues.join(" "), /Reserved/);
  assert.match(entry.issues.join(" "), /unaligned/);
  source.elf.sections[0]!.offset = 1n << 60n;
  assert.match((await parseElfArmEhabi(source.file(), source.elf))[0]!.issues.join(" "), /outside/);
});
void test("does not decode compressed extab through an overlapping load segment", async () => {
  const source = fixture();
  source.word(68, 0x3cn);
  source.word(128, 0x80b0b0b0n);
  source.elf.sections[1]!.flags = 0x800n;
  source.elf.programHeaders = [{ index: 0, type: 1, typeName: null, offset: 0n, vaddr: 4096n,
    paddr: 0n, filesz: 1024n, memsz: 1024n, flags: 4, flagNames: [], align: 4n }];
  assert.match((await parseElfArmEhabi(source.file(), source.elf))[0]!.entries[0]!.issues.join(" "), /outside/);
});
void test("decodes extab through file-backed PT_LOAD when section headers are absent", async () => {
  const source = fixture();
  source.elf.sections = [];
  source.word(68, 0x3cn);
  source.word(128, 0x80b0b0b0n);
  source.elf.programHeaders = [
    { index: 0, type: 0x70000001, typeName: null, offset: 64n, vaddr: 0x1040n,
      paddr: 0n, filesz: 8n, memsz: 8n, flags: 4, flagNames: [], align: 4n },
    { index: 1, type: 1, typeName: null, offset: 128n, vaddr: 0x1080n,
      paddr: 0n, filesz: 8n, memsz: 8n, flags: 4, flagNames: [], align: 4n }
  ];
  const entry = (await parseElfArmEhabi(source.file(), source.elf))[0]!.entries[0]!;
  assert.deepEqual(entry.descriptors, []);
  assert.deepEqual(entry.issues, []);
  assert.equal(entry.instructions[0]?.text, "finish");
  source.word(68, 0x44n); // At the end of the load segment is outside it.
  assert.match((await parseElfArmEhabi(source.file(), source.elf))[0]!.entries[0]!.issues.join(" "), /outside/);
});

void test("decodes scopes once for shared extab records", async () => {
  const source = fixture();
  source.word(68, 0x3cn);
  source.word(76, 0x34n);
  source.word(128, 0x80b0b0b0n);
  source.word(132, 4n); // 16-bit cleanup length=4, start=0.
  source.word(136, 4n);
  const entries = (await parseElfArmEhabi(source.file(), source.elf))[0]!.entries;
  assert.equal(entries[0]?.descriptors?.[0]?.landingPad, 0x108cn);
  assert.strictEqual(entries[0]?.descriptors, entries[1]?.descriptors);
  source.word(72, 0x7fffffb8n); // Duplicate function address is invalid.
  assert.match((await parseElfArmEhabi(source.file(), source.elf))[0]!.issues.join(" "), /order/);
});

void test("bounds retained index entries", async () => {
  const source = fixture();
  const bytes = new Uint8Array(800008); // One entry above the 100000-entry resource ceiling.
  source.elf.sections = [relocationSection(0, { type: 0x70000001, size: BigInt(bytes.length) })];
  source.elf.header.type = 1;
  const table = (await parseElfArmEhabi(new File([bytes], "large-exidx"), source.elf))[0]!;
  assert.equal(table.entries.length, 100000);
  assert.match(table.issues.join(" "), /entry limit/);
});
