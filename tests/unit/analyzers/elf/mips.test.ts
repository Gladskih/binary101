import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfMips } from "../../../../analyzers/elf/mips.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

const fixture = (type: number, size = 24n) => {
  const source = relocationFixture();
  source.elf.header.machine = 8;
  source.elf.sections.push(relocationSection(4, { type, offset: 64n, size }));
  return source;
};

void test("reads MIPS ABI flags and reports unknown versions", async () => {
  const source = fixture(0x7000002a);
  source.view.setUint16(64, 1, true);
  const metadata = (await parseElfMips(source.file(), source.elf))[0]!;
  assert.equal(metadata.abiFlags?.version, 1);
  assert.match(metadata.issues.join(" "), /version/);
  source.elf.sections[4]!.size = 23n;
  assert.match((await parseElfMips(source.file(), source.elf))[0]!.issues.join(" "), /truncated/);
});

void test("selects MIPS32 register info and MIPS64 option payloads", async () => {
  const source = fixture(0x70000006);
  source.elf.is64 = false;
  source.view.setUint32(84, 123, true);
  assert.equal((await parseElfMips(source.file(), source.elf))[0]!.registerInfo?.gpValue, 123n);
  source.elf.sections[4]!.size = 23n;
  assert.match((await parseElfMips(source.file(), source.elf))[0]!.issues.join(" "), /truncated/);
  const options = fixture(0x7000000d, 40n);
  options.bytes.set([1, 40], 64);
  options.word(96, 0x100000001n);
  assert.equal((await parseElfMips(options.file(), options.elf))[0]!.options?.[0]?.registerInfo?.gpValue,
    0x100000001n);
});

void test("finds segment metadata without sections and prefers existing sections", async () => {
  const source = fixture(0x7000002a);
  source.elf.programHeaders.push({ index: 1, type: 0x70000003, typeName: null, offset: 64n,
    vaddr: 0n, paddr: 0n, filesz: 24n, memsz: 24n, flags: 4, flagNames: [], align: 8n });
  assert.equal((await parseElfMips(source.file(), source.elf)).length, 1);
  source.elf.sections = [];
  assert.equal((await parseElfMips(source.file(), source.elf))[0]!.source, "Segment #1");
});

void test("rejects compressed or unavailable metadata and ignores non-MIPS files", async () => {
  const source = fixture(0x7000002a);
  source.elf.littleEndian = false;
  assert.equal((await parseElfMips(source.file(), source.elf))[0]!.abiFlags?.version, 0);
  source.elf.sections[4]!.flags = 0x800n;
  assert.match((await parseElfMips(source.file(), source.elf))[0]!.issues.join(" "), /compressed/);
  source.elf.sections[4]!.offset = 1n << 60n;
  assert.match((await parseElfMips(source.file(), source.elf))[0]!.issues.join(" "), /outside/);
  source.elf.header.machine = 62;
  assert.deepEqual(await parseElfMips(source.file(), source.elf), []);
});
