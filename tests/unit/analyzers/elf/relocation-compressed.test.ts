import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { readElfCompressedRelocations } from "../../../../analyzers/elf/relocation-compressed.js";
import { parseElfRelocations } from "../../../../analyzers/elf/relocations.js";
import { encodeElfCompressedSection } from "../../../fixtures/dwarf-compressed-section-fixture.js";
import { relocationFixture, relocationSection, relocationTable } from "../../../fixtures/elf-relocations.js";

const compressedFixture = (bits: 32 | 64, order: "little" | "big", codec: number) => {
  const fixture = relocationFixture(bits, order);
  const width = bits / 8;
  fixture.word(64, 8n);
  fixture.word(64 + width, 1n << BigInt(bits === 64 ? 32 : 8) | 1n);
  fixture.word(64 + width * 2, -4n);
  const bytes = encodeElfCompressedSection(fixture.bytes.slice(64, 64 + width * 3),
    bits === 64 ? "elf64" : "elf32", order, BigInt(width * 3), codec);
  fixture.bytes.set(bytes, 64);
  fixture.elf.sections.push(relocationSection(4, { type: 4, offset: 64n, size: BigInt(bytes.length),
    entsize: BigInt(width * 3), flags: 0x800n, link: 2, info: 1 }));
  return { ...fixture, table: relocationTable({ size: bytes.length, entrySize: width * 3, compressed: true }) };
};

for (const bits of [32, 64] as const) {
  for (const order of ["little", "big"] as const) {
    for (const codec of [1, 2]) { // gABI ELFCOMPRESS_ZLIB / ELFCOMPRESS_ZSTD.
      void test(`compressed ELF${bits} ${order} RELA codec ${codec} preserves logical records`, async () => {
        const fixture = compressedFixture(bits, order, codec);
        const result = await parseElfRelocations(fixture.file(), fixture.elf);
        assert.equal(result?.entries[0]?.offset, 8n);
        assert.equal(result?.entries[0]?.type, 1);
        assert.equal(result?.entries[0]?.addend, -4n);
        assert.equal(result?.entries[0]?.symbol?.name, "target");
        assert.equal(result?.entries[0]?.recordOffset, 0);
        assert.equal(result?.tables[0]?.complete, true);
        assert.deepEqual(result?.issues, []);
      });
    }
  }
}
void test("compressed relocation sections require valid headers and cannot be allocated", async () => {
  const fixture = compressedFixture(64, "little", 1);
  fixture.elf.sections[4]!.flags |= 2n;
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];
  assert.deepEqual(await Array.fromAsync(
    readElfCompressedRelocations(reader, fixture.table, fixture.elf, 0, issues)), []);
  assert.match(issues[0]!, /non-allocated/);
  fixture.elf.sections = [];
  assert.deepEqual(await Array.fromAsync(readElfCompressedRelocations(reader, fixture.table, fixture.elf, 0, [])), []);
});
void test("unsupported compression and truncated payloads never become relocation entries", async () => {
  const fixture = compressedFixture(64, "little", 1);
  fixture.view.setUint32(64, 99, true);
  const result = await parseElfRelocations(fixture.file(), fixture.elf);
  assert.deepEqual(result?.entries, []);
  assert.match(result!.issues.join(" "), /section #4: unsupported ELF compression/);
  const valid = compressedFixture(64, "little", 1);
  const reader = createFileRangeReader(valid.file(), 0, valid.bytes.length);
  const issues: string[] = [];
  assert.deepEqual(await Array.fromAsync(readElfCompressedRelocations({ ...reader,
    readBytes: async () => new Uint8Array() }, valid.table, valid.elf, 0, issues)), []);
  assert.match(issues[0]!, /truncated/);
});
void test("compression decoder failures become visible warnings including non-Error throws", async () => {
  const fixture = compressedFixture(64, "little", 1);
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];
  assert.deepEqual(await Array.fromAsync(readElfCompressedRelocations({ ...reader,
    readBytes: async () => { throw "decode failure"; } }, fixture.table, fixture.elf, 0, issues)), []);
  assert.match(issues[0]!, /decode failure/);
});

void test("corrupt zlib relocation payloads remain incomplete with a visible decoder error", async () => {
  const fixture = compressedFixture(64, "little", 1);
  fixture.bytes.fill(0, 88, 64 + fixture.table.size); // After Elf64_Chdr: corrupt the compressed frame.
  const result = await parseElfRelocations(fixture.file(), fixture.elf);
  assert.deepEqual(result?.entries, []);
  assert.equal(result?.tables[0]?.complete, false);
  assert.match(result!.issues.join(" "), /compressed relocations/);
});

void test("a decompressed partial record leaves the relocation table incomplete", async () => {
  const fixture = compressedFixture(64, "little", 1);
  const bytes = encodeElfCompressedSection(new Uint8Array(25), "elf64", "little");
  fixture.bytes.set(bytes, 64);
  fixture.elf.sections[4]!.size = BigInt(bytes.length);
  const result = await parseElfRelocations(fixture.file(), fixture.elf);
  assert.deepEqual(result?.entries, []);
  assert.equal(result?.tables[0]?.complete, false);
  assert.match(result!.issues.join(" "), /partial record/);
});
