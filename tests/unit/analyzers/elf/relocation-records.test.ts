import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { readElfRelocationRecords } from "../../../../analyzers/elf/relocation-records.js";
import { relocationFixture, relocationTable } from "../../../fixtures/elf-relocations.js";

for (const bits of [32, 64] as const) {
  for (const order of ["little", "big"] as const) {
    void test(`decodes ELF${bits} ${order} RELA signed addends and unknown types`, async () => {
      const fixture = relocationFixture(bits, order);
      const width = bits / 8;
      fixture.word(64, 8n);
      fixture.word(64 + width, (3n << BigInt(bits === 64 ? 32 : 8)) | 0xfan);
      fixture.word(64 + width * 2, -9n);

      const result = await Array.fromAsync(readElfRelocationRecords(
        createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
        relocationTable({ size: width * 3, entrySize: width * 3 }),
        fixture.elf, 2, []));

      assert.equal(result[0]?.addend, -9n);
      assert.equal(result[0]?.symbolIndex, 3);
      assert.equal(result[0]?.type, 250);
      assert.equal(result[0]?.recordOffset, 64);
      assert.equal(result[0]?.tableIndex, 2);
    });

    void test(`decodes ELF${bits} ${order} RELR high bit and consecutive addresses`, async () => {
      const fixture = relocationFixture(bits, order);
      const width = bits / 8;
      fixture.word(64, 0x1000n);
      fixture.word(64 + width, 1n | (1n << BigInt(bits - 1)));
      fixture.word(64 + width * 2, 0x2000n);

      const result = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
        relocationTable({ encoding: "RELR", size: width * 3, entrySize: width }), fixture.elf, 0, []));

      assert.deepEqual(result.map(entry => entry.offset), [0x1000n,
        0x1000n + BigInt((bits - 1) * width), 0x2000n]);
    });
  }
}

void test("rejects an initial bitmap, detects overflow and truncated reads", async () => {
  const fixture = relocationFixture();
  fixture.word(64, 3n);
  fixture.word(72, 0xffff_ffff_ffff_fffen);
  fixture.word(80, 3n);
  const issues: string[] = [];

  const entries = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable({ encoding: "RELR", size: 24, entrySize: 8 }), fixture.elf, 0, issues));
  const truncated = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable({ offset: 1020 }), fixture.elf, 0, issues));

  assert.equal(entries.length, 1);
  assert.deepEqual(truncated, []);
  assert.match(issues.join(" "), /before an address/);
  assert.match(issues.join(" "), /overflows/);
  assert.match(issues.join(" "), /truncated/);
});

void test("does not misinterpret MIPS64 compound r_info as generic ELF64", async () => {
  const fixture = relocationFixture();
  fixture.elf.header.machine = 8; // ELF EM_MIPS.
  const issues: string[] = [];

  assert.deepEqual(await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable(), fixture.elf, 0, issues)), []);
  assert.match(issues.join(" "), /MIPS64/);
});

void test("MIPS64 RELR still uses the generic packed encoding", async () => {
  const fixture = relocationFixture();
  fixture.elf.header.machine = 8;
  fixture.word(64, 0x1000n);
  const issues: string[] = [];

  const entries = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable({ encoding: "RELR", size: 8, entrySize: 8 }), fixture.elf, 0, issues));

  assert.deepEqual(entries.map(entry => entry.offset), [0x1000n]);
  assert.deepEqual(issues, []);
});

void test("a RELR bitmap may end exactly at the ELF address-space boundary", async () => {
  const fixture = relocationFixture(32);
  fixture.word(64, (1n << 32n) - 128n); // 32 four-byte slots, ending at 2^32.
  fixture.word(68, 0x8000_0001n);
  const issues: string[] = [];

  const entries = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable({ encoding: "RELR", size: 8, entrySize: 4 }), fixture.elf, 0, issues));

  assert.deepEqual(entries.map(entry => entry.offset), [0xffff_ff80n, 0xffff_fffcn]);
  assert.deepEqual(issues, []);
});
