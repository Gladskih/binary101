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

  assert.equal(entries.length, 0);
  assert.deepEqual(truncated, []);
  assert.match(issues.join(" "), /before an address/);
  assert.match(issues.join(" "), /overflows/);
  assert.match(issues.join(" "), /truncated/);
});

void test("decodes MIPS64 compound r_info instead of applying generic ELF64", async () => {
  const fixture = relocationFixture();
  fixture.elf.header.machine = 8; // ELF EM_MIPS.
  fixture.word(72, 0x0212030100000003n); // r_sym=3, ssym=1, types=18/3/2.
  const issues: string[] = [];

  const entries = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable(), fixture.elf, 0, issues));
  assert.equal(entries[0]?.type, 0x01031202);
  assert.equal(entries[0]?.symbolIndex, 3);
  assert.deepEqual(issues, []);
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

void test("packed truncation and trailing bytes become warnings with complete records retained", async () => {
  const fixture = relocationFixture();
  fixture.bytes.set([12, 0, 99], 64); // One explicit CREL with no deltas, then an extra byte.
  const issues: string[] = [];
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const entries = await Array.fromAsync(readElfRelocationRecords(reader,
    relocationTable({ encoding: "CREL", size: 3, entrySize: 1 }), fixture.elf, 0, issues));
  const bad = await Array.fromAsync(readElfRelocationRecords(reader,
    relocationTable({ encoding: "ANDROID_REL", size: 1, entrySize: 1 }), fixture.elf, 0, issues));
  assert.equal(entries.length, 1);
  assert.deepEqual(bad, []);
  assert.match(issues.join(" "), /trailing bytes/);
  assert.match(issues.join(" "), /invalid APS2 magic/);
});

void test("DT_CREL discovers its byte count without scanning the segment tail", async () => {
  const fixture = relocationFixture();
  fixture.bytes.set([12, 0, 99], 64);
  const table = relocationTable({ encoding: "CREL", size: 100, entrySize: 1,
    sources: ["DT_CREL"], sectionIndex: null });
  const issues: string[] = [];
  const entries = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), table, fixture.elf, 0, issues));
  assert.equal(entries.length, 1);
  assert.equal(table.size, 2);
  assert.deepEqual(issues, []);
});

for (const fields of [{ entrySize: 0 }, { offset: -1 }, { size: -1 }, { size: NaN },
  { entrySize: 8 }, { size: 25 }]) {
  void test(`malformed record geometry never loops or crosses a partial table: ${Object.keys(fields)}`, async () => {
    const fixture = relocationFixture();
    const issues: string[] = [];
    assert.deepEqual(await Array.fromAsync(readElfRelocationRecords(
      createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
      relocationTable(fields), fixture.elf, 0, issues)), []);
    assert.match(issues.join(" "), /invalid/);
  });
}

void test("authenticated RELR decodes sites without pretending its signed pointers are ordinary RELR addends", async () => {
  const fixture = relocationFixture();
  fixture.word(64, 8n);
  const entries = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable({ encoding: "AUTH_RELR", size: 8, entrySize: 8 }), fixture.elf, 0, []));
  assert.deepEqual(entries.map(entry => [entry.offset, entry.type, entry.addend]), [[8n, null, null]]);
});

void test("packed read failures become visible issues even for non-Error throws", async () => {
  const fixture = relocationFixture();
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];
  assert.deepEqual(await Array.fromAsync(readElfRelocationRecords({ ...reader,
    read: async () => { throw "read failure"; } },
  relocationTable({ encoding: "CREL", size: 1, entrySize: 1 }), fixture.elf, 0, issues)), []);
  assert.match(issues[0]!, /read failure/);
});

void test("a RELR bitmap cannot advance past the address space even with a valid preceding slot", async () => {
  const fixture = relocationFixture(32);
  fixture.word(64, 0xfffffff8n);
  fixture.word(68, 3n);
  const issues: string[] = [];
  const entries = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable({ encoding: "RELR", size: 8, entrySize: 4 }), fixture.elf, 0, issues));
  assert.deepEqual(entries.map(entry => entry.offset), [0xfffffff8n]);
  assert.match(issues[0]!, /bitmap overflows/);
});

void test("APS2 grouped explicit addend applies once and preserves repeated sites", async () => {
  const fixture = relocationFixture();
  // LLVM APS2: magic, count=2, initial offset=0, group count=2, flags=15,
  // grouped offset delta=8, info=8 (R_X86_64_RELATIVE), addend delta=-4.
  fixture.bytes.set([65, 80, 83, 50, 2, 0, 2, 15, 8, 8, 0x7c], 64);
  const issues: string[] = [];
  const entries = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable({ encoding: "ANDROID_RELA", size: 11, entrySize: 1 }), fixture.elf, 0, issues));
  assert.deepEqual(entries.map(entry => [entry.offset, entry.type, entry.addend]),
    [[8n, 8, -4n], [16n, 8, -4n]]);
  assert.deepEqual(issues, []);
});

void test("CREL explicit deltas retain state, alignment and signed addends", async () => {
  const fixture = relocationFixture();
  // LLVM CREL header: count=2, explicit addends, offset shift=2.
  // First record delta=2, all fields change; second delta=1, no fields change.
  fixture.bytes.set([22, 23, 1, 2, 0x7c, 8], 64);
  const issues: string[] = [];
  const entries = await Array.fromAsync(readElfRelocationRecords(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length),
    relocationTable({ encoding: "CREL", size: 6, entrySize: 1 }), fixture.elf, 0, issues));
  assert.deepEqual(entries.map(entry => [entry.offset, entry.symbolIndex, entry.type, entry.addend]),
    [[8n, 1, 2, -4n], [12n, 1, 2, -4n]]);
  assert.deepEqual(issues, []);
});
