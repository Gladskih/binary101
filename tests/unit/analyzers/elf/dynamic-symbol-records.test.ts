import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { selectElfBinaryLayout } from "../../../../analyzers/elf/binary-layout.js";
import {
  createElfDynamicSymbolNameReader, readElfDynamicSymbolRecords
} from "../../../../analyzers/elf/dynamic-symbol-records.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

const captureHashes = () => {
  const hashes: [number, number][] = [];
  const counts: number[] = [];
  return { hashes, counts, claims: (index: number) => index === 1,
    check(index: number, value: number) { hashes.push([index, value]); },
    finish(count: number) { counts.push(count); } };
};

void test("shares cached names between both hash algorithms without carrying state across names", async () => {
  const file = new File([Uint8Array.of(0, 97, 0, 98, 0)], "names");
  const reader = createFileRangeReader(file, 0, file.size);
  const gnu = captureHashes();
  const sysv = captureHashes();
  const issues: string[] = [];
  const read = createElfDynamicSymbolNameReader({ offset: 0, size: file.size }, reader, issues,
    { gnu, sysv });
  const symbol = (index: number, nameOffset: number) => ({
    index, record: { nameOffset, value: 0n, size: 0n, info: 0, other: 0, sectionIndex: 0 }
  });

  assert.equal(await read(symbol(1, 1)), "a");
  assert.equal(await read(symbol(2, 1)), "a");
  assert.equal(await read(symbol(3, 3)), "b");
  assert.equal(await read(symbol(4, 5)), null);

  // GNU hash: 5381 * 33 + byte. System V hash of a single byte is the byte itself.
  assert.deepEqual(gnu.hashes, [[1, 177670], [2, 177670], [3, 177671]]);
  assert.deepEqual(sysv.hashes, [[1, 97], [2, 97], [3, 98]]);
  assert.match(issues.join(" "), /invalid string table offset/);
});

void test("keeps otherwise hidden records only when referenced by a hash", async () => {
  const fixture = relocationFixture();
  const section = fixture.elf.sections[2]!;
  fixture.bytes[284] = 3; // Elf64_Sym.st_info: STT_SECTION is omitted from the report.
  const file = fixture.file();
  const reader = createFileRangeReader(file, 0, file.size);
  const range = { offset: Number(section.offset), size: Number(section.size) };
  const layout = selectElfBinaryLayout(fixture.elf);

  const unclaimed = await readElfDynamicSymbolRecords(range, layout, [], reader,
    { gnu: undefined, sysv: undefined });
  const claimed = await readElfDynamicSymbolRecords(range, layout, [], reader,
    { gnu: undefined, sysv: captureHashes() });

  assert.deepEqual(unclaimed.map(record => record.index), [0]);
  assert.deepEqual(claimed.map(record => record.index), [0, 1]);
});

void test("skips the complete-count check when the symbol reader encounters truncation", async () => {
  const layout = selectElfBinaryLayout(relocationFixture().elf);
  const file = new File([new Uint8Array(layout.symbolEntrySize)], "truncated-symbols");
  const reader = createFileRangeReader(file, 0, file.size);
  const gnu = captureHashes();
  const issues: string[] = [];

  const records = await readElfDynamicSymbolRecords({ offset: 0, size: file.size * 2 },
    layout, issues, reader, { gnu, sysv: undefined });

  assert.deepEqual(records.map(record => record.index), [0]);
  assert.deepEqual(gnu.counts, []);
  assert.deepEqual(issues, ["Dynamic symbol #1 is truncated."]);
});
