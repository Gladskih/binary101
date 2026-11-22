import assert from "node:assert/strict";
import { test } from "node:test";
import { elfLoadFilePrefix, elfLoadFileTail } from "../../../../analyzers/elf/load-file-tail.js";
import { elfSegmentUnwindFixture } from "../../../fixtures/elf-unwind.js";

void test("bounds same-offset load aliases at the shorter file-backed tail", () => {
  const { elf } = elfSegmentUnwindFixture();
  const [load, unwind] = elf.programHeaders;
  const alias = { ...load!, filesz: 16n };
  const address = load!.vaddr + 4n;
  assert.deepEqual(elfLoadFileTail([load!, alias, unwind!], address, elf.fileSize), { offset: 68, size: 12 });
  assert.deepEqual(elfLoadFileTail([alias, load!], load!.vaddr, elf.fileSize), { offset: 64, size: 16 });
  assert.equal(elfLoadFileTail([load!, { ...alias, offset: 65n }], address, elf.fileSize), null);
});

void test("rejects nonloads, zero-fill, memory size violations and tails outside the file", () => {
  const { elf } = elfSegmentUnwindFixture();
  const [load, unwind] = elf.programHeaders;
  const header = load!;
  assert.equal(elfLoadFileTail([unwind!], unwind!.vaddr, elf.fileSize), null);
  assert.equal(elfLoadFileTail([header], header.vaddr - 1n, elf.fileSize), null);
  assert.equal(elfLoadFileTail([{ ...header, memsz: 100n }], header.vaddr + header.filesz, elf.fileSize), null);
  assert.equal(elfLoadFileTail([{ ...header, memsz: 1n }], header.vaddr, elf.fileSize), null);
  assert.equal(elfLoadFileTail([header], header.vaddr, Number(header.offset + header.filesz - 1n)), null);
});

void test("a record prefix is bounded by its requested size, the segment and EOF", () => {
  const { elf } = elfSegmentUnwindFixture();
  const load = elf.programHeaders[0]!;
  const address = load.vaddr + 4n;
  assert.deepEqual(elfLoadFilePrefix([load], address, 8n, elf.fileSize), { offset: 68, size: 8 });
  assert.deepEqual(elfLoadFilePrefix([load], address, 80n, elf.fileSize), { offset: 68, size: 68 });
  assert.deepEqual(elfLoadFilePrefix([load], address, 80n, 78), { offset: 68, size: 10 });
  assert.equal(elfLoadFilePrefix([load], address, 8n, 68), null);
  assert.equal(elfLoadFilePrefix([load], address, 0n, elf.fileSize), null);
  assert.equal(elfLoadFilePrefix([load], address, -1n, elf.fileSize), null);
});

void test("a record prefix requires a consistent file offset across load aliases", () => {
  const { elf } = elfSegmentUnwindFixture();
  const load = elf.programHeaders[0]!;
  const shorter = { ...load, filesz: 16n };
  assert.deepEqual(elfLoadFilePrefix([load, shorter], load.vaddr, 24n, elf.fileSize), { offset: 64, size: 16 });
  assert.equal(elfLoadFilePrefix([load, { ...shorter, offset: 65n }], load.vaddr, 24n, elf.fileSize), null);
  assert.equal(elfLoadFilePrefix([{ ...load, offset: -1n }], load.vaddr, 8n, elf.fileSize), null);
});
