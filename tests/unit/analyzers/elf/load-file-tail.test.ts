import assert from "node:assert/strict";
import { test } from "node:test";
import { elfLoadFileTail } from "../../../../analyzers/elf/load-file-tail.js";
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
