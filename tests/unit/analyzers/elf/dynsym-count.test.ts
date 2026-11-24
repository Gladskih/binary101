import assert from "node:assert/strict";
import { test } from "node:test";
import { readDynsymCountFromGnuHash, readDynsymCountFromSysvHash } from "../../../../analyzers/elf/dynsym-count.js";
import { createElfGnuHashDynamicFixture } from "../../../fixtures/elf-gnu-hash-file.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";

void test("counts GNU hash symbols when a chain is split between adjacent file-backed loads", async () => {
  const { file, programHeaders: [load] } = createElfGnuHashDynamicFixture();
  const split = 0x9en; // The GNU chain word occupies 0x9c through 0x9f in the fixture.
  const firstSize = split - load!.offset;
  const issues: string[] = [];
  const heads = [{ ...load!, filesz: firstSize, memsz: firstSize },
    { ...load!, index: 1, offset: split, vaddr: load!.vaddr + firstSize,
      filesz: load!.filesz - firstSize, memsz: load!.filesz - firstSize }];

  assert.equal(await readDynsymCountFromGnuHash({ file, programHeaders: heads,
    hashVaddr: 0x3080n, is64: true, littleEndian: true, issues }), 2);
  assert.deepEqual(issues, []);
});

void test("counts SysV hash symbols across a split header and rejects discontinuous storage", async () => {
  const fixture = dynamicRelocationFixture();
  const load = fixture.elf.programHeaders[0]!;
  fixture.view.setUint32(4, 2, true); // SysV nchain, gABI 8.5.
  const issues: string[] = [];
  const next = { ...load, index: 1, offset: 6n, vaddr: load.vaddr + 6n, filesz: 2n, memsz: 2n };
  const image = { file: fixture.file(), programHeaders: [{ ...load, filesz: 6n, memsz: 6n }, next],
    hashVaddr: load.vaddr, littleEndian: true, issues };

  assert.equal(await readDynsymCountFromSysvHash(image), 2);
  assert.deepEqual(issues, []);
  next.offset += 1n;
  assert.equal(await readDynsymCountFromSysvHash(image), null);
  assert.deepEqual(issues, ["DT_HASH table header is truncated."]);
});
