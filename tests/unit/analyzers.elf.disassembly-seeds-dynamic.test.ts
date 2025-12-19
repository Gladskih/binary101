"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ElfProgramHeader } from "../../analyzers/elf/types.js";
import { collectElfDisassemblySeedsFromDynamic } from "../../analyzers/elf/disassembly-seeds-dynamic.js";
import { MockFile } from "../helpers/mock-file.js";

const ph = (overrides: Partial<ElfProgramHeader>): ElfProgramHeader =>
  ({
    type: 1,
    typeName: "PT_LOAD",
    offset: 0n,
    vaddr: 0n,
    paddr: 0n,
    filesz: 1n,
    memsz: 1n,
    flags: 0,
    flagNames: [],
    align: 0n,
    index: 0,
    ...overrides
  }) as unknown as ElfProgramHeader;

void test("collectElfDisassemblySeedsFromDynamic reads DT_INIT_ARRAY pointers", async () => {
  const fileBytes = new Uint8Array(0x80);

  // Pointer array at file offset 0x00, mapped at vaddr 0x3000.
  new DataView(fileBytes.buffer).setBigUint64(0, 0x2000n, true);

  // Dynamic table at 0x40 (3 entries * 16 bytes).
  const dyn = new DataView(fileBytes.buffer, 0x40, 0x30);
  dyn.setBigInt64(0x00, 25n, true); // DT_INIT_ARRAY
  dyn.setBigUint64(0x08, 0x3000n, true);
  dyn.setBigInt64(0x10, 27n, true); // DT_INIT_ARRAYSZ
  dyn.setBigUint64(0x18, 8n, true);
  dyn.setBigInt64(0x20, 0n, true); // DT_NULL
  dyn.setBigUint64(0x28, 0n, true);

  const file = new MockFile(fileBytes, "dynamic.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromDynamic({
    file,
    programHeaders: [
      ph({ index: 0, type: 1, flags: 0, offset: 0n, vaddr: 0x3000n, filesz: 8n }),
      ph({ index: 1, type: 2, offset: 0x40n, vaddr: 0x5000n, filesz: 0x30n })
    ],
    is64: true,
    littleEndian: true,
    issues
  });

  const initArray = groups.find(group => group.source === "DT_INIT_ARRAY");
  assert.ok(initArray);
  assert.deepEqual(initArray?.vaddrs, [0x2000n]);
});

void test("collectElfDisassemblySeedsFromDynamic reads function symbols from DT_SYMTAB using DT_HASH", async () => {
  const fileBytes = new Uint8Array(0x200);

  // DT_HASH table at vaddr 0x3200 => file offset 0x100.
  const hash = new DataView(fileBytes.buffer, 0x100, 8);
  hash.setUint32(0, 1, true); // nbucket
  hash.setUint32(4, 1, true); // nchain

  // Dynsym at vaddr 0x3100 => file offset 0x120.
  const sym = new DataView(fileBytes.buffer, 0x120, 24);
  sym.setUint8(4, 0x12); // STT_FUNC
  sym.setUint16(6, 1, true); // defined
  sym.setBigUint64(8, 0x2000n, true); // st_value

  // Dynamic table at vaddr doesn't matter; file offset 0x180.
  const dyn = new DataView(fileBytes.buffer, 0x180, 0x40);
  dyn.setBigInt64(0x00, 4n, true); // DT_HASH
  dyn.setBigUint64(0x08, 0x3200n, true);
  dyn.setBigInt64(0x10, 6n, true); // DT_SYMTAB
  dyn.setBigUint64(0x18, 0x3100n, true);
  dyn.setBigInt64(0x20, 11n, true); // DT_SYMENT
  dyn.setBigUint64(0x28, 24n, true);
  dyn.setBigInt64(0x30, 0n, true); // DT_NULL
  dyn.setBigUint64(0x38, 0n, true);

  const file = new MockFile(fileBytes, "dynsym-dynamic.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromDynamic({
    file,
    programHeaders: [
      ph({ index: 0, type: 1, flags: 0, offset: 0x100n, vaddr: 0x3200n, filesz: 8n }),
      ph({ index: 1, type: 1, flags: 0, offset: 0x120n, vaddr: 0x3100n, filesz: 24n }),
      ph({ index: 2, type: 2, offset: 0x180n, vaddr: 0x5000n, filesz: 0x40n })
    ],
    is64: true,
    littleEndian: true,
    issues
  });

  const symtab = groups.find(group => group.source === "DT_SYMTAB (function symbols)");
  assert.ok(symtab);
  assert.deepEqual(symtab?.vaddrs, [0x2000n]);
});

void test("collectElfDisassemblySeedsFromDynamic reads DT_INIT/DT_FINI pointer tags", async () => {
  const fileBytes = new Uint8Array(0x60);

  const dyn = new DataView(fileBytes.buffer, 0x20, 0x30);
  dyn.setBigInt64(0x00, 12n, true); // DT_INIT
  dyn.setBigUint64(0x08, 0x1234n, true);
  dyn.setBigInt64(0x10, 13n, true); // DT_FINI
  dyn.setBigUint64(0x18, 0x5678n, true);
  dyn.setBigInt64(0x20, 0n, true); // DT_NULL
  dyn.setBigUint64(0x28, 0n, true);

  const file = new MockFile(fileBytes, "dyn-pointers.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromDynamic({
    file,
    programHeaders: [
      ph({ index: 0, type: 1, flags: 0, offset: 0n, vaddr: 0x3000n, filesz: 1n }),
      ph({ index: 1, type: 2, offset: 0x20n, vaddr: 0x5000n, filesz: 0x30n })
    ],
    is64: true,
    littleEndian: true,
    issues
  });

  assert.deepEqual(
    groups.map(group => group.source).sort(),
    ["DT_FINI", "DT_INIT"]
  );
  assert.deepEqual(groups.find(group => group.source === "DT_INIT")?.vaddrs, [0x1234n]);
  assert.deepEqual(groups.find(group => group.source === "DT_FINI")?.vaddrs, [0x5678n]);
});

void test("collectElfDisassemblySeedsFromDynamic reports pointer arrays outside PT_LOAD segments", async () => {
  const fileBytes = new Uint8Array(0x60);

  const dyn = new DataView(fileBytes.buffer, 0x20, 0x30);
  dyn.setInt32(0x00, 25, true); // DT_INIT_ARRAY
  dyn.setUint32(0x04, 0x3000, true);
  dyn.setInt32(0x08, 27, true); // DT_INIT_ARRAYSZ
  dyn.setUint32(0x0c, 4, true);
  dyn.setInt32(0x10, 0, true); // DT_NULL
  dyn.setUint32(0x14, 0, true);

  const file = new MockFile(fileBytes, "dyn-missing-load.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromDynamic({
    file,
    programHeaders: [
      ph({ index: 0, type: 1, flags: 0, offset: 0n, vaddr: 0x1000n, filesz: 0x10n }),
      ph({ index: 1, type: 2, offset: 0x20n, vaddr: 0x5000n, filesz: 0x18n })
    ],
    is64: false,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 0);
  assert.ok(issues.some(issue => issue.includes("DT_INIT_ARRAY does not map into a PT_LOAD segment.")));
});

void test("collectElfDisassemblySeedsFromDynamic warns on truncated/misaligned pointer arrays", async () => {
  const fileBytes = new Uint8Array(0x80);
  new DataView(fileBytes.buffer).setUint32(0x7b, 0x2000, true);

  const dyn = new DataView(fileBytes.buffer, 0x20, 0x18);
  dyn.setInt32(0x00, 25, true); // DT_INIT_ARRAY
  dyn.setUint32(0x04, 0x3000, true);
  dyn.setInt32(0x08, 27, true); // DT_INIT_ARRAYSZ
  dyn.setUint32(0x0c, 6, true);
  dyn.setInt32(0x10, 0, true); // DT_NULL
  dyn.setUint32(0x14, 0, true);

  const file = new MockFile(fileBytes, "dyn-array-truncated.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromDynamic({
    file,
    programHeaders: [
      ph({ index: 0, type: 1, flags: 0, offset: 0x7bn, vaddr: 0x3000n, filesz: 5n }),
      ph({ index: 1, type: 2, offset: 0x20n, vaddr: 0x5000n, filesz: 0x18n })
    ],
    is64: false,
    littleEndian: true,
    issues
  });

  const initArray = groups.find(group => group.source === "DT_INIT_ARRAY");
  assert.ok(initArray);
  assert.deepEqual(initArray?.vaddrs, [0x2000n]);
  assert.ok(issues.some(issue => issue.includes("DT_INIT_ARRAY extends past end of file; truncating")));
  assert.ok(issues.some(issue => issue.includes("DT_INIT_ARRAY size is not aligned to pointer size")));
});

void test("collectElfDisassemblySeedsFromDynamic reads 32-bit function symbols from DT_SYMTAB", async () => {
  const fileBytes = new Uint8Array(0x200);

  const hash = new DataView(fileBytes.buffer, 0x120, 8);
  hash.setUint32(0, 1, true); // nbucket
  hash.setUint32(4, 4, true); // nchain

  const sym = new DataView(fileBytes.buffer, 0x100, 0x40);
  sym.setUint32(0x04, 0x2000, true);
  sym.setUint8(0x0c, 0x12); // STT_FUNC, defined
  sym.setUint16(0x0e, 1, true);

  sym.setUint32(0x10 + 0x04, 0x1111, true);
  sym.setUint8(0x10 + 0x0c, 0x11); // STT_OBJECT
  sym.setUint16(0x10 + 0x0e, 1, true);

  sym.setUint32(0x20 + 0x04, 0x2222, true);
  sym.setUint8(0x20 + 0x0c, 0x12); // STT_FUNC, undefined
  sym.setUint16(0x20 + 0x0e, 0, true);

  sym.setUint32(0x30 + 0x04, 0, true); // STT_FUNC, zero value
  sym.setUint8(0x30 + 0x0c, 0x12);
  sym.setUint16(0x30 + 0x0e, 1, true);

  const dyn = new DataView(fileBytes.buffer, 0x180, 0x20);
  dyn.setInt32(0x00, 4, true); // DT_HASH
  dyn.setUint32(0x04, 0x3200, true);
  dyn.setInt32(0x08, 6, true); // DT_SYMTAB
  dyn.setUint32(0x0c, 0x3100, true);
  dyn.setInt32(0x10, 11, true); // DT_SYMENT
  dyn.setUint32(0x14, 16, true);
  dyn.setInt32(0x18, 0, true); // DT_NULL
  dyn.setUint32(0x1c, 0, true);

  const file = new MockFile(fileBytes, "dynsym32.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromDynamic({
    file,
    programHeaders: [
      ph({ index: 0, type: 1, flags: 0, offset: 0x120n, vaddr: 0x3200n, filesz: 8n }),
      ph({ index: 1, type: 1, flags: 0, offset: 0x100n, vaddr: 0x3100n, filesz: 0x40n }),
      ph({ index: 2, type: 2, offset: 0x180n, vaddr: 0x5000n, filesz: 0x20n })
    ],
    is64: false,
    littleEndian: true,
    issues
  });

  const symtab = groups.find(group => group.source === "DT_SYMTAB (function symbols)");
  assert.ok(symtab);
  assert.deepEqual(symtab?.vaddrs, [0x2000n]);
});

