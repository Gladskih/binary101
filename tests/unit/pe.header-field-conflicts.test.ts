"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeHeaderFieldWarnings } from "../../analyzers/pe/layout/header-field-warnings.js";
import { createWindowsLayoutSubject } from "../fixtures/pe-layout-warning-subject.js";

// Microsoft PE/COFF file and DLL characteristic bits used by these fixtures.
const IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
const IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800;

void test("collectPeHeaderFieldWarnings reports RELOCS_STRIPPED with relocation metadata", () => {
  const directoryBacked = createWindowsLayoutSubject();
  directoryBacked.coff.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_RELOCS_STRIPPED;
  directoryBacked.dirs = [{ name: "BASERELOC", rva: 0x2000, size: 8 }];
  const parsedBacked = createWindowsLayoutSubject();
  parsedBacked.coff.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_RELOCS_STRIPPED;
  parsedBacked.reloc = { blocks: [], totalEntries: 1 };

  assert.ok(collectPeHeaderFieldWarnings(directoryBacked).includes(
    "RELOCS_STRIPPED is set, but the image declares base relocations."
  ));
  assert.ok(collectPeHeaderFieldWarnings(parsedBacked).includes(
    "RELOCS_STRIPPED is set, but the image declares base relocations."
  ));
});

void test("collectPeHeaderFieldWarnings accepts RELOCS_STRIPPED without relocation metadata", () => {
  const pe = createWindowsLayoutSubject();
  pe.coff.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_RELOCS_STRIPPED;
  pe.dirs = [{ name: "BASERELOC", rva: 0, size: 0 }];

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports NO_BIND with bound import metadata", () => {
  const directoryBacked = createWindowsLayoutSubject();
  directoryBacked.opt.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NO_BIND;
  directoryBacked.dirs = [{ name: "BOUND_IMPORT", rva: 0x3000, size: 8 }];
  const parsedBacked = createWindowsLayoutSubject();
  parsedBacked.opt.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NO_BIND;
  parsedBacked.boundImports = {
    entries: [{ name: "demo.dll", TimeDateStamp: 1, NumberOfModuleForwarderRefs: 0 }]
  };

  assert.ok(collectPeHeaderFieldWarnings(directoryBacked).includes(
    "NO_BIND is set, but the image contains bound import metadata."
  ));
  assert.ok(collectPeHeaderFieldWarnings(parsedBacked).includes(
    "NO_BIND is set, but the image contains bound import metadata."
  ));
});

void test("collectPeHeaderFieldWarnings accepts NO_BIND without bound import metadata", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NO_BIND;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports commit sizes exceeding reserves", () => {
  const stack = createWindowsLayoutSubject();
  stack.opt.SizeOfStackCommit = 0x2000n;
  stack.opt.SizeOfStackReserve = 0x1000n;
  const heap = createWindowsLayoutSubject();
  heap.opt.SizeOfHeapCommit = 0x2000n;
  heap.opt.SizeOfHeapReserve = 0x1000n;

  assert.ok(collectPeHeaderFieldWarnings(stack).includes(
    "Stack/heap commit size exceeds reserve size."
  ));
  assert.ok(collectPeHeaderFieldWarnings(heap).includes(
    "Stack/heap commit size exceeds reserve size."
  ));
});

void test("collectPeHeaderFieldWarnings accepts commit sizes within reserves", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.SizeOfStackCommit = 0x1000n;
  pe.opt.SizeOfStackReserve = 0x2000n;
  pe.opt.SizeOfHeapCommit = 0x1000n;
  pe.opt.SizeOfHeapReserve = 0x1000n;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});
