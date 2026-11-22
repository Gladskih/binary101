import assert from "node:assert/strict";
import { test } from "node:test";
import { elfRuntimeRelocationOperation, elfRuntimeRelocationWriteSize, isElfRuntimeRelocationTable } from
  "../../../../analyzers/elf/relocation-operation.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationSection, relocationTable } from "../../../fixtures/elf-relocations.js";

// Numeric IDs and slot widths from x86/Arm psABI dynamic relocation tables.
for (const [machine, bits, type, operation, width] of [
  [3, 32, 1, "absolute", 4n], [3, 32, 2, "pc-relative", 4n], [3, 32, 5, "copy", undefined],
  [3, 32, 6, "global-data", 4n], [3, 32, 7, "jump-slot", 4n], [3, 32, 8, "relative", 4n],
  [3, 32, 41, "tls-descriptor", 8n], [3, 32, 42, "resolver", 4n],
  [62, 64, 7, "jump-slot", 8n], [62, 32, 6, "global-data", 4n], [62, 64, 37, "resolver", 8n],
  [62, 32, 1, "absolute64", 8n], [62, 32, 38, "relative64", 8n], [62, 64, 5, "copy", undefined],
  [62, 64, 8, "relative", 8n], [62, 64, 36, "tls-descriptor", 16n],
  [183, 64, 257, "absolute64", 8n], [183, 64, 1024, "copy", undefined],
  [183, 64, 1025, "global-data", 8n], [183, 64, 1026, "jump-slot", 8n], [183, 64, 1032, "resolver", 8n],
  [183, 64, 1027, "relative", 8n], [183, 64, 1031, "tls-descriptor", 16n],
  [183, 32, 180, "copy", undefined], [183, 32, 181, "global-data", 4n],
  [183, 32, 182, "jump-slot", 4n], [183, 32, 183, "relative", 4n],
  [183, 32, 187, "tls-descriptor", 8n], [183, 32, 188, "resolver", 4n]
] as const) {
  void test(`decodes machine ${machine}, ELF${bits} dynamic relocation ${type}`, () => {
    const { elf } = dynamicRelocationFixture(bits);
    elf.header.machine = machine;
    const parsed = elfRuntimeRelocationOperation(elf, type);
    assert.equal(parsed, operation);
    assert.equal(elfRuntimeRelocationWriteSize(elf, parsed), width);
  });
}

void test("leaves unsupported machine, class and relocation type combinations unclassified", () => {
  const { elf } = dynamicRelocationFixture();
  assert.equal(elfRuntimeRelocationOperation(elf, null), undefined);
  assert.equal(elfRuntimeRelocationOperation(elf, 99), undefined);
  elf.header.machine = 3; // EM_386 cannot use ELFCLASS64.
  assert.equal(elfRuntimeRelocationOperation(elf, 8), undefined);
  elf.header.machine = 183;
  assert.equal(elfRuntimeRelocationOperation(elf, 182), undefined); // R_AARCH64_P32_JUMP_SLOT.
  elf.header.machine = 0;
  assert.equal(elfRuntimeRelocationOperation(elf, 7), undefined);
  assert.equal(elfRuntimeRelocationWriteSize(elf, undefined), undefined);
});

void test("requires dynamic provenance or an allocated relocation section", () => {
  const { elf } = dynamicRelocationFixture();
  const table = relocationTable();
  assert.equal(isElfRuntimeRelocationTable(elf, table), false);
  elf.sections.push(relocationSection(4, { type: 4, flags: 2n }));
  assert.equal(isElfRuntimeRelocationTable(elf, table), false);
  elf.sections[2]!.type = 11; // SHT_DYNSYM.
  assert.equal(isElfRuntimeRelocationTable(elf, table), true);
  elf.sections[4]!.flags = 0n;
  assert.equal(isElfRuntimeRelocationTable(elf, table), false);
  elf.sections[4]!.flags = 2n;
  table.symbolTableIndex = null;
  assert.equal(isElfRuntimeRelocationTable(elf, table), false);
  table.encoding = "RELR";
  assert.equal(isElfRuntimeRelocationTable(elf, table), true);
  table.encoding = "AUTH_RELR";
  assert.equal(isElfRuntimeRelocationTable(elf, table), true);
  table.sectionIndex = null;
  table.sources = [".rela.dyn", "DT_RELA"];
  assert.equal(isElfRuntimeRelocationTable(elf, table), true);
  elf.header.type = 2; // ET_EXEC.
  assert.equal(isElfRuntimeRelocationTable(elf, table), true);
  elf.header.type = 1; // ET_REL.
  assert.equal(isElfRuntimeRelocationTable(elf, table), false);
});
