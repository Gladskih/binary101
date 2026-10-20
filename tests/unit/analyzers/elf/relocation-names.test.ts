import assert from "node:assert/strict";
import { test } from "node:test";
import { elfRelocationTypeName } from "../../../../analyzers/elf/relocation-names.js";

void test("names are architecture-specific, with numeric fallback for unknown types", () => {
  // LLVM ELFRelocs definitions, independent expected ABI values.
  assert.equal(elfRelocationTypeName(62, 7), "R_X86_64_JUMP_SLOT");
  assert.equal(elfRelocationTypeName(3, 8), "R_386_RELATIVE");
  assert.equal(elfRelocationTypeName(183, 1027), "R_AARCH64_RELATIVE");
  assert.equal(elfRelocationTypeName(243, 3), "R_RISCV_RELATIVE");
  assert.equal(elfRelocationTypeName(62, 0), "R_X86_64_NONE");
  assert.equal(elfRelocationTypeName(62, 999), "machine 62, type 999");
  assert.equal(elfRelocationTypeName(999, 1), "machine 999, type 1");
});

void test("complete LLVM tables cover other architectures and less common relocation kinds", () => {
  // Independent numeric expectations from pinned LLVM ELFRelocs/*.def.
  assert.equal(elfRelocationTypeName(3, 15), "R_386_TLS_IE");
  assert.equal(elfRelocationTypeName(40, 10), "R_ARM_THM_CALL");
  assert.equal(elfRelocationTypeName(183, 273), "R_AARCH64_LD_PREL_LO19");
  assert.equal(elfRelocationTypeName(243, 26), "R_RISCV_HI20");
  assert.equal(elfRelocationTypeName(8, 2), "R_MIPS_32");
  assert.equal(elfRelocationTypeName(20, 1), "R_PPC_ADDR32");
  assert.equal(elfRelocationTypeName(21, 38), "R_PPC64_ADDR64");
  assert.equal(elfRelocationTypeName(22, 22), "R_390_64");
  assert.equal(elfRelocationTypeName(258, 2), "R_LARCH_64");
  assert.equal(elfRelocationTypeName(83, 1), "R_AVR_32");
  assert.equal(elfRelocationTypeName(93, 1), "R_ARC_8");
  assert.equal(elfRelocationTypeName(8, 0x01031202),
    "R_MIPS_32 / R_MIPS_64 / R_MIPS_REL32 (special symbol 1)");
  assert.equal(elfRelocationTypeName(8, 0x00031202), "R_MIPS_32 / R_MIPS_64 / R_MIPS_REL32");
  assert.equal(elfRelocationTypeName(43, 0xffffff21), "R_SPARC_OLO10 (type data -1)");
});
