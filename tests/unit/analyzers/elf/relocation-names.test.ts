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
