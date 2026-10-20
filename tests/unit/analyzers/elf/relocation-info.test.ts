import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeElfRelocationInfo } from "../../../../analyzers/elf/relocation-info.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

void test("ELF32 and generic ELF64 split symbols and types at their ABI boundary", () => {
  assert.deepEqual(decodeElfRelocationInfo(0x12345678n, relocationFixture(32).elf),
    { type: 0x78, symbolIndex: 0x123456 });
  assert.deepEqual(decodeElfRelocationInfo(0x1234567887654321n, relocationFixture().elf),
    { type: 0x87654321, symbolIndex: 0x12345678 });
});
void test("MIPS64 N64 preserves all operation and special-symbol bytes in either order", () => {
  const little = relocationFixture();
  const big = relocationFixture(64, "big");
  little.elf.header.machine = 8;
  big.elf.header.machine = 8;
  // MIPS N64: 32-bit sym, then ssym/type3/type2/type1 byte sequence.
  assert.deepEqual(decodeElfRelocationInfo(0x0203120112345678n, little.elf),
    { type: 0x01120302, symbolIndex: 0x12345678 });
  assert.deepEqual(decodeElfRelocationInfo(0x1234567801120302n, big.elf),
    { type: 0x01120302, symbolIndex: 0x12345678 });
});
