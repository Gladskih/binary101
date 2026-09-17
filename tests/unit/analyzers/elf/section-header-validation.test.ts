import assert from "node:assert/strict";
import { test } from "node:test";
import { validateElfSectionHeaders } from "../../../../analyzers/elf/section-header-validation.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

// SHT_NULL=0, SHT_PROGBITS=1, SHT_NOBITS=8; gABI 3.2/3.3.
// https://gabi.xinuos.com/elf/03-sheader.html
for (const type of [0, 8]) {
  void test(`section type ${type} has no file payload`, () => {
    const issues: string[] = [];
    validateElfSectionHeaders([relocationSection(1, { type, offset: 100n, size: 100n })],
      0, issues);
    assert.deepEqual(issues, []);
  });
}

for (const addralign of [0n, 1n, 2n, 8n]) {
  void test(`accepts valid alignment ${addralign} and an exact-end payload`, () => {
    const issues: string[] = [];
    validateElfSectionHeaders([relocationSection(1, { offset: 1n, size: 7n,
      addr: 16n, addralign })], 8, issues);
    assert.deepEqual(issues, []);
  });
}

void test("reports payload overflow and both alignment violations", () => {
  const issues: string[] = [];
  validateElfSectionHeaders([relocationSection(1, { size: 9n, addralign: 3n, addr: 1n })],
    8, issues);
  assert.equal(issues.length, 3);
  assert.match(issues.join(" "), /outside the file/);
  assert.match(issues.join(" "), /not a power of two/);
  assert.match(issues.join(" "), /sh_addr does not satisfy/);
});

void test("ignores undefined NULL fields and zero-size payload offsets", () => {
  const issues: string[] = [];
  validateElfSectionHeaders([relocationSection(0, { type: 0, addralign: 3n, addr: 1n }),
    relocationSection(1, { offset: 100n, size: 0n })], 0, issues);
  assert.deepEqual(issues, []);
});
