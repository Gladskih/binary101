import assert from "node:assert/strict";
import { test } from "node:test";
import { validateElfSectionHeaders } from "../../../../analyzers/elf/section-header-validation.js";
import { parseSectionHeadersWithNames, resolveExtendedHeaderCounts } from
  "../../../../analyzers/elf/header-tables.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

const base = { ...relocationFixture().elf.header, shentsize: 64 };

void test("rejects extended counts from a section-zero record with the wrong type", async () => {
  const bytes = new Uint8Array(128);
  const sectionZero = new DataView(bytes.buffer, 64);
  sectionZero.setUint32(4, 1, true); // sh_type=SHT_PROGBITS.
  sectionZero.setBigUint64(32, 7n, true);
  const issues: string[] = [];

  const resolved = await resolveExtendedHeaderCounts(new File([bytes], "wrong-section-zero.elf"),
    { ...base, shoff: 64n }, true, true, issues, 64);

  assert.equal(resolved.shnum, 0);
  assert.deepEqual(issues, ["Section header #0 must have sh_type SHT_NULL."]);
});

void test("warns on unrequested extension values in a regular section table", async () => {
  const bytes = new Uint8Array(128);
  const sectionZero = new DataView(bytes.buffer, 64);
  // Elf64_Shdr.sh_size, sh_link and sh_info at +32/+40/+44.
  sectionZero.setBigUint64(32, 1n, true);
  sectionZero.setUint32(40, 1, true);
  sectionZero.setUint32(44, 1, true);
  const issues: string[] = [];

  await parseSectionHeadersWithNames(new File([bytes], "unrequested-extensions.elf"),
    { ...base, shoff: 64n, shnum: 1 }, true, true, issues, 64);

  assert.deepEqual(issues, [
    "Section header #0 sh_size must be zero without extended section numbering.",
    "Section header #0 sh_link must be zero without an extended section name table index.",
    "Section header #0 sh_info must be zero without an extended program header count."
  ]);
});
void test("checks the fixed fields of section header zero", () => {
  const bad = relocationSection(0, { type: 1, nameOff: 1, flags: 1n, addr: 1n,
    offset: 1n, addralign: 1n, entsize: 1n });
  const issues: string[] = [];

  validateElfSectionHeaders([bad], 32, issues);

  assert.deepEqual(issues, ["Section header #0 must have sh_type SHT_NULL.",
    "Section header #0 fields must be zero: sh_name, sh_flags, sh_addr, sh_offset, sh_addralign, sh_entsize."]);
});

void test("allows each section-zero extension only when the ELF header requests it", () => {
  const section = relocationSection(0, { type: 0, size: 0xff00n, link: 0xff01, info: 0xffff, addralign: 0n });
  const issues: string[] = [];
  // gABI e_shnum=0 / SHN_XINDEX and Linux PN_XNUM opt into the three extensions.
  validateElfSectionHeaders([section], 32, issues, { ...base, shnum: 0, shstrndx: 0xffff, phnum: 0xffff });

  assert.deepEqual(issues, []);
});

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
  validateElfSectionHeaders([relocationSection(1, { type: 0, addralign: 3n, addr: 1n }),
    relocationSection(2, { offset: 100n, size: 0n })], 0, issues);
  assert.deepEqual(issues, []);
});

void test("checks stored section overlap despite unordered and nested sections", () => {
  const issues: string[] = [];
  const sections = [
    relocationSection(1, { offset: 8n, size: 2n }),
    relocationSection(2, { offset: 4n, size: 8n, flags: 0x800n }),
    relocationSection(3, { offset: 10n, size: 1n }),
    relocationSection(4, { offset: 12n, size: 4n }),
    relocationSection(5, { offset: 4n, size: 8n, type: 8 }),
    relocationSection(6, { offset: 6n, size: 0n })
  ];

  validateElfSectionHeaders(sections, 16, issues);

  assert.deepEqual(issues, ["Section #1 file range overlaps section #2.",
    "Section #3 file range overlaps section #2."]);
});
