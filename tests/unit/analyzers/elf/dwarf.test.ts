"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeElfDwarf } from "../../../../analyzers/elf/dwarf.js";
import type { ElfSectionHeader } from "../../../../analyzers/elf/types.js";
import { createDwarf4SectionsFixture } from "../../../fixtures/dwarf-sections-fixture.js";
import {
  createCompressedDwarfSectionsFixture
} from "../../../fixtures/dwarf-compressed-section-fixture.js";

// Independent ELF values from System V ABI, section attributes and types:
// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html
const TEST_ELF = {
  sectionType: { programBits: 1 },
  sectionFlag: { compressed: 0x800n }
} as const;

const toElfSection = (
  section: { name: string; offset: number; size: number },
  index: number,
  flags = 0n
): ElfSectionHeader => ({
  nameOff: 0,
  type: TEST_ELF.sectionType.programBits,
  typeName: "PROGBITS",
  flags,
  flagNames: [],
  addr: 0n,
  offset: BigInt(section.offset),
  size: BigInt(section.size),
  link: 0,
  info: 0,
  addralign: 1n,
  entsize: 0n,
  index,
  name: section.name
});

void test("analyzeElfDwarf adapts ELF debug sections to the common analyzer", async () => {
  const fixture = createDwarf4SectionsFixture();
  const issues: string[] = [];

  const dwarf = await analyzeElfDwarf(
    fixture.file,
    fixture.sections.map((section, index) => toElfSection(section, index)),
    "elf64",
    true,
    issues
  );

  assert.equal(dwarf?.units[0]?.root?.name, "main.c");
  assert.deepEqual(issues, []);
});

void test("analyzeElfDwarf decodes ELF64 SHF_COMPRESSED zlib sections", async () => {
  const fixture = createCompressedDwarfSectionsFixture("elf64-little-zlib");
  const sections = fixture.candidates.map((candidate, index) => toElfSection(
    candidate.section,
    index,
    TEST_ELF.sectionFlag.compressed
  ));

  const dwarf = await analyzeElfDwarf(fixture.file, sections, "elf64", true, []);

  assert.equal(dwarf?.units[0]?.root?.name, "main.c");
  assert.equal(dwarf?.linePrograms[0]?.files[0]?.path, "main.c");
  assert.equal(dwarf?.units[0]?.root?.producer, "fixture compiler");
  assert.equal(dwarf?.sections[0]?.status, "decoded");
  assert.deepEqual(dwarf?.issues, []);
});

void test("analyzeElfDwarf recognizes SHF_COMPRESSED and unsafe offsets", async () => {
  const fixture = createDwarf4SectionsFixture();
  const issues: string[] = [];
  const compressed = toElfSection(
    fixture.sections[0]!,
    0,
    TEST_ELF.sectionFlag.compressed
  );
  const unsafe = {
    ...toElfSection(fixture.sections[1]!, 1),
    offset: BigInt(Number.MAX_SAFE_INTEGER) + 1n
  };

  const dwarf = await analyzeElfDwarf(
    fixture.file,
    [compressed, unsafe],
    "elf64",
    true,
    issues
  );

  assert.equal(dwarf?.sections[0]?.status, "compressed-unsupported");
  assert.ok(issues.some(issue => issue.includes("too large to index")));
});

void test("analyzeElfDwarf does not decode relocation-backed ELF object DWARF", async () => {
  const fixture = createDwarf4SectionsFixture();
  const sections = fixture.sections.map((section, index) => toElfSection(section, index));
  sections.push(toElfSection({
    name: ".rela.debug_info",
    offset: 0,
    size: Uint8Array.BYTES_PER_ELEMENT
  }, sections.length));

  const dwarf = await analyzeElfDwarf(fixture.file, sections, "elf64", true, []);

  assert.equal(dwarf?.units.length, 0);
  assert.equal(
    dwarf?.sections.find(section => section.name === ".debug_info")?.status,
    "relocations-unsupported"
  );
  assert.ok(dwarf?.issues.some(issue => issue.includes("relocations are required")));
});
