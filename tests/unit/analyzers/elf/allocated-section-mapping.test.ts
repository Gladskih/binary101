import assert from "node:assert/strict";
import { test } from "node:test";
import { validateElfAllocatedSectionMappings } from "../../../../analyzers/elf/allocated-section-mapping.js";
import { readElfImageHeaders } from "../../../../analyzers/elf/image-headers.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

const mappingFixture = async () => {
  const image = await readElfImageHeaders(createElfMetadataFile().file);
  assert.ok(image && !("incompleteHeader" in image));
  image.issues.length = 0;
  const load = image.programHeaders[0]!;
  image.programHeaders = [load];
  image.header.phnum = 1;
  const offset = load.filesz - 16n;
  const section = relocationSection(1, { flags: 2n, addr: load.vaddr + offset, offset, size: 16n });
  image.sections = [section];
  return { image, load, section };
};

for (const [type, flags, displacement, warning] of [
  [1, 2n, 0n, null], [1, 2n, 1n, /lacks file-backed PT_LOAD/],
  [8, 2n, 0n, null], [8, 2n, 1n, /SHT_NOBITS.*outside PT_LOAD memory/],
  [8, 0x402n, 1n, null], [1, 0n, 1n, null], [0, 2n, 1n, null]
] as const) {
  void test(`validates allocated section type=${type}, flags=${flags}, displacement=${displacement}`, async () => {
    const { image, section } = await mappingFixture();
    Object.assign(section, { type, flags, addr: section.addr + displacement });

    validateElfAllocatedSectionMappings(image);

    assert.deepEqual(image.issues.map(issue => warning?.test(issue)), warning ? [true] : []);
  });
}

for (const [displacement, expected] of [[0n, false], [1n, true]] as const) {
  void test(`combines adjacent load mappings only at the same translation (${displacement})`, async () => {
    const { image, load, section } = await mappingFixture();
    const cut = section.offset + 8n;
    image.programHeaders.push({ ...load, index: 1, offset: cut, vaddr: load.vaddr + cut + displacement,
      filesz: 8n, memsz: 8n });
    load.filesz = cut;
    load.memsz = cut;
    image.header.phnum = 2;

    validateElfAllocatedSectionMappings(image);

    assert.equal(image.issues.some(issue => issue.includes("lacks file-backed PT_LOAD")), expected);
  });
}

void test("the program headers must be complete before an absent mapping is confirmed", async () => {
  const { image, section } = await mappingFixture();
  image.header.phnum += 1;
  section.addr += 1n;

  validateElfAllocatedSectionMappings(image);

  assert.deepEqual(image.issues, []);
});

void test("ignores empty allocated sections at virtual addresses without a load mapping", async () => {
  const { image, section } = await mappingFixture();
  section.addr += 1n;
  section.size = 0n;

  validateElfAllocatedSectionMappings(image);

  assert.deepEqual(image.issues, []);
});

void test("ignores a non-PT_LOAD segment even if its file and virtual ranges match the allocated section", async () => {
  const { image, load, section } = await mappingFixture();
  section.addr += 128n;
  image.programHeaders.push({ ...load, type: 4, index: 1, vaddr: load.vaddr + 128n });
  image.header.phnum = 2;

  validateElfAllocatedSectionMappings(image);

  assert.match(image.issues.join(" "), /lacks file-backed PT_LOAD/);
});

void test("does not duplicate the missing-load diagnostic for each allocated section", async () => {
  const { image, load, section } = await mappingFixture();
  load.type = 4;
  section.addr += 1n;

  validateElfAllocatedSectionMappings(image);

  assert.deepEqual(image.issues, []);
});

void test("does not accept file-backed coverage from a load whose file size exceeds its memory size", async () => {
  const { image, load } = await mappingFixture();
  load.memsz -= 1n;

  validateElfAllocatedSectionMappings(image);

  assert.match(image.issues.join(" "), /lacks file-backed PT_LOAD/);
});
