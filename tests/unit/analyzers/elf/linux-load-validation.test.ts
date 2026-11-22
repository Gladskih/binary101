import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfImageHeaders } from "../../../../analyzers/elf/image-headers.js";
import { validateElfLinuxLoadLayout } from "../../../../analyzers/elf/linux-load-validation.js";
import type { ElfParseResult } from "../../../../analyzers/elf/types.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";

const imageFixture = async (): Promise<ElfParseResult> => {
  const image = await readElfImageHeaders(createElfMetadataFile().file);
  assert.ok(image && !("incompleteHeader" in image));
  image.issues.length = 0;
  return image;
};

for (const [machine, osabi, type, align, offset, warning] of [
  [3, 0, 2, 0n, 1n, true], [62, 3, 3, 1n, 1n, true], [183, 0, 3, 256n, 256n, true],
  [62, 0, 3, 1n, 4096n, false], [62, 0, 3, 4096n, 1n, false],
  [62, 9, 3, 1n, 1n, false], [62, 0, 1, 1n, 1n, false], [243, 0, 3, 1n, 1n, false]
] as const) {
  void test(`Linux page rule for machine ${machine}, ABI ${osabi}, type ${type}, p_align ${align}, p_offset ${offset}`,
    async () => {
      const image = await imageFixture();
      Object.assign(image.header, { machine, type });
      image.ident.osabi = osabi;
      Object.assign(image.programHeaders[0]!, { align, offset, vaddr: 0x400000n });

      validateElfLinuxLoadLayout(image);

      assert.deepEqual(image.issues.map(issue => /minimum Linux page size/.test(issue)), warning ? [true] : []);
    });
}

void test("checks page congruence and reserved segments when reading a file", async () => {
  const file = createElfMetadataFile().file;
  const image = await imageFixture();
  const bytes = await file.arrayBuffer();
  const view = new DataView(bytes);
  const table = Number(image.header.phoff);
  // Elf64_Phdr offsets, gABI 7.1: p_offset at 8, p_filesz at 32, p_align at 48.
  view.setBigUint64(table + 8, 1n, true);
  view.setBigUint64(table + 32, BigInt(bytes.byteLength - 1), true);
  view.setBigUint64(table + 48, 1n, true);
  view.setUint32(table + 3 * 56, 5, true); // Replace PT_NOTE with the reserved PT_SHLIB.

  const parsed = await readElfImageHeaders(new File([bytes], file.name));

  assert.match(parsed?.issues.join(" ") ?? "", /PT_LOAD.*minimum Linux page size/);
  assert.match(parsed?.issues.join(" ") ?? "", /PT_SHLIB.*reserved/);
});

for (const is64 of [false, true]) {
  void test(`rejects a load range extending beyond the ELF${is64 ? 64 : 32} address space`, async () => {
    const image = await imageFixture();
    image.is64 = is64;
    const limit = 1n << (is64 ? 64n : 32n);
    const load = image.programHeaders[0]!;
    Object.assign(load, { vaddr: limit - 4096n, memsz: 4096n });
    image.header.phentsize = is64 ? 56 : 32;
    validateElfLinuxLoadLayout(image);
    assert.deepEqual(image.issues, []);
    load.memsz += 1n;

    validateElfLinuxLoadLayout(image);

    assert.deepEqual(image.issues, ["PT_LOAD #0: the memory range exceeds the ELF address space."]);
  });
}

void test("reports an oversized program header stride and a complete table with no PT_LOAD", async () => {
  const image = await imageFixture();
  image.header.phentsize += 8;
  image.programHeaders[0]!.type = 0;

  validateElfLinuxLoadLayout(image);

  assert.deepEqual(image.issues, ["Linux requires e_phentsize to be 56 bytes for this ELF class.",
    "A loadable Linux ELF image requires at least one PT_LOAD segment."]);
});

void test("a truncated program table cannot establish that PT_LOAD is absent", async () => {
  const image = await imageFixture();
  image.programHeaders.splice(0, 1);

  validateElfLinuxLoadLayout(image);

  assert.deepEqual(image.issues, []);
});
