"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeDwarf } from "../../../../analyzers/pe/dwarf.js";
import { createPeSection } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDwarf4SectionsFixture } from "../../../fixtures/dwarf-sections-fixture.js";

void test("analyzePeDwarf uses resolved COFF names and excludes raw alignment padding", async () => {
  const fixture = createDwarf4SectionsFixture();
  const sections = fixture.sections.map(section => createPeSection(section.name, {
    pointerToRawData: section.offset,
    virtualSize: section.size,
    sizeOfRawData: section.size + Uint8Array.BYTES_PER_ELEMENT
  }));

  const dwarf = await analyzePeDwarf(fixture.file, sections);

  assert.equal(dwarf?.units[0]?.root?.producer, "fixture compiler");
  assert.equal(dwarf?.sections[0]?.size, fixture.sections[0]?.size);
});

void test("analyzePeDwarf ignores ordinary PE sections and inventories .zdebug", async () => {
  const fixture = createDwarf4SectionsFixture();
  const ordinary = createPeSection(".text", {
    pointerToRawData: 0,
    virtualSize: Uint8Array.BYTES_PER_ELEMENT
  });
  const compressed = createPeSection(".zdebug_info", {
    pointerToRawData: 0,
    virtualSize: fixture.sections[0]!.size
  });

  assert.equal(await analyzePeDwarf(fixture.file, [ordinary]), null);
  const dwarf = await analyzePeDwarf(fixture.file, [ordinary, compressed]);
  assert.equal(dwarf?.sections[0]?.status, "compressed-unsupported");
});
