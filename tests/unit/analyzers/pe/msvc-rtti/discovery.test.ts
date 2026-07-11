"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { discoverMsvcRtti } from "../../../../../analyzers/pe/msvc-rtti/discovery.js";
import { createMsvcRttiGraphParser } from "../../../../../analyzers/pe/msvc-rtti/graph-parser.js";
import { createMsvcRttiImage } from "../../../../../analyzers/pe/msvc-rtti/image.js";
import { indexMsvcRttiDir64Sites } from "../../../../../analyzers/pe/msvc-rtti/relocation-index.js";
import { MsvcRttiPeFixtureBuilder } from "../../../../fixtures/pe-msvc-rtti-fixture.js";

void test("discoverMsvcRtti returns address-sorted canonical collections", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const firstHierarchy = builder.addHierarchy(builder.addType(".?AVFirst@@"));
  const firstVftable = builder.addVftable(firstHierarchy, [builder.allocateFunctionTarget()]);
  const secondHierarchy = builder.addHierarchy(builder.addType(".?AVSecond@@"));
  const secondVftable = builder.addVftable(secondHierarchy, [builder.allocateFunctionTarget()]);
  const fixture = builder.build();
  const image = createMsvcRttiImage(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core.sections,
    fixture.core.opt.ImageBase,
    fixture.core.opt.SizeOfImage
  );
  const sites = indexMsvcRttiDir64Sites(fixture.relocations, image);
  assert.ok(sites);
  const reversedSites = new Set([...sites].sort((left, right) => right - left));

  const result = await discoverMsvcRtti(image, reversedSites, createMsvcRttiGraphParser(image));

  assert.ok(result);
  assert.deepEqual(result.completeObjectLocators.map(locator => locator.rva), [
    firstVftable.colRva,
    secondVftable.colRva
  ]);
  assert.deepEqual(result.vftables.map(vftable => vftable.rva), [
    firstVftable.rva,
    secondVftable.rva
  ]);
  assert.deepEqual(result.types.map(type => type.decoratedName), [".?AVFirst@@", ".?AVSecond@@"]);
});
