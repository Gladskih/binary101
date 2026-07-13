"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { discoverMsvcRtti } from "../../../../../analyzers/pe/msvc-rtti/discovery.js";
import {
  createMsvcRttiGraphParser,
  type MsvcRttiGraphParser
} from "../../../../../analyzers/pe/msvc-rtti/graph-parser.js";
import {
  createMsvcRttiImage,
  type MsvcRttiImage
} from "../../../../../analyzers/pe/msvc-rtti/image.js";
import { indexMsvcRttiDir64Sites } from "../../../../../analyzers/pe/msvc-rtti/relocation-index.js";
import { MsvcRttiPeFixtureBuilder } from "../../../../fixtures/pe-msvc-rtti-fixture.js";

const createProbeImage = (overrides: Partial<MsvcRttiImage> = {}): MsvcRttiImage => ({
  availableDataSize: () => 8,
  isDataRange: () => true,
  isExecutableRva: () => true,
  preferredVaToRva: value => Number(value),
  readData: async () => new DataView(new ArrayBuffer(8)),
  readPreferredVaRva: async rva => rva === 0x2000 ? 0x3000 : 0x1000,
  ...overrides
});

const createRejectingGraph = (
  onCompleteObjectLocator: (rva: number) => void
): MsvcRttiGraphParser => ({
  completeObjectLocator: async rva => {
    onCompleteObjectLocator(rva);
    return null;
  },
  getClassHierarchy: () => null,
  getTypeDescriptor: () => null
});

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

void test("discoverMsvcRtti rejects slots without an adjacent DIR64 function pointer before graph parsing", async () => {
  const reads: number[] = [];
  const graphRvas: number[] = [];
  const image = createProbeImage({
    readPreferredVaRva: async rva => {
      reads.push(rva);
      return 0x3000;
    }
  });

  const result = await discoverMsvcRtti(
    image,
    new Set([0x2000]),
    createRejectingGraph(rva => graphRvas.push(rva))
  );

  assert.equal(result, null);
  assert.deepEqual(reads, []);
  assert.deepEqual(graphRvas, []);
});

void test("discoverMsvcRtti rejects locator targets outside initialized data before graph parsing", async () => {
  const reads: number[] = [];
  const graphRvas: number[] = [];
  const image = createProbeImage({
    isDataRange: rva => rva !== 0x3000,
    readPreferredVaRva: async rva => {
      reads.push(rva);
      return rva === 0x2000 ? 0x3000 : 0x1000;
    }
  });

  const result = await discoverMsvcRtti(
    image,
    new Set([0x2000, 0x2008]),
    createRejectingGraph(rva => graphRvas.push(rva))
  );

  assert.equal(result, null);
  assert.deepEqual(reads, [0x2000]);
  assert.deepEqual(graphRvas, []);
});

void test("discoverMsvcRtti rejects non-executable first targets before graph parsing", async () => {
  const reads: number[] = [];
  const graphRvas: number[] = [];
  const image = createProbeImage({
    isExecutableRva: () => false,
    readPreferredVaRva: async rva => {
      reads.push(rva);
      return rva === 0x2000 ? 0x3000 : 0x1000;
    }
  });

  const result = await discoverMsvcRtti(
    image,
    new Set([0x2000, 0x2008]),
    createRejectingGraph(rva => graphRvas.push(rva))
  );

  assert.equal(result, null);
  assert.deepEqual(reads, [0x2000, 0x2008]);
  assert.deepEqual(graphRvas, []);
});
