import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeRelocationStructures } from "../../../../analyzers/pe/relocation-discovery.js";
import { analyzePeNativeAotMetadata } from "../../../../analyzers/pe/native-aot-metadata.js";
import { analyzePeMsvcRtti } from "../../../../analyzers/pe/msvc-rtti/index.js";
import { analyzePeItaniumRtti } from "../../../../analyzers/pe/itanium-rtti.js";
import { createPeItaniumFixture } from "../../../fixtures/pe-itanium-rtti.js";
import {
  nativeDiscovery, msvcDiscovery, nativeDiscoveryPeFile, managedMsvcPeFile, managedItaniumPeFile,
  managedNativeAotPeFile
} from "../../../helpers/pe-relocation-discovery.js";
import { getItaniumRttiTypeName } from "../../../../analyzers/itanium-rtti/type-name.js";
import { MsvcRttiDemangleError } from "../../../../analyzers/pe/msvc-rtti/type-name.js";
import { createPeNativeAotInitializerFixture } from "../../../helpers/pe-native-aot-initializer-fixture.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { parsePe, isPeWindowsParseResult } from "../../../../analyzers/pe/index.js";

for (const width of [4, 8] as const) {
  void test(`matches the independent positive PE${width * 8} NativeAOT analysis`, async () => {
    const { fixture, reader } = nativeDiscovery(width);
    const result = await analyzePeRelocationStructures(reader, fixture.core, fixture.relocations);
    assert.ok(result.nativeAotMetadata);
    assert.deepEqual(result.nativeAotMetadata,
      await analyzePeNativeAotMetadata(reader, fixture.core, fixture.relocations));
    assert.equal(result.msvcRtti, null);
    assert.equal(result.itaniumRtti, null);
  });

  void test(`matches independent PE${width * 8} Itanium types and inheritance`, async () => {
    const fixture = createPeItaniumFixture(width);
    const result = await analyzePeRelocationStructures(fixture.reader(), fixture.core, fixture.relocations);
    assert.ok(result.itaniumRtti?.types.some(type => type.name === "8Multiple"));
    assert.deepEqual(result.itaniumRtti,
      await analyzePeItaniumRtti(fixture.reader(), fixture.core, fixture.relocations));
    assert.equal(result.nativeAotMetadata, null);
    assert.equal(getItaniumRttiTypeName(result.itaniumRtti!.types.find(type => type.name === "8Multiple")!),
      "Multiple");
  });
}

void test("matches independent MSVC graph analysis", async () => {
  const { fixture, reader } = msvcDiscovery();
  const result = await analyzePeRelocationStructures(reader, fixture.core, fixture.relocations);
  assert.equal(result.msvcRtti?.types[0]?.decoratedName, ".?AVSimple@@");
  assert.deepEqual(result.msvcRtti, await analyzePeMsvcRtti(reader, fixture.core, fixture.relocations));
});

void test("preserves independent fallback results for incompatible optional headers", async () => {
  const { fixture, reader } = nativeDiscovery();
  fixture.core.opt.Magic = 0x10b;
  const result = await analyzePeRelocationStructures(reader, fixture.core, fixture.relocations);
  assert.deepEqual(result, { nativeAotMetadata: null, msvcRtti: null, itaniumRtti: null });
});

void test("preserves visible Itanium diagnostics after a failed shared source read", async () => {
  const { fixture, reader } = nativeDiscovery();
  reader.read = async () => { throw new Error("source unavailable"); };
  const result = await analyzePeRelocationStructures(reader, fixture.core, fixture.relocations);
  assert.deepEqual(result, { nativeAotMetadata: null, msvcRtti: null,
    itaniumRtti: { types: [], warnings: ["Itanium RTTI analysis could not read file data."] } });
});

for (const width of [4, 8] as const) {
  void test(`preserves PE${width * 8} NativeAOT initializer finalization`, async () => {
    const fixture = createPeNativeAotInitializerFixture(width);
    const result = await analyzePeRelocationStructures(new MockFile(fixture.bytes),
      fixture.core, fixture.relocations);
    assert.deepEqual(result.nativeAotMetadata?.initializers,
      [{ sectionType: 205, targetRvas: [fixture.codeRva], warnings: [] }]);
  });
}

void test("retains demangler diagnostics during ordered MSVC graph validation", async () => {
  const { fixture, reader, vftable } = msvcDiscovery();
  const read = reader.read.bind(reader);
  reader.read = (offset, size) => offset === fixture.rvaToOffset(vftable.colRva) && size === 24
    ? Promise.reject(new MsvcRttiDemangleError("unavailable")) : read(offset, size);
  const result = await analyzePeRelocationStructures(reader, fixture.core, fixture.relocations);
  assert.deepEqual(result.msvcRtti, { layout: "microsoft-cxx-amd64-image-relative-rtti-rev1", types: [],
    classHierarchies: [], completeObjectLocators: [], vftables: [], warnings: ["unavailable"] });
});

void test("rejects failed MSVC graph reads without discarding other analyses", async () => {
  const { fixture, reader, vftable } = msvcDiscovery();
  const read = reader.read.bind(reader);
  reader.read = (offset, size) => offset === fixture.rvaToOffset(vftable.colRva) && size === 24
    ? Promise.reject(new Error("unavailable")) : read(offset, size);
  const result = await analyzePeRelocationStructures(reader, fixture.core, fixture.relocations);
  assert.equal(result.msvcRtti, null);
  assert.equal(result.nativeAotMetadata, null);
});

void test("retains Itanium read warnings after the shared pointer scan", async () => {
  const fixture = createPeItaniumFixture();
  const reader = fixture.reader();
  const read = reader.read.bind(reader);
  reader.read = (offset, size) => size === 4096
    ? Promise.reject(new Error("unavailable")) : read(offset, size);
  const result = await analyzePeRelocationStructures(reader, fixture.core, fixture.relocations);
  assert.deepEqual(result.itaniumRtti?.warnings, ["Itanium RTTI analysis could not read file data."]);
});

void test("keeps MSVC results when duplicate fixups disqualify the shared scan", async () => {
  const { fixture, reader } = msvcDiscovery();
  const block = fixture.relocations!.blocks[0]!;
  block.entries.push({ ...block.entries[0]! }, { type: 0, offset: 0 });
  block.size += 4;
  block.count += 2;
  fixture.relocations!.totalEntries += 2;
  const result = await analyzePeRelocationStructures(reader, fixture.core, fixture.relocations);
  assert.equal(result.msvcRtti?.types[0]?.decoratedName, ".?AVSimple@@");
  assert.equal(result.nativeAotMetadata, null);
  assert.equal(result.itaniumRtti, null);
});

void test("routes a full PE NativeAOT image through candidate discovery", async () => {
  const parsed = await parsePe(nativeDiscoveryPeFile());
  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.ok(parsed.nativeAotCandidate?.status === "confirmed");
  assert.equal(parsed.nativeAotCandidate.headerRva, 0x1100);
  assert.equal(parsed.nativeAotCandidate.modulePointerRva, 0x1080);
});

void test("retains native RTTI for PE images with a CLR directory", async () => {
  const parsed = await parsePe(managedMsvcPeFile());
  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.ok(parsed.clr);
  assert.equal(parsed.msvcRtti?.types[0]?.decoratedName, ".?AVSimple@@");
  assert.equal(parsed.nativeAotCandidate, null);
});

void test("retains Itanium RTTI for images with a CLR directory", async () => {
  const parsed = await parsePe(managedItaniumPeFile());
  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.ok(parsed.clr);
  assert.ok(parsed.itaniumRtti?.types.some(type => type.name === "8Multiple"));
});

void test("does not run NativeAOT discovery when a CLR header is present", async () => {
  const parsed = await parsePe(await managedNativeAotPeFile());
  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.ok(parsed.clr);
  assert.equal(parsed.nativeAotCandidate, null);
});
