"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { IMAGE_FILE_MACHINE_ARM64 } from "../../../../../analyzers/coff/machine.js";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { isPeWindowsParseResult, parsePe } from "../../../../../analyzers/pe/index.js";
import { analyzePeMsvcRtti } from "../../../../../analyzers/pe/msvc-rtti/index.js";
import {
  createSimpleMsvcRttiFixture,
  MsvcRttiPeFixtureBuilder
} from "../../../../fixtures/pe-msvc-rtti-fixture.js";

const analyzeBuiltFixture = async (builder: MsvcRttiPeFixtureBuilder) => {
  const fixture = builder.build();
  return analyzePeMsvcRtti(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core,
    fixture.relocations
  );
};

void test("parsePe attaches confirmed MSVC RTTI without reparsing at the result boundary", async () => {
  const { builder, type, vftable } = createSimpleMsvcRttiFixture(2);
  const fixture = builder.build();

  const parsed = await parsePe(fixture.file);

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.ok(parsed.msvcRtti);
  assert.equal(parsed.msvcRtti.types[0]?.rva, type.rva);
  assert.deepEqual(parsed.msvcRtti.vftables[0]?.functionTargetRvas, vftable.functionTargetRvas);
  assert.ok(parsed.reloc);
  assert.equal(parsed.reloc.warnings, undefined);
});

void test("analyzePeMsvcRtti returns null for PE32", async () => {
  const { builder } = createSimpleMsvcRttiFixture();
  builder.setOptionalMagic(0x10b);

  const result = await analyzeBuiltFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti returns null for non-AMD64 PE32+", async () => {
  const { builder } = createSimpleMsvcRttiFixture();
  builder.setMachine(IMAGE_FILE_MACHINE_ARM64);

  const result = await analyzeBuiltFixture(builder);

  assert.equal(result, null);
});

void test("analyzePeMsvcRtti returns null without Base Relocation Directory", async () => {
  const { builder } = createSimpleMsvcRttiFixture();
  builder.omitBaseRelocations();

  const result = await analyzeBuiltFixture(builder);

  assert.equal(result, null);
});

void test("parsePe reports a truncated relocation-directory tail and suppresses RTTI", async () => {
  const { builder } = createSimpleMsvcRttiFixture();
  builder.appendRelocationTail(2);
  const fixture = builder.build();

  const parsed = await parsePe(fixture.file);

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.msvcRtti, null);
  assert.ok(parsed.reloc?.warnings?.some(warning => warning.includes("truncated block header")));
});

void test("parsePe leaves RTTI null for an ordinary relocation-heavy non-C++ image", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  for (let index = 0; index < 64; index += 1) builder.addDir64Pointer(0x1000);
  const fixture = builder.build();

  const parsed = await parsePe(fixture.file);

  assert.ok(parsed && isPeWindowsParseResult(parsed));
  assert.equal(parsed.msvcRtti, null);
  assert.ok((parsed.reloc?.totalEntries ?? 0) >= 64);
});

void test("analyzePeMsvcRtti treats unexpected reader failures as no result", async () => {
  const { builder } = createSimpleMsvcRttiFixture();
  const fixture = builder.build();
  const throwingReader = {
    size: fixture.file.size,
    read: async (): Promise<DataView> => { throw new Error("read failed"); },
    readBytes: async (): Promise<Uint8Array> => { throw new Error("read failed"); }
  };

  const result = await analyzePeMsvcRtti(throwingReader, fixture.core, fixture.relocations);

  assert.equal(result, null);
});

