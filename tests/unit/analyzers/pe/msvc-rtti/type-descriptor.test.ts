"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { createMsvcRttiImage } from "../../../../../analyzers/pe/msvc-rtti/image.js";
import { parseMsvcRttiTypeDescriptor } from "../../../../../analyzers/pe/msvc-rtti/type-descriptor.js";
import {
  MsvcRttiPeFixtureBuilder
} from "../../../../fixtures/pe-msvc-rtti-fixture.js";
import { MSVC_RTTI_FIXTURE_IMAGE_BASE } from "../../../../fixtures/pe-msvc-rtti-pe.js";

const parseType = async (builder: MsvcRttiPeFixtureBuilder, rva: number) => {
  const fixture = builder.build();
  const image = createMsvcRttiImage(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core.sections,
    MSVC_RTTI_FIXTURE_IMAGE_BASE,
    fixture.core.opt.SizeOfImage
  );
  return parseMsvcRttiTypeDescriptor(image, rva);
};

void test("parseMsvcRttiTypeDescriptor accepts class, struct, namespace, and template names", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const names = [".?AVClassName@@", ".?AUStructName@@", ".?AV?$Box@H@ns@@"];
  const types = names.map(name => builder.addType(name));

  const parsed = await Promise.all(types.map(type => parseType(builder, type.rva)));

  assert.deepEqual(parsed.map(type => type?.decoratedName), names);
});

void test("parseMsvcRttiTypeDescriptor rejects a non-class decorated name", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(".?AW4Enum@@");

  const parsed = await parseType(builder, type.rva);

  assert.equal(parsed, null);
});

void test("parseMsvcRttiTypeDescriptor rejects control bytes", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(".?AVControl@@");
  builder.patchByte(type.nameRva + 5, 0x1f);

  const parsed = await parseType(builder, type.rva);

  assert.equal(parsed, null);
});

void test("parseMsvcRttiTypeDescriptor rejects a nonzero file-image runtime cache", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(".?AVCached@@");
  // TypeDescriptor +8 is the runtime-populated undecorated-name cache in VCRuntime.
  builder.patchBigUint64(type.rva + 8, 1n);

  const parsed = await parseType(builder, type.rva);

  assert.equal(parsed, null);
});

void test("parseMsvcRttiTypeDescriptor rejects a missing NUL within the hard limit", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(`.?AV${"A".repeat(1018)}@@`);
  builder.patchByte(type.nameRva + 1024, 0x41);

  const parsed = await parseType(builder, type.rva);

  assert.equal(parsed, null);
});

void test("parseMsvcRttiTypeDescriptor rejects a name longer than 1024 bytes", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(`.?AV${"A".repeat(1019)}@@`);

  const parsed = await parseType(builder, type.rva);

  assert.equal(parsed, null);
});

void test("parseMsvcRttiTypeDescriptor accepts a name at the 1024-byte limit", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(`.?AV${"A".repeat(1018)}@@`);

  const parsed = await parseType(builder, type.rva);

  assert.equal(parsed?.decoratedName.length, 1024);
});

void test("parseMsvcRttiTypeDescriptor rejects an empty class encoding", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(".?AV@@");

  const parsed = await parseType(builder, type.rva);

  assert.equal(parsed, null);
});

void test("parseMsvcRttiTypeDescriptor requires the complete name suffix", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(".?AVIncomplete@");

  const parsed = await parseType(builder, type.rva);

  assert.equal(parsed, null);
});

for (const [name, byte] of [["space", 0x20], ["DEL", 0x7f]] as const) {
  void test(`parseMsvcRttiTypeDescriptor rejects a ${name} byte`, async () => {
    const builder = new MsvcRttiPeFixtureBuilder();
    const type = builder.addType(".?AVInvalid@@");
    builder.patchByte(type.nameRva + 5, byte);

    const parsed = await parseType(builder, type.rva);

    assert.equal(parsed, null);
  });
}

void test("parseMsvcRttiTypeDescriptor rejects a truncated fixed record", async () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(".?AVTruncated@@");
  builder.truncateAtRva(type.rva + 8);

  const parsed = await parseType(builder, type.rva);

  assert.equal(parsed, null);
});
