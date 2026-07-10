"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { createMsvcRttiImage } from "../../../../../analyzers/pe/msvc-rtti/image.js";
import { createSimpleMsvcRttiFixture } from "../../../../fixtures/pe-msvc-rtti-fixture.js";

const fixtureImage = () => {
  const subject = createSimpleMsvcRttiFixture();
  const fixture = subject.builder.build();
  const image = createMsvcRttiImage(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core.sections,
    fixture.core.opt.ImageBase,
    fixture.core.opt.SizeOfImage
  );
  return { ...subject, fixture, image };
};

void test("createMsvcRttiImage reads exact file-backed initialized data ranges", async () => {
  const { image, type } = fixtureImage();

  const view = await image.readData(type.rva, 16, 8);

  assert.equal(view?.byteLength, 16);
  assert.equal(image.isDataRange(type.rva, 16, 8), true);
  assert.equal(image.availableDataSize(type.nameRva, 32), 32);
});

void test("createMsvcRttiImage rejects misaligned, executable, and header ranges", async () => {
  const { image, type } = fixtureImage();

  const misaligned = await image.readData(type.rva + 1, 8, 8);
  const executable = await image.readData(0x1000, 8, 8);
  const header = await image.readData(0x100, 8, 8);

  assert.equal(misaligned, null);
  assert.equal(executable, null);
  assert.equal(header, null);
});

void test("createMsvcRttiImage distinguishes executable mapped targets", () => {
  const { image, type } = fixtureImage();

  assert.equal(image.isExecutableRva(0x1000), true);
  assert.equal(image.isExecutableRva(type.rva), false);
  assert.equal(image.isExecutableRva(0x5000), false);
});

void test("createMsvcRttiImage converts only preferred VAs inside SizeOfImage", () => {
  const { fixture, image } = fixtureImage();
  const imageBase = fixture.core.opt.ImageBase;

  assert.equal(image.preferredVaToRva(imageBase + 0x1234n), 0x1234);
  assert.equal(image.preferredVaToRva(imageBase - 1n), null);
  assert.equal(image.preferredVaToRva(imageBase + 0x5000n), null);
});

void test("createMsvcRttiImage reads an aligned preferred pointer slot", async () => {
  const { image, vftable } = fixtureImage();

  const target = await image.readPreferredVaRva(vftable.locatorSlotRva);

  assert.equal(target, vftable.colRva);
});

void test("createMsvcRttiImage rejects a range extending beyond raw section bytes", async () => {
  const subject = createSimpleMsvcRttiFixture();
  const fixture = subject.builder.build();
  const rdata = fixture.core.sections[1]!;
  rdata.sizeOfRawData = subject.type.rva - rdata.virtualAddress + 8;
  const image = createMsvcRttiImage(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core.sections,
    fixture.core.opt.ImageBase,
    fixture.core.opt.SizeOfImage
  );

  const view = await image.readData(subject.type.rva, 16, 8);

  assert.equal(view, null);
  assert.equal(image.availableDataSize(subject.type.rva, 16), 8);
});

void test("createMsvcRttiImage rejects invalid image sizes and read sizes", async () => {
  const { fixture, type } = fixtureImage();
  const image = createMsvcRttiImage(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core.sections,
    fixture.core.opt.ImageBase,
    0
  );

  assert.equal(await image.readData(type.rva, 16, 8), null);
  assert.equal(await image.readData(type.rva, 0, 8), null);
  assert.equal(image.availableDataSize(type.rva, 0), 0);
});

