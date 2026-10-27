import assert from "node:assert/strict";
import { test } from "node:test";
import { createEhImage } from "../../../../../analyzers/pe/msvc-eh/image.js";
import { createEhFixture } from "../../../../fixtures/pe-msvc-eh.js";

void test("EH image rejects headers, virtual tails, overflow and nonintegral addresses", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, fixture.core);
  assert.ok(await image.read(subject.dataRva, 4));
  assert.equal(image.available(0x100), 0);
  assert.equal(image.available(0x5000), 0);
  assert.equal(image.available(-1), 0);
  assert.equal(image.available(1.5), 0);
  assert.equal(await image.read(0xffffffff, 4), null);
  assert.equal(await image.read(subject.dataRva, 0), null);
  assert.equal(image.code(subject.dataRva), false);
  assert.equal(image.code(subject.beginRva, 16), true);
  assert.equal(image.code(0x11ff, 2), false);
});

void test("EH mapping does not accept overlapping sections or a range entering an overlap", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  fixture.core.sections.push({ ...fixture.core.sections[0]!, virtualAddress: subject.beginRva + 8 });
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal(image.available(subject.beginRva + 8), 0);
  assert.equal(image.code(subject.beginRva, 9), false);
  assert.equal(await image.read(subject.beginRva, 9), null);
});

void test("EH data requires readable bytes and exact reads", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  fixture.core.sections[1]!.characteristics = 0;
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal(await image.read(subject.dataRva, 4), null);
  fixture.file.read = async () => new DataView(new ArrayBuffer(0));
  const short = createEhImage(fixture.file, fixture.core);
  assert.equal(await short.read(subject.beginRva, 4), null);
});

void test("EH mapping rejects a mapper contradicting the section's physical position", () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const image = createEhImage(fixture.file, { ...fixture.core, rvaToOff: () => null });
  assert.equal(image.available(subject.beginRva), 0);
});

void test("EH image clips raw, virtual and image ends independently and accepts their exact boundary", () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  const section = fixture.core.sections[0]!;
  section.virtualSize = 0;
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal(image.available(section.virtualAddress + section.sizeOfRawData - 1), 1);
  assert.equal(image.code(section.virtualAddress + section.sizeOfRawData - 1), true);
  section.virtualSize = section.sizeOfRawData - 8;
  assert.equal(image.available(section.virtualAddress + section.virtualSize - 1), 1);
  fixture.core.opt.SizeOfImage = subject.beginRva + 8;
  assert.equal(image.available(subject.beginRva), 8);
  assert.equal(image.available(fixture.core.opt.SizeOfImage), 0);
});

void test("AArch64 code alignment is independent of raw readability", async () => {
  const subject = createEhFixture();
  const fixture = subject.builder.build();
  fixture.core.coff.Machine = 0xaa64; // PE IMAGE_FILE_MACHINE_ARM64.
  const image = createEhImage(fixture.file, fixture.core);
  assert.equal(image.code(subject.beginRva), true);
  assert.equal(image.code(subject.beginRva + 1), false);
  assert.ok(await image.read(subject.beginRva + 1, 1));
});
