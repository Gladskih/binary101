import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfUnwind } from "../../../../analyzers/elf/unwind.js";
import { elfSegmentUnwindFixture, elfUnwindFixture } from "../../../fixtures/elf-unwind.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

void test("uses PT_GNU_EH_FRAME when an incomplete section table has no .eh_frame name", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = [relocationSection(0, { type: 0 }), relocationSection(1, {
    offset: 64n, size: 48n, addr: 4096n
  })];

  const result = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(result.length, 1);
  assert.equal(result[0]?.programHeaderIndex, 1);
  assert.equal(result[0]?.fdes[0]?.start?.address, 8192n);
});

void test("keeps a malformed .eh_frame diagnostic once when PT_GNU_EH_FRAME aliases it", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = elfUnwindFixture().elf.sections;
  fixture.view.setUint32(64, 3, true); // Record length cannot hold the four-byte CIE ID.

  const result = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(result.length, 1);
  assert.equal(result[0]?.sectionIndex, 1);
  assert.equal(result[0].issues.length, 1);
});

void test("uses independently bounded segment bytes when .eh_frame has an out-of-file size", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = elfUnwindFixture().elf.sections;
  fixture.elf.sections[1]!.size = BigInt(fixture.bytes.length);

  const result = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.deepEqual(result.map(section => [section.sectionIndex, section.fdes.length]), [[1, 0], [null, 1]]);
  assert.match(result[0]!.issues[0]!, /outside the file/);
});

void test("treats .eh_frame section ends as exclusive when resolving a segment alias", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = elfUnwindFixture().elf.sections;
  Object.assign(fixture.elf.sections[1]!, { offset: 60n, size: 4n });

  const result = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.deepEqual(result.map(section => [section.sectionIndex, section.fdes.length]), [[1, 0], [null, 1]]);
});

void test("keeps a valid .eh_frame without following an unused malformed program header", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = elfUnwindFixture().elf.sections;
  fixture.bytes[128] = 2; // .eh_frame_hdr currently uses version 1.
  fixture.elf.dwarf = { sections: [], linePrograms: [], units: [], issues: [] };

  const result = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.deepEqual(result.map(section => [section.sectionIndex, section.fdes.length, section.issues]),
    [[1, 1, []]]);
});

void test("reuses .debug_frame records independently of runtime frames and their file ranges", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = [relocationSection(0, { type: 0 }), relocationSection(1, {
    name: ".debug_frame", offset: 64n, size: 48n
  })];
  fixture.elf.dwarf = { sections: [], linePrograms: [], units: [], issues: [], frames: {
    cies: [], fdes: [{ offset: 0, cieOffset: 0, start: 2048n, segment: null, range: 3n, instructions: [] }]
  } };

  const result = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.deepEqual(result.map(section => section.fdes[0]?.start?.address), [2048n, 8192n]);

  delete fixture.elf.dwarf.frames;
  const emptyDebugFrames = await parseElfUnwind(fixture.file(), fixture.elf);
  assert.deepEqual(emptyDebugFrames[0], { sectionIndex: 1, cies: [], fdes: [], issues: [] });
  assert.deepEqual(emptyDebugFrames.map(section => section.fdes.length), [0, 1]);
});

void test("tries separate segment storage after dropping an invalid section FDE", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.bytes.copyWithin(256, 64, 112);
  const section = relocationSection(1, { name: ".eh_frame", offset: 256n, size: 48n, addr: 4096n });
  fixture.elf.sections = [relocationSection(0, { type: 0 }), section];
  fixture.view.setInt32(256 + 32, -1, true); // FDE PC range uses the CIE's signed data format.

  const result = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.deepEqual(result.map(frames => frames.fdes.length), [0, 1]);
  assert.match(result[0]!.issues.join(" "), /PC range is negative/);
});
