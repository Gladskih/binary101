import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfUnwind } from "../../../../analyzers/elf/unwind.js";
import { elfSegmentUnwindFixture, elfUnwindFixture } from "../../../fixtures/elf-unwind.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";

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

for (const size of [20n, 22n, 32n]) {
  void test(`continues a short in-file .eh_frame of ${size} bytes through its load segment`, async () => {
    const fixture = elfSegmentUnwindFixture();
    fixture.elf.sections = elfUnwindFixture().elf.sections;
    // 20 is the end of the CIE. The larger sizes end inside the FDE length or body.
    fixture.elf.sections[1]!.size = size;

    const result = await parseElfUnwind(fixture.file(), fixture.elf);

    assert.equal(result.length, 1);
    assert.equal(result[0]?.programHeaderIndex, 1);
    assert.equal(result[0]?.cies.length, 1);
    assert.equal(result[0]?.fdes[0]?.start?.address, 8192n);
    assert.match(result[0]!.issues.join(" "), /extends beyond section #1/);
  });
}

const indexedFrames = () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = elfUnwindFixture().elf.sections;
  fixture.elf.sections[1]!.size = 44n; // One CIE and one complete FDE.
  const [load, header] = fixture.elf.programHeaders;
  Object.assign(load!, { filesz: 128n, memsz: 128n });
  Object.assign(header!, { offset: 160n, vaddr: 4192n, filesz: 28n, memsz: 28n });
  fixture.bytes.copyWithin(108, 84, 108); // Repeat the FDE, still referencing the original CIE.
  fixture.view.setUint32(112, 48, true);
  fixture.view.setUint32(132, 0, true);
  // .eh_frame_hdr v1: PC-relative pointer, udata4 count, data-relative sdata4 index.
  fixture.bytes.set([1, 0x1b, 3, 0x3b], 160);
  fixture.view.setInt32(164, 4096 - 4196, true);
  fixture.view.setUint32(168, 2, true);
  fixture.view.setInt32(172, 8192 - 4192, true);
  fixture.view.setInt32(176, 4116 - 4192, true);
  fixture.view.setInt32(180, 8216 - 4192, true);
  fixture.view.setInt32(184, 4140 - 4192, true);
  return fixture;
};

void test("uses the header FDE count when a short section ends between complete FDEs", async () => {
  const fixture = indexedFrames();

  const [result] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(result?.programHeaderIndex, 1);
  assert.equal(result?.cies.length, 1);
  assert.deepEqual(result?.fdes.map(fde => fde.start?.address), [8192n, 8216n]);
});

void test("requires a larger index count before extending a section at a complete FDE boundary", async () => {
  const fixture = indexedFrames();
  fixture.view.setUint32(168, 1, true);

  const [result] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(result?.sectionIndex, 1);
  assert.equal(result?.fdes.length, 1);
  assert.deepEqual(result?.issues, []);
});

void test("continues a truncated second FDE even if the header count is absent", async () => {
  const fixture = indexedFrames();
  fixture.bytes[162] = 0xff; // DW_EH_PE_omit for the FDE count.
  fixture.elf.sections[1]!.size = 52n; // CIE + first FDE + the second FDE's length and CIE reference.

  const [result] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(result?.programHeaderIndex, 1);
  assert.equal(result?.fdes.length, 2);
  assert.match(result!.issues.join(" "), /extends beyond section.*truncated/);
});

void test("keeps the original CIE and diagnostics if continuation reveals no complete FDE", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = elfUnwindFixture().elf.sections;
  fixture.elf.sections[1]!.size = 20n;
  fixture.bytes.copyWithin(84, 64, 84); // A second CIE, followed by an invalid record.
  fixture.view.setUint32(104, 3, true);

  const [result] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(result?.sectionIndex, 1);
  assert.equal(result?.cies.length, 1);
  assert.deepEqual(result?.issues, []);
});

void test("does not rescan the unfinished record when the segment has no additional bytes", async context => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = elfUnwindFixture().elf.sections;
  fixture.elf.sections[1]!.size = 32n;
  Object.assign(fixture.elf.programHeaders[0]!, { filesz: 32n, memsz: 32n });
  const readUint32 = DwarfCursor.prototype.uint32;
  const recordStarts: number[] = [];
  context.mock.method(DwarfCursor.prototype, "uint32", function (this: DwarfCursor) {
    recordStarts.push(this.position);
    return readUint32.call(this);
  });

  const [result] = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.equal(result?.sectionIndex, 1);
  assert.equal(recordStarts.filter(position => position === 20).length, 1);
});

void test("treats .eh_frame section ends as exclusive when resolving a segment alias", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = elfUnwindFixture().elf.sections;
  Object.assign(fixture.elf.sections[1]!, { offset: 60n, size: 4n });

  const result = await parseElfUnwind(fixture.file(), fixture.elf);

  assert.deepEqual(result.map(section => [section.sectionIndex, section.fdes.length]), [[1, 0], [null, 1]]);
});

void test("does not use a section with a different start as coverage for the segment", async () => {
  const fixture = elfSegmentUnwindFixture();
  fixture.elf.sections = elfUnwindFixture().elf.sections;
  Object.assign(fixture.elf.sections[1]!, { offset: 60n, size: 52n, addr: 4092n });

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
