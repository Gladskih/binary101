import assert from "node:assert/strict";
import { test } from "node:test";
import { hasCompressedSectionAt, openElfSectionData } from "../../../../analyzers/elf/section-data.js";
import { createMemoryRangeReader } from "../../../../analyzers/memory-range-reader.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";
import { compressElfFixtureSection } from "../../../fixtures/elf-compressed-section.js";

void test("bounds the decoded section separately from its stored size", async () => {
  const { bytes, elf, view } = relocationFixture(32, "big");
  const section = elf.sections[3]!;
  const strings = bytes.slice(Number(section.offset), Number(section.offset + section.size));
  compressElfFixtureSection(bytes, section, 640, { bits: 32, littleEndian: false, codec: "zstd" });
  const reader = createMemoryRangeReader(bytes);
  const issues: string[] = [];
  const source = await openElfSectionData(reader, section, elf, issues);
  assert.equal(source?.offset, 0);
  assert.equal(source?.size, strings.length);
  assert.deepEqual(await source?.reader.readBytes(0, source.size), strings);
  assert.deepEqual(issues, []);

  view.setUint32(644, 64 * 1024 * 1024 + 1, false); // Elf32_Chdr.ch_size.
  assert.equal(await openElfSectionData(reader, section, elf, issues), null);
  assert.match(issues.join(" "), /decoding limit/);
});

void test("does not give SHT_NOBITS a file-backed reader", async () => {
  const { bytes, elf } = relocationFixture();
  const issues: string[] = [];
  const section = { ...elf.sections[1]!, type: 8 }; // gABI SHT_NOBITS.
  assert.equal(await openElfSectionData(createMemoryRangeReader(bytes), section, elf, issues), null);
  assert.match(issues.join(" "), /no file data/);
});

void test("permits allocated compressed sections only outside the executable and shared-object restriction", async () => {
  const fixture = relocationFixture();
  const section = fixture.elf.sections[3]!;
  compressElfFixtureSection(fixture.bytes, section, 640, { bits: 64, littleEndian: true, codec: "zlib" });
  const reader = createMemoryRangeReader(fixture.bytes);
  section.flags |= 2n; // SHF_ALLOC.
  assert.equal((await openElfSectionData(reader, section, fixture.elf, []))?.size, 8);
  fixture.elf.header.type = 2; // ET_EXEC.
  assert.equal(await openElfSectionData(reader, section, fixture.elf, []), null);
  section.flags &= ~2n;
  assert.equal((await openElfSectionData(reader, section, fixture.elf, []))?.size, 8);
  assert.equal((await openElfSectionData(reader, section, { is64: true, littleEndian: true }, []))?.size, 8);
});

void test("checks both limits before fetching bytes and permits the exact boundary", async context => {
  const { bytes, elf, view } = relocationFixture();
  const section = elf.sections[3]!;
  compressElfFixtureSection(bytes, section, 640, { bits: 64, littleEndian: true, codec: "zlib" });
  const limit = 64 * 1024 * 1024;
  const reader = createMemoryRangeReader(bytes);
  // Simulate a sparse file. No large allocations are needed to verify codec dispatch.
  const readBytes = context.mock.fn(async () => new Uint8Array());
  const sparse = { ...reader, size: Number(section.offset) + 24 + limit + 1, readBytes };
  section.size = BigInt(24 + limit + 1);
  view.setBigUint64(648, BigInt(limit), true);
  const exceeded: string[] = [];
  assert.equal(await openElfSectionData(sparse, section, elf, exceeded), null);
  assert.match(exceeded[0]!, /limit/);
  assert.equal(readBytes.mock.callCount(), 0);
  section.size -= 1n;
  const admitted: string[] = [];
  assert.equal(await openElfSectionData(sparse, section, elf, admitted), null);
  assert.match(admitted[0]!, /payload is truncated/);
  assert.equal(readBytes.mock.callCount(), 1);
});

void test("detects an address only inside a compressed section of the requested type", () => {
  const fixture = relocationFixture();
  const section = fixture.elf.sections[3]!;
  compressElfFixtureSection(fixture.bytes, section, 640, { bits: 64, littleEndian: true, codec: "zlib" });
  const end = Number(section.offset + section.size);
  assert.equal(hasCompressedSectionAt(fixture.elf.sections, 3, 639), false);
  assert.equal(hasCompressedSectionAt(fixture.elf.sections, 3, 640), true);
  assert.equal(hasCompressedSectionAt(fixture.elf.sections, 3, end - 1), true);
  assert.equal(hasCompressedSectionAt(fixture.elf.sections, 3, end), false);
  assert.equal(hasCompressedSectionAt(fixture.elf.sections, 2, 640), false);
  section.flags = 0n;
  assert.equal(hasCompressedSectionAt(fixture.elf.sections, 3, 640), false);
});
