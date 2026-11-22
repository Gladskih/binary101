import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfDynamicInfo } from "../../../../analyzers/elf/dynamic-info.js";
import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
import type { ElfRelocationSymbol } from "../../../../analyzers/elf/relocation-types.js";
import { compressElfFixtureSection } from "../../../fixtures/elf-compressed-section.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";

const format = { bits: 64, littleEndian: true, codec: "zlib" } as const;

void test("reads a compressed section-only dynamic table and its linked strings", async () => {
  const fixture = relocationFixture();
  fixture.word(64, 1n); // DT_NEEDED, string at offset one.
  fixture.word(72, 1n);
  const section = relocationSection(4, { type: 6, link: 3, offset: 64n, size: 32n, entsize: 16n });
  fixture.elf.sections.push(section);
  compressElfFixtureSection(fixture.bytes, section, 640, format);
  compressElfFixtureSection(fixture.bytes, fixture.elf.sections[3]!, 704, format);
  const info = await parseElfDynamicInfo({ file: fixture.file(), ...fixture.elf });
  assert.equal(info?.terminated, true);
  assert.deepEqual(info?.needed, ["target"]);
  assert.deepEqual(info?.entries, [{ tag: 1, value: 1n, string: "target" }]);
  assert.deepEqual(info?.issues, []);
});

void test("reads compressed dynamic symbol, string and extended index data without caching fake file offsets", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11; // SHT_DYNSYM.
  fixture.elf.sections[2]!.info = 1;
  fixture.bytes[284] = 0x12; // STB_GLOBAL | STT_FUNC.
  fixture.view.setUint16(286, 0xffff, true);
  const extended = relocationSection(4, { type: 18, link: 2, offset: 512n, size: 8n, entsize: 4n });
  fixture.elf.sections.push(extended);
  fixture.view.setUint32(516, 65536, true);
  compressElfFixtureSection(fixture.bytes, fixture.elf.sections[2]!, 640, format);
  compressElfFixtureSection(fixture.bytes, fixture.elf.sections[3]!, 704, format);
  compressElfFixtureSection(fixture.bytes, extended, 768, format);
  const cache = new Map<number, ElfRelocationSymbol>();
  const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf }, [], cache);
  assert.equal(result?.total, 2);
  assert.equal(result?.exportSymbols[0]?.name, "target");
  assert.equal(result?.exportSymbols[0]?.shndx, 65536);
  assert.deepEqual(result?.issues, []);
  assert.equal(cache.size, 0);
});

void test("does not treat an allocated compressed table as live dynamic data", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.installTags();
  const segment = fixture.elf.programHeaders[1]!;
  const section = relocationSection(4, { type: 6, link: 3, offset: segment.offset, size: segment.filesz });
  fixture.elf.sections.push(section);
  compressElfFixtureSection(fixture.bytes, section, 576, format);
  segment.offset = section.offset;
  segment.filesz = section.size;
  section.flags |= 2n;
  const info = await parseElfDynamicInfo({ file: fixture.file(), ...fixture.elf });
  assert.deepEqual(info?.entries, []);
  assert.equal(info?.terminated, false);
  assert.match(info!.issues.join(" "), /PT_DYNAMIC.*compressed/);
});
