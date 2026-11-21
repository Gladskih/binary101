"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfDebugLink } from "../../../../analyzers/elf/debug-link.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";
import { compressElfFixtureSection } from "../../../fixtures/elf-compressed-section.js";

void test("parseElfDebugLink reads filename and CRC32", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  assert.ok(parsed?.debugLink);
  assert.equal(parsed.debugLink.fileName, expected.debugLinkFileName);
  assert.equal(parsed.debugLink.crc32, expected.debugLinkCrc32);
});

void test("parseElfDebugLink reports missing CRC32", async () => {
  const bytes = new TextEncoder().encode("sample.debug\0");
  const file = new MockFile(bytes, "debuglink.bin", "application/x-elf");
  const { elf } = relocationFixture();
  elf.sections = [relocationSection(1, { name: ".gnu_debuglink", offset: 0n, size: BigInt(bytes.length) })];

  const debugLink = await parseElfDebugLink(file, elf);
  assert.ok(debugLink);
  assert.ok(debugLink.issues.some(issue => issue.includes("CRC32")));
});

void test("aligns a UTF-8 filename by byte length in a compressed debug link", async () => {
  const fixture = relocationFixture(32, "big");
  // The UTF-8 name occupies four bytes; its terminating NUL moves the CRC to +8.
  fixture.bytes.set(new TextEncoder().encode("éé\0"), 64);
  fixture.view.setUint32(72, 0x11223344, false);
  const section = relocationSection(4, { name: ".gnu_debuglink", offset: 64n, size: 12n });
  fixture.elf.sections.push(section);
  compressElfFixtureSection(fixture.bytes, section, 640, { bits: 32, littleEndian: false, codec: "zstd" });
  assert.deepEqual(await parseElfDebugLink(fixture.file(), fixture.elf),
    { fileName: "éé", crc32: 0x11223344, issues: [] });
});
