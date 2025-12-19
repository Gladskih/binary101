"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { parseElfDebugLink } from "../../analyzers/elf/debug-link.js";
import type { ElfSectionHeader } from "../../analyzers/elf/types.js";
import { MockFile } from "../helpers/mock-file.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";

const makeSection = (partial: Partial<ElfSectionHeader>): ElfSectionHeader =>
  ({
    nameOff: 0,
    type: 0,
    typeName: null,
    flags: 0n,
    flagNames: [],
    addr: 0n,
    offset: 0n,
    size: 0n,
    link: 0,
    info: 0,
    addralign: 0n,
    entsize: 0n,
    index: 0,
    ...partial
  }) as ElfSectionHeader;

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
  const sections: ElfSectionHeader[] = [makeSection({ name: ".gnu_debuglink", offset: 0n, size: BigInt(bytes.length), index: 0 })];

  const debugLink = await parseElfDebugLink(file, sections, true);
  assert.ok(debugLink);
  assert.ok(debugLink.issues.some(issue => issue.includes("CRC32")));
});
