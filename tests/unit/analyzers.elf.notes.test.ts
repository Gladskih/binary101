"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { parseElfNotes } from "../../analyzers/elf/notes.js";
import type { ElfProgramHeader, ElfSectionHeader } from "../../analyzers/elf/types.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { MockFile } from "../helpers/mock-file.js";

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

void test("parseElfNotes decodes GNU build-id", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  assert.ok(parsed?.notes);
  const buildId = parsed.notes.entries.find(entry => entry.typeName === "NT_GNU_BUILD_ID");
  assert.ok(buildId);
  assert.equal(buildId.value, expected.buildIdHex);
});

void test("parseElfNotes reports truncated note payloads", async () => {
  const namesz = 4;
  const descsz = 32;
  const bytes = new Uint8Array(12 + namesz + 4).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, namesz, true);
  dv.setUint32(4, descsz, true);
  dv.setUint32(8, 3, true);
  bytes.set(new TextEncoder().encode("GNU\0"), 12);
  const file = new MockFile(bytes, "note.bin", "application/x-elf");
  const sections: ElfSectionHeader[] = [makeSection({ type: 7, name: ".note.gnu.build-id", offset: 0n, size: BigInt(bytes.length), index: 0 })];

  const notes = await parseElfNotes({ file, programHeaders: [] as ElfProgramHeader[], sections, littleEndian: true });
  assert.ok(notes);
  assert.ok(notes.issues.some(issue => issue.includes("truncated")));
});
