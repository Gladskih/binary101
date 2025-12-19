"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { parseElfComment } from "../../analyzers/elf/comment.js";
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

void test("parseElfComment reads NUL-separated compiler strings", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  assert.ok(parsed?.comment);
  assert.deepEqual(parsed.comment.strings, expected.commentStrings);
});

void test("parseElfComment reports truncation", async () => {
  const bytes = new TextEncoder().encode("ABC\0");
  const file = new MockFile(bytes, "comment.bin", "application/x-elf");
  const sections: ElfSectionHeader[] = [makeSection({ name: ".comment", offset: 0n, size: 32n, index: 0 })];

  const comment = await parseElfComment(file, sections);
  assert.ok(comment);
  assert.ok(comment.issues.some(issue => issue.includes("truncated")));
});
