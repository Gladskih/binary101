"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfComment } from "../../../../analyzers/elf/comment.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";
import { compressElfFixtureSection } from "../../../fixtures/elf-compressed-section.js";

void test("parseElfComment reads NUL-separated compiler strings", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  assert.ok(parsed?.comment);
  assert.deepEqual(parsed.comment.strings, expected.commentStrings);
});

void test("parseElfComment reports truncation", async () => {
  const bytes = new TextEncoder().encode("ABC\0");
  const file = new MockFile(bytes, "comment.bin", "application/x-elf");
  const { elf } = relocationFixture();
  elf.sections = [relocationSection(1, { name: ".comment", offset: 0n, size: 32n })];

  const comment = await parseElfComment(file, elf);
  assert.ok(comment);
  assert.ok(comment.issues.some(issue => issue.includes("truncated")));
});

void test("decodes compressed compiler strings and drops an unterminated final fragment", async () => {
  const fixture = relocationFixture();
  const data = new TextEncoder().encode("compiler\0partial");
  fixture.bytes.set(data, 64);
  const section = relocationSection(4, { name: ".comment", offset: 64n, size: BigInt(data.length) });
  fixture.elf.sections.push(section);
  compressElfFixtureSection(fixture.bytes, section, 640, { bits: 64, littleEndian: true, codec: "zlib" });
  const result = await parseElfComment(fixture.file(), fixture.elf);
  assert.deepEqual(result?.strings, ["compiler"]);
  assert.match(result!.issues.join(" "), /Unterminated/);
});
