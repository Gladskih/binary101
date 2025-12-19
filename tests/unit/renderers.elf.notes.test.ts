"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { renderElfNotes } from "../../renderers/elf/notes.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("renderElfNotes renders GNU build-id", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const out: string[] = [];
  renderElfNotes(elf, out);
  const html = out.join("");
  assert.ok(html.includes("Notes"));
  assert.ok(html.includes("Build ID"));
  assert.ok(html.includes(expected.buildIdHex));
});

