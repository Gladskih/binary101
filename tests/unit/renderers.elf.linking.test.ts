"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { renderElfLinking } from "../../renderers/elf/linking.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("renderElfLinking renders interpreter and DT_NEEDED libraries", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const out: string[] = [];
  renderElfLinking(elf, out);
  const html = out.join("");
  assert.ok(html.includes("Dynamic linking"));
  assert.ok(html.includes(expected.interpreter));
  assert.ok(html.includes(expectDefined(expected.needed[0])));
  assert.ok(html.includes(expectDefined(expected.needed[1])));
  assert.ok(html.includes(expected.soname));
  assert.ok(html.includes(expected.runpath));
});
