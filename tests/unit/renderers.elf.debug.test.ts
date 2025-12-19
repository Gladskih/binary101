"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { renderElfDebug } from "../../renderers/elf/debug.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("renderElfDebug renders .comment and .gnu_debuglink", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const out: string[] = [];
  renderElfDebug(elf, out);
  const html = out.join("");
  assert.ok(html.includes("Build / debug"));
  assert.ok(html.includes(".comment"));
  assert.ok(html.includes(expectDefined(expected.commentStrings[0])));
  assert.ok(html.includes(expected.debugLinkFileName));
});
