"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { renderElfTls } from "../../renderers/elf/tls.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("renderElfTls renders TLS segments and sections", async () => {
  const { file } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const out: string[] = [];
  renderElfTls(elf, out);
  const html = out.join("");
  assert.ok(html.includes("<h4"));
  assert.ok(html.includes("TLS"));
  assert.ok(html.includes(".tdata"));
  assert.ok(html.includes("PT_TLS"));
});

