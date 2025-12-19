"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { renderElfSymbols } from "../../renderers/elf/symbols.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("renderElfSymbols renders import/export tables", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const out: string[] = [];
  renderElfSymbols(elf, out);
  const html = out.join("");
  assert.ok(html.includes("Imports / exports"));
  assert.ok(html.includes("Imported symbols"));
  assert.ok(html.includes("Exported symbols"));
  assert.ok(html.includes(expected.importSymbol));
  assert.ok(html.includes(expected.exportSymbol));
});

