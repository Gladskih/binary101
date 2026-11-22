"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { renderElfTls } from "../../../../renderers/elf/tls.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

void test("renderElfTls renders TLS segments and sections", async () => {
  const { file } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const out: string[] = [];
  renderElfTls(elf, out);
  const html = out.join("");
  assert.ok(html.includes('<summary class="peSectionSummary"><b>TLS</b></summary>'));
  assert.ok(html.includes("TLS"));
  assert.ok(html.includes(".tdata"));
  assert.ok(html.includes("PT_TLS"));
  assert.match(html, /<caption>PT_TLS segments<\/caption>/);
  assert.match(html, /<caption>TLS sections<\/caption>/);
  assert.doesNotMatch(html, /<summary[^>]*>Show (?:PT_TLS segments|TLS sections)/);
});

void test("renders TLS consistency warnings with the segment they describe", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  elf.tls!.issues = ["PT_TLS #4: p_filesz exceeds p_memsz. <invalid>"];
  const out: string[] = [];

  renderElfTls(elf, out);

  assert.match(out.join(""), /p_filesz exceeds p_memsz.*&lt;invalid>/);
});

