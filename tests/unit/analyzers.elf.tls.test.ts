"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { parseElfTlsInfo } from "../../analyzers/elf/tls.js";
import { createElfFile } from "../fixtures/elf-sample-file.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseElfTlsInfo collects PT_TLS segments and TLS sections", async () => {
  const { file } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const tls = parseElfTlsInfo(elf.programHeaders, elf.sections);
  assert.ok(tls);
  assert.equal(tls.segments.length, 1);
  assert.equal(tls.sections.some(sec => sec.name === ".tdata"), true);
});

void test("parseElfTlsInfo returns null when no TLS is present", async () => {
  const file = createElfFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  assert.equal(parseElfTlsInfo(elf.programHeaders, elf.sections), null);
});

