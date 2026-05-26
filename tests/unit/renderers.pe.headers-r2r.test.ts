"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import { renderHeaders } from "../../renderers/pe/headers.js";
import { createBasePe } from "../fixtures/pe-renderer-headers-fixture.js";

void test("renderHeaders splits .NET ReadyToRun machine and OS override chips", () => {
  const pe: PeParseResult = createBasePe();
  // .NET ReadyToRun: IMAGE_FILE_MACHINE_AMD64 0x8664 XOR Linux override 0x7B79.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/pedecoder.h
  pe.coff.Machine = 0xfd1d;

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /<dt[^>]*>Machine<\/dt><dd>[\s\S]*>x86-64 \(AMD64\)<\/span>/);
  assert.match(html, /<dt[^>]*>Raw Machine<\/dt><dd>0xfd1d<\/dd>/);
  assert.match(html, /<dt[^>]*>R2R OS override<\/dt><dd>[\s\S]*>Linux<\/span>/);
  assert.doesNotMatch(html, /Linux R2R x86-64/);
});
