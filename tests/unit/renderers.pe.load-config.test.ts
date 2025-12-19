"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderLoadConfig } from "../../renderers/pe/load-config.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

void test("renderLoadConfig renders GuardFlags names and CFG function-table entry size", () => {
  const pe = {
    opt: { isPlus: false, ImageBase: 0x400000 },
    loadcfg: {
      GuardFlags: 0x30417500,
      CodeIntegrity: { Flags: 0, Catalog: 0, CatalogOffset: 0, Reserved: 0 }
    }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderLoadConfig(pe, out);
  const html = out.join("");

  assert.ok(html.includes("CF_INSTRUMENTED"));
  assert.ok(html.includes("CF_FUNCTION_TABLE_PRESENT"));
  assert.ok(html.includes("CF_EXPORT_SUPPRESSION_INFO_PRESENT"));
  assert.ok(html.includes("CF_LONGJUMP_TABLE_PRESENT"));
  assert.ok(html.includes("PROTECT_DELAYLOAD_IAT"));
  assert.ok(html.includes("DELAYLOAD_IAT_IN_ITS_OWN_SECTION"));
  assert.ok(html.includes("EH_CONTINUATION_TABLE_PRESENT"));
  assert.ok(html.includes("CF_FUNCTION_TABLE_SIZE_7BYTES"));
});

