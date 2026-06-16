"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderLoadConfig } from "../../../../renderers/pe/load-config.js";
import { createPeLoadConfigResult } from "../../../../analyzers/pe/load-config/result.js";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";

// Microsoft PE format documents 0x00400000 as the historical PE32 executable ImageBase.
const PE32_DEFAULT_IMAGE_BASE = 0x400000n;
// Synthetic RVAs stay 16-byte aligned because GFIDS checks treat target RVAs as function starts.
const CFG_TABLE_RVA = 0x1000;
const TABLE_ENTRY_COUNT_OVER_RENDER_LIMIT = 513;

const makePe = (
  loadcfg: ReturnType<typeof createPeLoadConfigResult>,
  opt: PeWindowsParseResult["opt"] = {
    Magic: 0x10b,
    ImageBase: PE32_DEFAULT_IMAGE_BASE
  } as PeWindowsParseResult["opt"]
): PeWindowsParseResult => ({
  opt,
  sections: [],
  loadcfg
}) as unknown as PeWindowsParseResult;

void test("renderLoadConfig renders GuardFlags names and CFG function-table entry size", () => {
  const loadcfg = createPeLoadConfigResult();
  Object.assign(loadcfg, {
    // Fixture combines documented GuardFlags, including high-nibble stride 3 for 7-byte GFIDS entries.
    GuardFlags: 0x30417500,
    Size: 64,
    CodeIntegrity: { Flags: 0, Catalog: 0, CatalogOffset: 0, Reserved: 0 },
    checks: [{
      status: "fail",
      title: "CFG header agreement",
      detail: "IMAGE_DLLCHARACTERISTICS_GUARD_CF and IMAGE_GUARD_CF_INSTRUMENTED should agree."
    }],
    tables: {
      guardFid: {
        kind: "guardFid",
        name: "GuardCFFunctionTable",
        tableVa: PE32_DEFAULT_IMAGE_BASE + BigInt(CFG_TABLE_RVA),
        tableRva: CFG_TABLE_RVA,
        declaredCount: 1,
        entrySize: 5,
        truncated: false,
        entries: [{
          index: 0,
          rva: CFG_TABLE_RVA + 0x10,
          metadataBytes: [0x03],
          gfidsFlags: ["FID_SUPPRESSED", "EXPORT_SUPPRESSED"]
        }]
      }
    }
  });
  const pe = makePe(loadcfg);

  const out: string[] = [];
  renderLoadConfig(pe, out);
  const html = out.join("");

  assert.match(html, /<summary[^>]*><b>Load Config<\/b> - v0\.0<\/summary>/);
  assert.ok(html.includes("CF_INSTRUMENTED"));
  assert.ok(html.includes("CF_FUNCTION_TABLE_PRESENT"));
  assert.ok(html.includes("CF_EXPORT_SUPPRESSION_INFO_PRESENT"));
  assert.ok(html.includes("CF_LONGJUMP_TABLE_PRESENT"));
  assert.ok(html.includes("PROTECT_DELAYLOAD_IAT"));
  assert.ok(html.includes("DELAYLOAD_IAT_IN_ITS_OWN_SECTION"));
  assert.ok(html.includes("EH_CONTINUATION_TABLE_PRESENT"));
  assert.ok(html.includes("CF_FUNCTION_TABLE_SIZE_7BYTES"));
  assert.ok(html.includes("Load Config cross-checks"));
  assert.ok(html.includes("CFG header agreement"));
  assert.ok(html.indexOf("Load Config cross-checks") > html.indexOf("GuardFlags"));
  assert.ok(html.includes("64 B (64 bytes)"));
  assert.ok(html.includes("Module contains compiler-inserted CFG checks"));
  assert.ok(html.includes("GuardCFFunctionTable (1/1)"));
  assert.ok(html.includes("FID_SUPPRESSED, EXPORT_SUPPRESSED"));
});

void test("renderLoadConfig aggregates large uniform Load Config tables", () => {
  const loadcfg = createPeLoadConfigResult();
  loadcfg.tables = {
    guardFid: {
      kind: "guardFid",
      name: "GuardCFFunctionTable",
      tableVa: PE32_DEFAULT_IMAGE_BASE + BigInt(CFG_TABLE_RVA),
      tableRva: CFG_TABLE_RVA,
      declaredCount: TABLE_ENTRY_COUNT_OVER_RENDER_LIMIT,
      entrySize: 4,
      truncated: false,
      entries: Array.from({ length: TABLE_ENTRY_COUNT_OVER_RENDER_LIMIT }, (_, index) => ({
        index,
        rva: CFG_TABLE_RVA + index * 0x10
      }))
    }
  };
  const pe = makePe(loadcfg);

  const out: string[] = [];
  renderLoadConfig(pe, out);
  const html = out.join("");

  // Renderer contract: uniform address tables are summarized instead of rendering useless rows.
  assert.ok(html.includes("loadConfigSummaryTable"));
  assert.ok(html.includes("<th scope=\"row\">GuardCFFunctionTable</th>"));
  assert.ok(html.includes("<td class=\"num\">513</td>"));
  assert.ok(html.includes("<td>(outside sections)</td>"));
  assert.ok(html.includes("<td class=\"num\">4 bytes</td>"));
  assert.ok(!html.includes("showing first 512; 1 hidden"));
  assert.ok(!html.includes(
    `GuardCFFunctionTable (${TABLE_ENTRY_COUNT_OVER_RENDER_LIMIT}/${TABLE_ENTRY_COUNT_OVER_RENDER_LIMIT})`
  ));
});

void test("renderLoadConfig renders Load Config notes without warning styling", () => {
  const loadcfg = createPeLoadConfigResult();
  loadcfg.notes = ["LOAD_CONFIG: SecurityCookie RVA 0x500 is not backed by raw file data."];
  loadcfg.tables = {
    safeSehHandler: {
      kind: "safeSeh",
      name: "SEHandlerTable",
      tableVa: PE32_DEFAULT_IMAGE_BASE + BigInt(CFG_TABLE_RVA),
      tableRva: CFG_TABLE_RVA,
      declaredCount: 1,
      entrySize: 4,
      truncated: true,
      entries: [],
      notes: ["SEHandlerTable: table RVA 0x1000 is not backed by raw file data."]
    }
  };
  const pe = makePe(loadcfg);

  const out: string[] = [];
  renderLoadConfig(pe, out);
  const html = out.join("");

  assert.ok(html.includes("SecurityCookie RVA 0x500 is not backed by raw file data."));
  assert.ok(html.includes("SEHandlerTable: table RVA 0x1000 is not backed by raw file data."));
  assert.ok(!html.includes("color:var(--warn-fg)"));
});

void test("renderLoadConfig labels known dynamic relocation symbols", () => {
  const loadcfg = createPeLoadConfigResult();
  loadcfg.dynamicRelocations = {
    version: 2, // Dynamic relocation v2 rows include symbol and fixup payload columns.
    dataSize: 20,
    entries: [{
      kind: "v2",
      headerSize: 24,
      fixupInfoSize: 4,
      symbol: 6n, // LLVM COFF IMAGE_DYNAMIC_RELOCATION_ARM64X currently uses symbol value 6.
      symbolGroup: 0,
      flags: 0,
      availableBytes: 4
    }]
  };
  const pe = makePe(
    loadcfg,
    {
      Magic: 0x20b, // Microsoft PE Optional Header magic for PE32+.
      ImageBase: 0x140000000n // Common PE32+ fixture base used to exercise 64-bit VA rendering.
    } as PeWindowsParseResult["opt"]
  );

  const out: string[] = [];
  renderLoadConfig(pe, out);
  const html = out.join("");
  const dynamicRelocationsStart = html.indexOf("loadConfigDynamicSummaryTable");
  assert.notEqual(dynamicRelocationsStart, -1);
  const dynamicHtml = html.slice(dynamicRelocationsStart);

  assert.ok(html.includes("ARM64X"));
  assert.ok(dynamicHtml.includes("loadConfigDynamicSummaryTable"));
  assert.ok(dynamicHtml.includes("20 B (20 bytes)"));
  assert.ok(dynamicHtml.includes("<td>0x6</td>"));
  assert.ok(dynamicHtml.includes("<td>ARM64X</td>"));
  assert.ok(!dynamicHtml.includes("<th scope=\"col\">Type</th>"));
  assert.ok(!dynamicHtml.includes("<th scope=\"col\">Entry</th>"));
  assert.ok(!dynamicHtml.includes("<details"));
  assert.ok(!dynamicHtml.includes("<dl"));
  assert.ok(!dynamicHtml.includes("<th>#</th><th>Kind</th>"));
});
