"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeLoadConfigResult } from "../../../../analyzers/pe/load-config/result.js";
import type { PeLoadConfigTable } from "../../../../analyzers/pe/load-config/index.js";
import { inlinePeSectionName } from "../../../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../../../analyzers/pe/types.js";
import {
  getDynamicRelocationSymbolName,
  renderLoadConfigAddressTable,
  renderLoadConfigChecks,
  renderLoadConfigDynamicRelocations,
  renderLoadConfigGuardFlags
} from "../../../../renderers/pe/load-config-widgets.js";

// Microsoft PE format documents 0x00400000 as the historical PE32 executable ImageBase.
const IMAGE_BASE = 0x400000n;
// Synthetic RVAs stay 16-byte aligned because GFIDS checks treat target RVAs as function starts.
const SECTION_RVA = 0x1000;
const CFG_TARGET_RVA = 0x1010;
const TABLE_ENTRY_COUNT_OVER_RENDER_LIMIT = 513;

const textSection: PeSection = {
  name: inlinePeSectionName(".text"),
  virtualSize: 0x2000,
  virtualAddress: SECTION_RVA,
  sizeOfRawData: 0x2000,
  pointerToRawData: 0x200,
  // PE section flags: CNT_CODE | MEM_EXECUTE | MEM_READ.
  characteristics: 0x60000020
};

const table = (entryCount: number): PeLoadConfigTable => ({
  kind: "guardFid",
  name: "GuardCFFunctionTable",
  tableVa: IMAGE_BASE + BigInt(SECTION_RVA),
  tableRva: SECTION_RVA,
  declaredCount: entryCount,
  entrySize: 5,
  truncated: false,
  entries: Array.from({ length: entryCount }, (_, index) => ({
    index,
    rva: CFG_TARGET_RVA + index * 0x10,
    metadataBytes: [0x03],
    gfidsFlags: ["FID_SUPPRESSED", "EXPORT_SUPPRESSED"]
  }))
});

void test("renderLoadConfigGuardFlags renders decoded chips and inline explanations", () => {
  const loadConfig = createPeLoadConfigResult();
  loadConfig.GuardFlags =
    0x00000100 | // Microsoft PE GuardFlags: CF_INSTRUMENTED.
    0x00000400 | // Microsoft PE GuardFlags: CF_FUNCTION_TABLE_PRESENT.
    0x30000000; // GuardFlags high nibble 3 encodes 3 extra bytes, so GFIDS entries are 7 bytes.

  const html = renderLoadConfigGuardFlags(loadConfig);

  assert.ok(html.includes("CF_INSTRUMENTED"));
  assert.ok(html.includes("CF_FUNCTION_TABLE_PRESENT"));
  assert.ok(html.includes("CF_FUNCTION_TABLE_SIZE_7BYTES"));
  assert.ok(html.includes("Module contains compiler-inserted CFG checks"));
});

void test("renderLoadConfigChecks escapes checklist text and maps fail status", () => {
  const loadConfig = createPeLoadConfigResult();
  loadConfig.checks = [{
    status: "fail",
    title: "Bad <field>",
    detail: "Value \"x\" is invalid",
    source: "unit test"
  }];

  const html = renderLoadConfigChecks(loadConfig);

  assert.ok(html.includes("manifestCheckItem--fail"));
  assert.ok(html.includes("Bad &lt;field>"));
  assert.ok(html.includes("&quot;x&quot;"));
});

void test("renderLoadConfigChecks renders pass checks with pass styling and a check mark", () => {
  const loadConfig = createPeLoadConfigResult();
  loadConfig.checks = [{
    status: "pass",
    title: "CFG header agreement",
    detail: "Fields agree."
  }];

  const html = renderLoadConfigChecks(loadConfig);

  assert.match(
    html,
    /<li class="manifestCheckItem manifestCheckItem--pass"><span class="manifestCheckIcon">&#10003;<\/span>/
  );
  assert.ok(html.includes("<b>CFG header agreement</b>: Fields agree."));
});

void test("renderLoadConfigAddressTable caps large tables and renders metadata", () => {
  const html = renderLoadConfigAddressTable(
    table(TABLE_ENTRY_COUNT_OVER_RENDER_LIMIT),
    [textSection],
    IMAGE_BASE,
    8, // 32-bit VAs render as 8 hex digits in the address table.
    "GFIDS table"
  );

  assert.ok(html.includes(
    `GuardCFFunctionTable (${TABLE_ENTRY_COUNT_OVER_RENDER_LIMIT}/${TABLE_ENTRY_COUNT_OVER_RENDER_LIMIT})`
  ));
  assert.ok(html.includes("showing first 512; 1 hidden"));
  assert.ok(html.includes("loadConfigAddressTableBody"));
  assert.ok(html.includes("FID_SUPPRESSED, EXPORT_SUPPRESSED"));
  assert.ok(html.includes(".text"));
});

void test("renderLoadConfigAddressTable aggregates uniform rows without metadata", () => {
  const plainTable: PeLoadConfigTable = {
    ...table(3),
    entries: Array.from({ length: 3 }, (_, index) => ({
      index,
      rva: CFG_TARGET_RVA + index * 0x10
    }))
  };

  const html = renderLoadConfigAddressTable(plainTable, [textSection], IMAGE_BASE, 8, "GFIDS table");

  assert.ok(html.includes("loadConfigSummaryTable"));
  assert.ok(html.includes("<th scope=\"col\">Table</th>"));
  assert.ok(html.includes("<th scope=\"row\">GuardCFFunctionTable</th>"));
  assert.ok(html.includes("<td class=\"num\">3</td>"));
  assert.ok(html.includes("<td>.text</td>"));
  assert.ok(html.includes("<td class=\"num\">5 bytes</td>"));
  assert.ok(html.includes("<td>0x00001000</td>"));
  assert.ok(!html.includes("<summary"));
  assert.ok(!html.includes("<th>Metadata</th>"));
  assert.ok(!html.includes("beyond the render limit"));
});

void test("getDynamicRelocationSymbolName labels known and unknown symbols", () => {
  // LLVM COFF IMAGE_DYNAMIC_RELOCATION_ARM64X currently uses symbol value 6.
  assert.equal(getDynamicRelocationSymbolName(6n), "ARM64X");
  // 0xffff is outside the documented dynamic relocation symbol set and should stay explicit.
  assert.equal(getDynamicRelocationSymbolName(0xffffn), "UNKNOWN");
});

void test("renderLoadConfigDynamicRelocations summarizes a single entry without details", () => {
  const html = renderLoadConfigDynamicRelocations({
    version: 1,
    dataSize: 80,
    entries: [{
      kind: "v1",
      symbol: 7n,
      baseRelocSize: 68,
      availableBytes: 68
    }]
  });

  assert.ok(html.includes("loadConfigDynamicSummaryTable"));
  assert.ok(html.includes("80 B (80 bytes)"));
  assert.ok(html.includes("<th scope=\"col\">Symbol</th>"));
  assert.ok(html.includes("<th scope=\"col\">Name</th>"));
  assert.ok(html.includes("<td>0x7</td>"));
  assert.ok(html.includes("<td>UNKNOWN</td>"));
  assert.ok(!html.includes("<th scope=\"col\">Type</th>"));
  assert.ok(!html.includes("<th scope=\"col\">Entry</th>"));
  assert.ok(!html.includes("68 B (68 bytes)"));
  assert.ok(!html.includes("Status</th>"));
  assert.ok(!html.includes("<details"));
  assert.ok(!html.includes("<dl"));
  assert.ok(!html.includes("<th>#</th><th>Kind</th>"));
});

void test("renderLoadConfigDynamicRelocations keeps truncated single-entry status visible", () => {
  const html = renderLoadConfigDynamicRelocations({
    version: 1,
    dataSize: 80,
    entries: [{
      kind: "v1",
      symbol: 7n,
      baseRelocSize: 68,
      availableBytes: 32
    }]
  });

  assert.ok(html.includes("<th scope=\"col\">Payload</th>"));
  assert.ok(html.includes("<td>68 B (68 bytes)</td>"));
  assert.ok(html.includes("<td>32 B (32 bytes)</td>"));
  assert.ok(html.includes("<td class=\"loadConfigStatusWarn\">truncated</td>"));
});
