"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAndEnrichLoadConfig } from "../../analyzers/pe/load-config/enrich.js";
import { createPeLoadConfigResult } from "../../analyzers/pe/load-config/result.js";
import type { PeDynamicRelocations } from "../../analyzers/pe/dynamic-relocations/index.js";
import type { PeLoadConfig, PeLoadConfigTable } from "../../analyzers/pe/load-config/index.js";
import { MockFile } from "../helpers/mock-file.js";

// Microsoft PE format documents 0x00400000 as the historical PE32 executable ImageBase.
const IMAGE_BASE = 0x400000n;
// Small fixture RVA used to keep synthetic Load Config tables inside the mock file.
const TABLE_RVA = 0x80;
const TABLE_VA = IMAGE_BASE + BigInt(TABLE_RVA);
// Synthetic code RVA; only the exact value matters because the CFG table stores RVAs.
const CFG_TARGET_RVA = 0x1000;
const MOCK_FILE_SIZE = 0x200;

const parseWith = (
  reader: MockFile,
  loadConfig: PeLoadConfig | null,
  parseDynamicRelocations: () => Promise<PeDynamicRelocations | null> = async () => null,
  readSafeSehHandlerTable: (() => Promise<PeLoadConfigTable>) | null = null
): Promise<PeLoadConfig | null> =>
  parseAndEnrichLoadConfig(
    reader,
    [],
    (rva: number) => rva,
    IMAGE_BASE,
    MOCK_FILE_SIZE,
    [],
    async () => loadConfig,
    parseDynamicRelocations,
    readSafeSehHandlerTable
  );

void test("parseAndEnrichLoadConfig returns null when no LOAD_CONFIG is present", async () => {
  assert.equal(await parseWith(new MockFile(new Uint8Array(MOCK_FILE_SIZE)), null), null);
});

void test("parseAndEnrichLoadConfig attaches structured CFG table entries and dynamic relocations", async () => {
  const bytes = new Uint8Array(MOCK_FILE_SIZE).fill(0);
  new DataView(bytes.buffer).setUint32(TABLE_RVA, CFG_TARGET_RVA, true);
  const loadConfig = createPeLoadConfigResult();
  loadConfig.GuardCFFunctionTable = TABLE_VA;
  loadConfig.GuardCFFunctionCount = 1;

  const enriched = await parseWith(
    new MockFile(bytes, "loadcfg-enrich.bin"),
    loadConfig,
    async () => ({ version: 1, dataSize: 0, entries: [] })
  );

  assert.deepEqual(enriched?.tables?.guardFid?.entries.map(entry => entry.rva), [CFG_TARGET_RVA]);
  assert.equal(enriched?.dynamicRelocations?.version, 1);
});

void test("parseAndEnrichLoadConfig attaches each supported Load Config address table", async () => {
  const bytes = new Uint8Array(MOCK_FILE_SIZE).fill(0);
  new DataView(bytes.buffer).setUint32(TABLE_RVA, CFG_TARGET_RVA, true);
  const loadConfig = createPeLoadConfigResult();
  Object.assign(loadConfig, {
    GuardCFFunctionTable: TABLE_VA,
    GuardCFFunctionCount: 1,
    GuardEHContinuationTable: TABLE_VA,
    GuardEHContinuationCount: 1,
    GuardLongJumpTargetTable: TABLE_VA,
    GuardLongJumpTargetCount: 1,
    GuardAddressTakenIatEntryTable: TABLE_VA,
    GuardAddressTakenIatEntryCount: 1,
    SEHandlerTable: TABLE_VA,
    SEHandlerCount: 1
  });
  const safeSehTable: PeLoadConfigTable = {
    kind: "safeSeh",
    name: "SEHandlerTable",
    tableVa: TABLE_VA,
    tableRva: TABLE_RVA,
    declaredCount: 1,
    entrySize: Uint32Array.BYTES_PER_ELEMENT,
    truncated: false,
    entries: [{ index: 0, rva: CFG_TARGET_RVA }]
  };

  const enriched = await parseWith(
    new MockFile(bytes, "loadcfg-all-tables.bin"),
    loadConfig,
    async () => null,
    async () => safeSehTable
  );

  assert.deepEqual(enriched?.tables?.guardEhContinuation?.entries.map(entry => entry.rva), [CFG_TARGET_RVA]);
  assert.deepEqual(enriched?.tables?.guardLongJumpTarget?.entries.map(entry => entry.rva), [CFG_TARGET_RVA]);
  assert.deepEqual(enriched?.tables?.guardIat?.entries.map(entry => entry.rva), [CFG_TARGET_RVA]);
  assert.deepEqual(enriched?.tables?.safeSehHandler?.entries.map(entry => entry.rva), [CFG_TARGET_RVA]);
});

void test("parseAndEnrichLoadConfig collects warnings when optional readers fail", async () => {
  const loadConfig = createPeLoadConfigResult();
  loadConfig.SEHandlerTable = TABLE_VA;
  loadConfig.SEHandlerCount = 1;

  const enriched = await parseWith(
    new MockFile(new Uint8Array(MOCK_FILE_SIZE), "loadcfg-reader-fail.bin"),
    loadConfig,
    async () => {
      throw new Error("dynamic relocation failure");
    },
    async () => {
      throw new Error("safeseh failure");
    }
  );

  assert.equal(enriched?.dynamicRelocations, null);
  assert.ok(enriched?.warnings?.some(warning => warning.includes("failed to read SEHandlerTable")));
  assert.ok(enriched?.warnings?.some(warning => warning.includes("failed to read dynamic relocations")));
});
