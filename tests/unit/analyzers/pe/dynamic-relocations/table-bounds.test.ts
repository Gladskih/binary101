"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { FileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { parseDynamicRelocationsFromLoadConfig32 } from
  "../../../../../analyzers/pe/dynamic-relocations/index.js";
import type { PeLoadConfig } from "../../../../../analyzers/pe/load-config/index.js";
import type { PeSection } from "../../../../../analyzers/pe/types.js";
import { expectDefined } from "../../../../helpers/expect-defined.js";

void test("parseDynamicRelocationsFromLoadConfig bounds a huge declared table read", async () => {
  const header = new DataView(new ArrayBuffer(8));
  header.setUint32(0, 1, true);
  header.setUint32(4, 0xffff_ffff, true); // Maximum DWORD table size.
  const requested: number[] = [];
  const reader = {
    size: 0x1_0000_0000,
    read: async (_offset: number, size: number) => {
      requested.push(size);
      return header;
    }
  } as FileRangeReader;
  const sections = [{ virtualAddress: 0 }] as PeSection[];
  const loadConfig = { DynamicValueRelocTable: 0n,
    DynamicValueRelocTableSection: 1,
    DynamicValueRelocTableOffset: 0x80 } as PeLoadConfig;

  const parsed = expectDefined(await parseDynamicRelocationsFromLoadConfig32(
    reader, sections, rva => rva, 0x400000n, loadConfig
  ));

  assert.ok(requested.every(size => size <= 16 * 1024 * 1024));
  assert.ok(parsed.warnings?.some(warning => /limit/.test(warning)));
});
