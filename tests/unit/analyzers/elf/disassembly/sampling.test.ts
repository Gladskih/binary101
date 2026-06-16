"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import {
  sampleElfExecutableRegions,
  toSafeElfFileIndex
} from "../../../../../analyzers/elf/disassembly-sampling.js";
import type { ElfExecutableRegion } from "../../../../../analyzers/elf/executable-regions.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("toSafeElfFileIndex rejects negative and oversized indexes", () => {
  const issues: string[] = [];
  assert.equal(toSafeElfFileIndex(-1n, "offset", issues), null);
  assert.equal(toSafeElfFileIndex(BigInt(Number.MAX_SAFE_INTEGER) + 1n, "size", issues), null);
  assert.equal(issues.length, 2);
});

void test("sampleElfExecutableRegions truncates samples at file end", async () => {
  const issues: string[] = [];
  const samples = await sampleElfExecutableRegions(
    new MockFile(new Uint8Array([1, 2, 3]), "short-elf"),
    [createRegion(1n, 8n, 0x1000n)],
    issues
  );
  assert.equal(samples.length, 1);
  assert.deepEqual([...samples[0]?.data ?? []], [2, 3]);
  assert.match(issues.join("\n"), /truncating/);
});

const createRegion = (
  fileOffset: bigint,
  fileSize: bigint,
  vaddr: bigint
): ElfExecutableRegion => ({
  label: "Segment #0 (PT_LOAD + PF_X)",
  fileOffset,
  fileSize,
  vaddr
});
