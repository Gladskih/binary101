"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  analyzeEntrypoint,
  createExecutableSection
} from "../../../../../helpers/pe-entrypoint-disassembly-fixture.js";

void test("analyzePeEntrypointDisassembly reports decoded instruction progress", async () => {
  const snapshots: string[] = [];
  const result = await analyzeEntrypoint(
    new Uint8Array(5).fill(0x90),
    createExecutableSection({ virtualSize: 5, sizeOfRawData: 5 }),
    0x1000,
    {
      yieldEveryInstructions: 2,
      onProgress: progress => {
        snapshots.push(`${progress.stage}:${progress.instructionCount}`);
      }
    }
  );

  assert.equal(result.instructionCount, 5);
  assert.deepEqual(snapshots, [
    "loading:0",
    "decoding:0",
    "decoding:2",
    "decoding:4",
    "done:5"
  ]);
});
