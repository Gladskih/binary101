"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  runMetadataDecoding, type MetadataDecodingTask
} from "../../../../../../analyzers/pe/clr/metadata-decoding-stack.js";

function* nestedValue(depth: number): MetadataDecodingTask<number> {
  if (!depth) return 1;
  return 1 + ((yield nestedValue(depth - 1)) as number);
}

function* siblingValues(): MetadataDecodingTask<unknown[]> {
  return [yield nestedValue(1), yield nestedValue(2)];
}

void test("preserves nested return values without recursive call-stack growth", () => {
  assert.equal(runMetadataDecoding(nestedValue(20000)), 20001);
  assert.deepEqual(runMetadataDecoding(siblingValues()), [2, 3]);
});
