"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDelayImports32 } from "../../analyzers/pe/imports/delay.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { IMAGE_DELAYLOAD_DESCRIPTOR_SIZE } from "./pe.delay-import-layout.js";

void test("parseDelayImports warns when directory size is non-zero but RVA is 0", async () => {
  const result = await parseDelayImports32(
    new MockFile(new Uint8Array(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE).fill(0)),
    // Microsoft PE format: IMAGE_DATA_DIRECTORY is an address/size pair; a non-zero size with RVA 0 is malformed.
    [{ name: "DELAY_IMPORT", rva: 0, size: IMAGE_DELAYLOAD_DESCRIPTOR_SIZE }],
    value => value
  );
  const definedResult = expectDefined(result);
  assert.deepEqual(definedResult.entries, []);
  assert.ok(definedResult.warning?.toLowerCase().includes("rva is 0"));
});
