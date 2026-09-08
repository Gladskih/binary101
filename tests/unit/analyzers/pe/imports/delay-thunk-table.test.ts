import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { readDelayThunkFunctions64 } from "../../../../../analyzers/pe/imports/delay-thunk-table.js";

for (const offset of [null, -1]) {
  void test(`PE32+ delay thunks reject an invalid mapped file offset: ${offset}`, async context => {
    // One complete 8-byte IMAGE_THUNK_DATA64; mapping must be checked before reading it.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-lookup-table
    const file = new File([new Uint8Array(8)], "delay-thunk");
    const reader = createFileRangeReader(file, 0, file.size);
    const readBytes = context.mock.fn(reader.read);
    const warnings = new Set<string>();

    const result = await readDelayThunkFunctions64({ ...reader, read: readBytes },
      () => offset, 0, warnings, () => 1);

    assert.deepEqual(result, { functions: [], terminated: false });
    assert.equal(readBytes.mock.callCount(), 0);
    assert.equal(warnings.size, 1);
  });
}
