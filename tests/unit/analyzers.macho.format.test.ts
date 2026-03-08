"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createRangeReader, getMachOMagicInfo } from "../../analyzers/macho/format.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";
import { wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createMachOIncidentalValues } from "../fixtures/macho-incidental-values.js";

void test("Mach-O format helpers recognise swapped thin magics", () => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setUint32(4, 0xcefaedfe, false); // MH_CIGAM

  const info = getMachOMagicInfo(new DataView(bytes.buffer), 4);

  assert.deepEqual(info, {
    kind: "thin",
    is64: false,
    littleEndian: true,
    magic: 0xcefaedfe,
    magicName: "MH_CIGAM"
  });
});

void test("createRangeReader does not cache oversized reads", async () => {
  const bytes = new Uint8Array(70_000);
  const tracked = createSliceTrackingFile(bytes, bytes.length, "macho-large-read");
  const reader = createRangeReader(tracked.file, 0, tracked.file.size);

  const largeView = await reader.read(0, 70_000);
  const smallView = await reader.read(16, 4);

  assert.equal(largeView.byteLength, 70_000);
  assert.equal(smallView.byteLength, 4);
  assert.deepEqual(tracked.requests.slice(0, 2), [70_000, 65_536]);
});

void test("createRangeReader returns unterminated strings when maxLength is exhausted", async () => {
  const values = createMachOIncidentalValues();
  const unterminatedLabel = values.nextLabel("abc");
  const bytes = new TextEncoder().encode(unterminatedLabel);
  const reader = createRangeReader(wrapMachOBytes(bytes, "macho-unterminated-string"), 0, bytes.length);

  assert.equal(await reader.readZeroTerminatedString(0, bytes.length), unterminatedLabel);
});
