"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeLoadConfigTableEntry } from "../../../../../analyzers/pe/load-config/table-record.js";

// Windows SDK winnt.h defines GFIDS flags 0x01 through 0x08; 0x10 is deliberately unknown.
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
void test("decodeLoadConfigTableEntry decodes GFIDS metadata and unknown bits", () => {
  const bytes = Uint8Array.from([0x78, 0x56, 0x34, 0x12, 0x1f]);
  const entry = decodeLoadConfigTableEntry(new DataView(bytes.buffer), 7, "guardFid");
  assert.deepEqual(entry, {
    index: 7,
    rva: 0x12345678,
    metadataBytes: [0x1f],
    gfidsFlags: ["FID_SUPPRESSED", "EXPORT_SUPPRESSED", "FID_LANGEXCPTHANDLER", "FID_XFG"],
    unknownGfidsFlagBits: 0x10
  });
});

void test("decodeLoadConfigTableEntry omits zero RVAs and non-GFIDS interpretations", () => {
  const zero = decodeLoadConfigTableEntry(new DataView(new ArrayBuffer(4)), 0, "safeSeh");
  const bytes = Uint8Array.from([1, 0, 0, 0, 0xff, 0xee]);
  const entry = decodeLoadConfigTableEntry(new DataView(bytes.buffer), 1, "guardIat");
  const zeroFlags = decodeLoadConfigTableEntry(
    new DataView(Uint8Array.from([1, 0, 0, 0, 0]).buffer), 2, "guardFid"
  );
  assert.equal(zero, null);
  assert.deepEqual(entry, { index: 1, rva: 1, metadataBytes: [0xff, 0xee] });
  assert.deepEqual(zeroFlags, { index: 2, rva: 1, metadataBytes: [0] });
});
