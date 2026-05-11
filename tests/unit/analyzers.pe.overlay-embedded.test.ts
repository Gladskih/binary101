"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  detectEmbeddedCandidateType,
  EMBEDDED_EXECUTABLE_LABEL,
  isEmbeddedCandidateStartByte
} from "../../analyzers/pe/overlay-embedded.js";

const dataViewFrom = (bytes: ArrayLike<number>): DataView =>
  new DataView(Uint8Array.from(bytes).buffer);

void test("isEmbeddedCandidateStartByte gates expensive embedded probes", () => {
  assert.equal(isEmbeddedCandidateStartByte(0x50), true);
  assert.equal(isEmbeddedCandidateStartByte(0x00), false);
});

void test("detectEmbeddedCandidateType rejects bare MZ without e_lfanew signature", () => {
  const bytes = new Uint8Array(96);
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;

  assert.equal(detectEmbeddedCandidateType(new DataView(bytes.buffer), bytes.byteLength), null);
});

void test("detectEmbeddedCandidateType accepts MZ only when e_lfanew points to PE signature", () => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(0x3c, 0x40, true);
  view.setUint32(0x40, 0x50450000, false);

  assert.equal(detectEmbeddedCandidateType(view, bytes.byteLength), EMBEDDED_EXECUTABLE_LABEL);
});

void test("detectEmbeddedCandidateType validates gzip method and reserved flags", () => {
  assert.equal(
    detectEmbeddedCandidateType(dataViewFrom([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0]), 10),
    "gzip compressed data"
  );
  assert.equal(
    detectEmbeddedCandidateType(dataViewFrom([0x1f, 0x8b, 0x09, 0x00, 0, 0, 0, 0, 0, 0]), 10),
    null
  );
  assert.equal(
    detectEmbeddedCandidateType(dataViewFrom([0x1f, 0x8b, 0x08, 0xe0, 0, 0, 0, 0, 0, 0]), 10),
    null
  );
});
