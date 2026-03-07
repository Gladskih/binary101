"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeMachO } from "../../analyzers/macho/probe.js";

const dvFrom = (bytes: ArrayLike<number>): DataView => new DataView(new Uint8Array(bytes).buffer);

void test("probeMachO differentiates 32-bit, 64-bit and fat", () => {
  assert.strictEqual(probeMachO(dvFrom([0xfe, 0xed, 0xfa, 0xce])), "Mach-O 32-bit");
  assert.strictEqual(probeMachO(dvFrom([0xce, 0xfa, 0xed, 0xfe])), "Mach-O 32-bit");
  assert.strictEqual(probeMachO(dvFrom([0xfe, 0xed, 0xfa, 0xcf])), "Mach-O 64-bit");
  assert.strictEqual(probeMachO(dvFrom([0xcf, 0xfa, 0xed, 0xfe])), "Mach-O 64-bit");
  assert.strictEqual(
    probeMachO(dvFrom([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02])),
    "Mach-O universal (Fat)"
  );
  assert.strictEqual(
    probeMachO(dvFrom([0xca, 0xfe, 0xba, 0xbf, 0x00, 0x00, 0x00, 0x02])),
    "Mach-O universal (Fat)"
  );
  assert.strictEqual(probeMachO(dvFrom([0x00, 0x01, 0x02, 0x03])), null);
});

void test("probeMachO excludes Java class files and swapped fat constants", () => {
  const javaClass = dvFrom([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01]);
  assert.strictEqual(probeMachO(javaClass), null);
  assert.strictEqual(probeMachO(dvFrom([0xbe, 0xba, 0xfe, 0xca, 0x00, 0x00, 0x00, 0x02])), null);
  assert.strictEqual(probeMachO(dvFrom([0xbf, 0xba, 0xfe, 0xca, 0x00, 0x00, 0x00, 0x02])), null);
});
