import assert from "node:assert/strict";
import { test } from "node:test";
import { elfCoreNoteName, parseElfCoreNote } from "../../../../analyzers/elf/core-notes.js";

void test("decodes Linux signal info with errno before code", () => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  view.setInt32(0, 11, true);
  view.setInt32(4, 2, true);
  view.setInt32(8, -6, true);
  assert.deepEqual(parseElfCoreNote(bytes, 0x53494749, 8, "little", 62).fields, [
    { name: "Signal", value: 11n }, { name: "Errno", value: 2n },
    { name: "Code", value: -6n }
  ]);
});

void test("decodes auxiliary vector pairs and requires AT_NULL", () => {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 6);
  view.setUint32(4, 4096);
  assert.deepEqual(parseElfCoreNote(bytes, 6, 4, "big", 3).auxv,
    [{ tag: 6n, value: 4096n }, { tag: 0n, value: 0n }]);
  assert.match(parseElfCoreNote(bytes.subarray(0, 8), 6, 4, "big", 3)
    .issues.join(" "), /AT_NULL/);
});

void test("reports truncated and unsupported core descriptors", () => {
  assert.match(parseElfCoreNote(new Uint8Array(2), 1, 8, "little", 62)
    .issues.join(" "), /truncated/);
  assert.match(parseElfCoreNote(new Uint8Array([1, 2]), 999, 8, "little", 62)
    .issues.join(" "), /Unsupported/);
});

void test("dispatches process and mapping notes without confusing their layouts", () => {
  assert.equal(parseElfCoreNote(new Uint8Array(136), 3, 8, "little", 62)
    .fields.find(field => field.name === "Executable")?.value, "");
  assert.deepEqual(parseElfCoreNote(new Uint8Array(16), 0x46494c45, 8, "little", 62).mappings, []);
  assert.deepEqual(parseElfCoreNote(new Uint8Array(0), 0x53494749, 8, "little", 62).fields, []);
  assert.equal(parseElfCoreNote(new Uint8Array(336), 1, 8, "little", 62).registers?.length, 27);
  assert.deepEqual([1, 2, 3, 6, 0x202, 0x53494749, 0x46494c45, 999].map(elfCoreNoteName),
    ["NT_PRSTATUS", "NT_FPREGSET", "NT_PRPSINFO", "NT_AUXV", "NT_X86_XSTATE",
      "NT_SIGINFO", "NT_FILE", null]);
});
