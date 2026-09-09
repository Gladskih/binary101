import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfGnuProperties } from "../../../../analyzers/elf/gnu-properties.js";

// GNU property header: uint32 type, uint32 datasz, data, ELF-class alignment padding.
// https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
const property = (type: number, value: number, order: "little" | "big" = "little") => {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, type, order === "little");
  view.setUint32(4, 4, order === "little");
  view.setUint32(8, value, order === "little");
  return bytes;
};

void test("reads x86 feature masks with ELF64 alignment", () => {
  const issues: string[] = [];
  assert.deepEqual(parseElfGnuProperties(property(0xc0000002, 3), 8, "little", issues),
    [{ type: 0xc0000002, value: 3n }]);
  assert.deepEqual(issues, []);
});

void test("reads big endian ELF32 properties", () => {
  const issues: string[] = [];
  assert.deepEqual(parseElfGnuProperties(property(0xc0000000, 7, "big").slice(0, 12),
    4, "big", issues), [{ type: 0xc0000000, value: 7n }]);
  assert.deepEqual(issues, []);
});

void test("warns on truncated property headers and payloads", () => {
  const issues: string[] = [];
  assert.deepEqual(parseElfGnuProperties(new Uint8Array(7), 8, "little", issues), []);
  assert.deepEqual(parseElfGnuProperties(property(1, 0).slice(0, 10), 8, "little", issues), []);
  assert.equal(issues.length, 2);
});

void test("warns on invalid known property sizes and retains raw data", () => {
  const issues: string[] = [];
  const bytes = property(0xc0000002, 3);
  new DataView(bytes.buffer).setUint32(4, 1, true);
  assert.deepEqual(parseElfGnuProperties(bytes, 8, "little", issues),
    [{ type: 0xc0000002, value: "03" }]);
  assert.match(issues.join(" "), /size/);
});

void test("retains unknown properties and warns on duplicates", () => {
  const issues: string[] = [];
  const bytes = new Uint8Array([...property(12345, 7), ...property(12345, 9)]);
  assert.equal(parseElfGnuProperties(bytes, 8, "little", issues).length, 2);
  assert.match(issues.join(" "), /order/);
});

void test("reads class-sized stack size and empty no-copy properties", () => {
  const bytes = new Uint8Array(24);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  view.setUint32(4, 8, true);
  view.setBigUint64(8, 8192n, true);
  view.setUint32(16, 2, true);
  const issues: string[] = [];
  assert.deepEqual(parseElfGnuProperties(bytes, 8, "little", issues),
    [{ type: 1, value: 8192n }, { type: 2, value: 0n }]);
  assert.deepEqual(issues, []);
});
