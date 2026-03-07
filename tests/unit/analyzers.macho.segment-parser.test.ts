"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSegment } from "../../analyzers/macho/segment-parser.js";

const encoder = new TextEncoder();

const writeAscii = (bytes: Uint8Array, offset: number, text: string): void => {
  bytes.set(encoder.encode(text), offset);
};

void test("parseSegment reports truncated segment commands", () => {
  const issues: string[] = [];
  const segment = parseSegment(new DataView(new Uint8Array(40).buffer), 0, true, true, { value: 1 }, issues);
  assert.equal(segment, null);
  assert.match(issues[0] || "", /segment command is truncated/);
});

void test("parseSegment reports section counts that do not fit in the command", () => {
  const bytes = new Uint8Array(72 + 80);
  const view = new DataView(bytes.buffer);
  writeAscii(bytes, 8, "__TEXT");
  view.setUint32(64, 2, true);
  writeAscii(bytes, 72, "__text");
  writeAscii(bytes, 88, "__TEXT");
  view.setBigUint64(104, 0x100000000n, true);
  view.setBigUint64(112, 8n, true);
  view.setUint32(120, 0x200, true);
  const issues: string[] = [];
  const segment = parseSegment(view, 1, true, true, { value: 1 }, issues);
  assert.ok(segment);
  assert.equal(segment.sections.length, 1);
  assert.match(issues[0] || "", /declares 2 sections but only 1 fit/);
});

void test("parseSegment parses 32-bit segments and uses unnamed fallback in warnings", () => {
  const bytes = new Uint8Array(56 + 68);
  const view = new DataView(bytes.buffer);
  view.setUint32(24, 0x1000, true);
  view.setUint32(28, 0x200, true);
  view.setUint32(32, 0x200, true);
  view.setUint32(36, 0x200, true);
  view.setUint32(40, 7, true);
  view.setUint32(44, 5, true);
  view.setUint32(48, 2, true);
  view.setUint32(52, 0x4, true);
  writeAscii(bytes, 56, "__text");
  writeAscii(bytes, 72, "__TEXT");
  view.setUint32(88, 0x1000, true);
  view.setUint32(92, 0x20, true);
  view.setUint32(96, 0x200, true);
  view.setUint32(100, 4, true);
  view.setUint32(104, 0x220, true);
  view.setUint32(108, 1, true);
  view.setUint32(112, 0x80000400, true);
  view.setUint32(116, 2, true);
  view.setUint32(120, 3, true);

  const issues: string[] = [];
  const segment = parseSegment(view, 2, false, true, { value: 7 }, issues);

  assert.ok(segment);
  assert.equal(segment.name, "");
  assert.equal(segment.nsects, 2);
  assert.equal(segment.sections.length, 1);
  assert.equal(segment.sections[0]?.index, 7);
  assert.equal(segment.sections[0]?.addr, 0x1000n);
  assert.equal(segment.sections[0]?.size, 0x20n);
  assert.equal(segment.sections[0]?.reserved3, null);
  assert.match(issues[0] || "", /segment <unnamed> declares 2 sections but only 1 fit/);
});
