"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseThinImage } from "../../analyzers/macho/thin.js";
import { createThinMachOFixtureData, wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

const loadCommandSizeOffset = (commandOffset: number): number => commandOffset + 4;

void test("parseThinImage reports truncated load-command regions", async () => {
  const fixture = createThinMachOFixtureData();
  const bytes = fixture.bytes.slice(0, fixture.layout.textOffset - 8);
  const parsed = await parseThinImage(wrapMachOBytes(bytes, "thin-truncated-loads"), 0, bytes.length);
  assert.ok(parsed);
  assert.match(parsed.issues[0] || "", /Load-command region is truncated/);
});

void test("parseThinImage reports invalid cmdsize values", async () => {
  const fixture = createThinMachOFixtureData();
  const view = new DataView(fixture.bytes.buffer);
  view.setUint32(loadCommandSizeOffset(fixture.layout.textSegmentCommandOffset), 4, true);
  const parsed = await parseThinImage(wrapMachOBytes(fixture.bytes, "thin-bad-cmdsize"), 0, fixture.bytes.length);
  assert.ok(parsed);
  assert.match(parsed.issues[0] || "", /invalid cmdsize 4/);
});

void test("parseThinImage reports load commands that extend past available bytes", async () => {
  const fixture = createThinMachOFixtureData();
  const view = new DataView(fixture.bytes.buffer);
  view.setUint32(loadCommandSizeOffset(fixture.layout.textSegmentCommandOffset), fixture.bytes.length, true);
  const parsed = await parseThinImage(wrapMachOBytes(fixture.bytes, "thin-overflow-cmd"), 0, fixture.bytes.length);
  assert.ok(parsed);
  assert.match(parsed.issues[0] || "", /extends beyond available command bytes/);
});

void test("parseThinImage reports truncated UUID commands", async () => {
  const fixture = createThinMachOFixtureData();
  const view = new DataView(fixture.bytes.buffer);
  view.setUint32(loadCommandSizeOffset(fixture.layout.uuidCommandOffset), 16, true);
  const parsed = await parseThinImage(wrapMachOBytes(fixture.bytes, "thin-truncated-uuid"), 0, fixture.bytes.length);
  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /UUID command is truncated/);
});

void test("parseThinImage reports truncated source-version commands", async () => {
  const fixture = createThinMachOFixtureData();
  const view = new DataView(fixture.bytes.buffer);
  view.setUint32(loadCommandSizeOffset(fixture.layout.sourceVersionCommandOffset), 12, true);
  const parsed = await parseThinImage(wrapMachOBytes(fixture.bytes, "thin-truncated-source"), 0, fixture.bytes.length);
  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /source-version command is truncated/);
});

void test("parseThinImage reports truncated entry-point commands", async () => {
  const fixture = createThinMachOFixtureData();
  const view = new DataView(fixture.bytes.buffer);
  view.setUint32(loadCommandSizeOffset(fixture.layout.mainCommandOffset), 16, true);
  const parsed = await parseThinImage(wrapMachOBytes(fixture.bytes, "thin-truncated-main"), 0, fixture.bytes.length);
  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /entry-point command is truncated/);
});

void test("parseThinImage reports truncated symtab commands", async () => {
  const fixture = createThinMachOFixtureData();
  const view = new DataView(fixture.bytes.buffer);
  view.setUint32(loadCommandSizeOffset(fixture.layout.symtabCommandOffset), 20, true);
  const parsed = await parseThinImage(wrapMachOBytes(fixture.bytes, "thin-truncated-symtab"), 0, fixture.bytes.length);
  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /symbol-table command is truncated/);
});

void test("parseThinImage reads load commands incrementally", async () => {
  const bytes = new Uint8Array(40);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0xcffaedfe, false);
  view.setUint32(4, 0x01000007, true);
  view.setUint32(8, 3, true);
  view.setUint32(12, 2, true);
  view.setUint32(16, 1, true);
  view.setUint32(20, 0x100000, true);
  view.setUint32(24, 0, true);
  view.setUint32(28, 0, true);
  view.setUint32(32, 0, true);
  view.setUint32(36, 8, true);
  const tracked = createSliceTrackingFile(bytes, 0x100020, "thin-incremental");

  const parsed = await parseThinImage(tracked.file, 0, tracked.file.size);

  assert.ok(parsed);
  assert.equal(parsed.loadCommands.length, 1);
  assert.ok(Math.max(...tracked.requests) <= 64 * 1024);
});
