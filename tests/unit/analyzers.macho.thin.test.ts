"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  LC_DYLD_INFO_ONLY,
  LC_FILESET_ENTRY,
  LC_RPATH,
  LC_VERSION_MIN_MACOSX
} from "../../analyzers/macho/commands.js";
import { parseThinImage } from "../../analyzers/macho/thin.js";
import { createThinMachOFixtureData, wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

const loadCommandSizeOffset = (commandOffset: number): number => commandOffset + 4;
const THIN_HEADER_SIZE = 32;

const createThinImageWithCommands = (...commands: Uint8Array[]): Uint8Array => {
  const loadCommandBytes = commands.reduce((sum, command) => sum + command.length, 0);
  const bytes = new Uint8Array(THIN_HEADER_SIZE + loadCommandBytes);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0xcffaedfe, false);
  view.setUint32(4, 0x01000007, true);
  view.setUint32(8, 3, true);
  view.setUint32(12, 2, true);
  view.setUint32(16, commands.length, true);
  view.setUint32(20, loadCommandBytes, true);
  let cursor = THIN_HEADER_SIZE;
  for (const command of commands) {
    bytes.set(command, cursor);
    cursor += command.length;
  }
  return bytes;
};

const createLoadCommand = (cmd: number, payloadSize: number): Uint8Array => {
  const bytes = new Uint8Array(8 + payloadSize);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, cmd, true);
  view.setUint32(4, bytes.length, true);
  return bytes;
};

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

void test("parseThinImage reports short command headers when the declared image is longer than available bytes", async () => {
  const bytes = createThinImageWithCommands(new Uint8Array(4));
  const tracked = createSliceTrackingFile(bytes, THIN_HEADER_SIZE + 8, "thin-short-command-header");

  const parsed = await parseThinImage(tracked.file, 0, tracked.file.size);

  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /header extends beyond available command bytes/);
});

void test("parseThinImage parses RPATH, minimum-version, dyld-info, and fileset-entry commands", async () => {
  const rpathBytes = new TextEncoder().encode("@loader_path\0");
  const rpathCommand = createLoadCommand(LC_RPATH, 4 + rpathBytes.length);
  const rpathView = new DataView(rpathCommand.buffer);
  rpathView.setUint32(8, 12, true);
  rpathCommand.set(rpathBytes, 12);

  const versionCommand = createLoadCommand(LC_VERSION_MIN_MACOSX, 8);
  const versionView = new DataView(versionCommand.buffer);
  versionView.setUint32(8, 0x000a0f00, true);
  versionView.setUint32(12, 0x000b0000, true);

  const dyldInfoCommand = createLoadCommand(LC_DYLD_INFO_ONLY, 40);
  const dyldInfoView = new DataView(dyldInfoCommand.buffer);
  dyldInfoView.setUint32(8, 1, true);
  dyldInfoView.setUint32(12, 2, true);
  dyldInfoView.setUint32(16, 3, true);
  dyldInfoView.setUint32(20, 4, true);
  dyldInfoView.setUint32(24, 5, true);
  dyldInfoView.setUint32(28, 6, true);
  dyldInfoView.setUint32(32, 7, true);
  dyldInfoView.setUint32(36, 8, true);
  dyldInfoView.setUint32(40, 9, true);
  dyldInfoView.setUint32(44, 10, true);

  const filesetEntryBytes = new TextEncoder().encode("com.example.slice\0");
  const filesetEntryCommand = createLoadCommand(LC_FILESET_ENTRY, 32 + filesetEntryBytes.length);
  const filesetEntryView = new DataView(filesetEntryCommand.buffer);
  filesetEntryView.setBigUint64(8, 0x1000n, true);
  filesetEntryView.setBigUint64(16, 0x2000n, true);
  filesetEntryView.setUint32(24, 32, true);
  filesetEntryCommand.set(filesetEntryBytes, 32);

  const parsed = await parseThinImage(
    wrapMachOBytes(
      createThinImageWithCommands(rpathCommand, versionCommand, dyldInfoCommand, filesetEntryCommand),
      "thin-extra-loads"
    ),
    0,
    THIN_HEADER_SIZE + rpathCommand.length + versionCommand.length + dyldInfoCommand.length + filesetEntryCommand.length
  );

  assert.ok(parsed);
  assert.equal(parsed.rpaths[0]?.path, "@loader_path");
  assert.equal(parsed.minVersions[0]?.version, 0x000a0f00);
  assert.equal(parsed.dyldInfo?.command, LC_DYLD_INFO_ONLY);
  assert.equal(parsed.fileSetEntries[0]?.entryId, "com.example.slice");
});
