"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseThinImage } from "../../analyzers/macho/thin.js";
import { CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_X86_64 } from "../fixtures/macho-thin-sample.js";
import { createThinMachOFixtureData, wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";
import { createMachOIncidentalValues, packMachOVersion } from "../fixtures/macho-incidental-values.js";

const loadCommandSizeOffset = (commandOffset: number): number => commandOffset + 4;
const THIN_HEADER_SIZE = 32;
const textEncoder = new TextEncoder();
const alignUp = (value: number, alignment: number): number => Math.ceil(value / alignment) * alignment;

const createThinImageWithCommands = (...commands: Uint8Array[]): Uint8Array => {
  const loadCommandBytes = commands.reduce((sum, command) => sum + command.length, 0);
  const bytes = new Uint8Array(THIN_HEADER_SIZE + loadCommandBytes);
  const view = new DataView(bytes.buffer);
  // mach-o/loader.h: MH_CIGAM_64 == 0xcffaedfe.
  view.setUint32(0, 0xcffaedfe, false);
  view.setUint32(4, CPU_TYPE_X86_64, true);
  view.setUint32(8, CPU_SUBTYPE_X86_64_ALL, true);
  // mach-o/loader.h: MH_EXECUTE == 0x2.
  view.setUint32(12, 0x2, true);
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
  const bytes = new Uint8Array(alignUp(8 + payloadSize, 8));
  const view = new DataView(bytes.buffer);
  view.setUint32(0, cmd, true);
  view.setUint32(4, bytes.length, true);
  return bytes;
};

const createUnalignedLoadCommand = (cmd: number, payloadSize: number): Uint8Array => {
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

void test("parseThinImage reports 64-bit load commands with misaligned cmdsize values", async () => {
  const values = createMachOIncidentalValues();
  const command = createUnalignedLoadCommand(values.nextUint32(), 1);
  const parsed = await parseThinImage(
    wrapMachOBytes(createThinImageWithCommands(command), "thin-misaligned-cmdsize"),
    0,
    THIN_HEADER_SIZE + command.length
  );

  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /cmdsize 9 is not aligned to 8 bytes/i);
});

void test("parseThinImage reports load commands that extend past available bytes", async () => {
  const fixture = createThinMachOFixtureData();
  const view = new DataView(fixture.bytes.buffer);
  view.setUint32(
    loadCommandSizeOffset(fixture.layout.textSegmentCommandOffset),
    alignUp(fixture.bytes.length + 1, 8),
    true
  );
  const parsed = await parseThinImage(wrapMachOBytes(fixture.bytes, "thin-overflow-cmd"), 0, fixture.bytes.length);
  assert.ok(parsed);
  assert.match(parsed.issues[0] || "", /extends beyond the declared load-command region/);
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
  view.setUint32(loadCommandSizeOffset(fixture.layout.sourceVersionCommandOffset), 8, true);
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
  view.setUint32(loadCommandSizeOffset(fixture.layout.symtabCommandOffset), 16, true);
  const parsed = await parseThinImage(wrapMachOBytes(fixture.bytes, "thin-truncated-symtab"), 0, fixture.bytes.length);
  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /symbol-table command is truncated/);
});

void test("parseThinImage reads load commands incrementally", async () => {
  const declaredLoadCommandBytes = 64 * 1024 * 16;
  const bytes = new Uint8Array(40);
  const view = new DataView(bytes.buffer);
  // mach-o/loader.h: MH_CIGAM_64 == 0xcffaedfe.
  view.setUint32(0, 0xcffaedfe, false);
  view.setUint32(4, CPU_TYPE_X86_64, true);
  view.setUint32(8, CPU_SUBTYPE_X86_64_ALL, true);
  // mach-o/loader.h: MH_EXECUTE == 0x2.
  view.setUint32(12, 0x2, true);
  view.setUint32(16, 1, true);
  view.setUint32(20, declaredLoadCommandBytes, true);
  view.setUint32(24, 0, true);
  view.setUint32(28, 0, true);
  view.setUint32(32, 0, true);
  view.setUint32(36, 8, true);
  const tracked = createSliceTrackingFile(bytes, THIN_HEADER_SIZE + declaredLoadCommandBytes, "thin-incremental");

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
  assert.match(parsed.issues.join("\n"), /header extends beyond the declared load-command region/);
});

void test("parseThinImage stops at sizeofcmds even when the image contains more bytes", async () => {
  // mach-o/loader.h: LC_RPATH == 0x8000001c and LC_LOAD_DYLINKER == 0x0e.
  const firstCommand = createLoadCommand(0x8000001c, 4);
  const secondCommand = createLoadCommand(0x0e, 4);
  const bytes = createThinImageWithCommands(firstCommand, secondCommand);
  const view = new DataView(bytes.buffer);
  view.setUint32(16, 2, true);
  view.setUint32(20, firstCommand.length, true);

  const parsed = await parseThinImage(wrapMachOBytes(bytes, "thin-sizeofcmds-boundary"), 0, bytes.length);

  assert.ok(parsed);
  assert.equal(parsed.loadCommands.length, 1);
  assert.match(parsed.issues.join("\n"), /header extends beyond the declared load-command region/);
});

void test("parseThinImage parses RPATH, minimum-version, dyld-info, and fileset-entry commands", async () => {
  const values = createMachOIncidentalValues();
  const rpathBytes = textEncoder.encode("@loader_path\0");
  // mach-o/loader.h: LC_RPATH == 0x8000001c.
  const rpathCommand = createLoadCommand(0x8000001c, 4 + rpathBytes.length);
  const rpathView = new DataView(rpathCommand.buffer);
  rpathView.setUint32(8, 12, true);
  rpathCommand.set(rpathBytes, 12);

  // mach-o/loader.h: LC_VERSION_MIN_MACOSX == 0x24.
  const versionCommand = createLoadCommand(0x24, 8);
  const versionView = new DataView(versionCommand.buffer);
  versionView.setUint32(8, packMachOVersion(10, 15), true);
  versionView.setUint32(12, packMachOVersion(11), true);

  // mach-o/loader.h: LC_DYLD_INFO_ONLY == 0x80000022.
  const dyldInfoCommand = createLoadCommand(0x80000022, 40);
  const dyldInfoView = new DataView(dyldInfoCommand.buffer);
  dyldInfoView.setUint32(8, values.nextUint8(), true);
  dyldInfoView.setUint32(12, values.nextUint8(), true);
  dyldInfoView.setUint32(16, values.nextUint8(), true);
  dyldInfoView.setUint32(20, values.nextUint8(), true);
  dyldInfoView.setUint32(24, values.nextUint8(), true);
  dyldInfoView.setUint32(28, values.nextUint8(), true);
  dyldInfoView.setUint32(32, values.nextUint8(), true);
  dyldInfoView.setUint32(36, values.nextUint8(), true);
  dyldInfoView.setUint32(40, values.nextUint8(), true);
  dyldInfoView.setUint32(44, values.nextUint8(), true);

  const entryId = values.nextLabel("com.example.slice");
  const filesetEntryBytes = textEncoder.encode(`${entryId}\0`);
  // mach-o/loader.h: LC_FILESET_ENTRY == 0x80000035.
  const filesetEntryCommand = createLoadCommand(0x80000035, 32 + filesetEntryBytes.length);
  const filesetEntryView = new DataView(filesetEntryCommand.buffer);
  filesetEntryView.setBigUint64(8, BigInt(values.nextUint16() + 0x1000), true);
  filesetEntryView.setBigUint64(16, BigInt(values.nextUint16() + 0x2000), true);
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
  assert.equal(parsed.minVersions[0]?.version, packMachOVersion(10, 15));
  // mach-o/loader.h: LC_DYLD_INFO_ONLY == 0x80000022.
  assert.equal(parsed.dyldInfo?.command, 0x80000022);
  assert.equal(parsed.fileSetEntries[0]?.entryId, entryId);
});

void test("parseThinImage reports malformed load-command strings instead of silently blanking them", async () => {
  const values = createMachOIncidentalValues();
  // mach-o/loader.h: LC_LOAD_DYLINKER == 0x0e.
  const dylinkerCommand = createLoadCommand(0x0e, 4);
  const dylinkerView = new DataView(dylinkerCommand.buffer);
  dylinkerView.setUint32(8, 20, true);

  const unterminatedRpathBytes = textEncoder.encode(values.nextLabel("path"));
  // mach-o/loader.h: LC_RPATH == 0x8000001c.
  const rpathCommand = createLoadCommand(0x8000001c, 4 + unterminatedRpathBytes.length);
  const rpathView = new DataView(rpathCommand.buffer);
  rpathView.setUint32(8, 12, true);
  rpathCommand.set(unterminatedRpathBytes, 12);
  rpathCommand.fill((values.nextUint8() & 0x7f) + 1, 12 + unterminatedRpathBytes.length);

  const parsed = await parseThinImage(
    wrapMachOBytes(createThinImageWithCommands(dylinkerCommand, rpathCommand), "thin-invalid-lc-str"),
    0,
    THIN_HEADER_SIZE + dylinkerCommand.length + rpathCommand.length
  );

  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /LC_LOAD_DYLINKER string offset 20 points outside the command/);
  assert.match(parsed.issues.join("\n"), /rpath path is not NUL-terminated within cmdsize/);
});
