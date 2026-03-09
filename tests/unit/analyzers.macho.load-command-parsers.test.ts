"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseBuildVersion,
  parseDylib,
  parseDyldInfo,
  parseEncryptionInfo,
  parseFileSetEntry,
  parseLinkeditData,
  parseRpath,
  parseStringCommand,
  parseVersionMin
} from "../../analyzers/macho/load-command-parsers.js";
import { createMachOIncidentalValues, packMachOVersion } from "../fixtures/macho-incidental-values.js";

const encoder = new TextEncoder();

void test("Mach-O load-command parsers decode dylib and minimum-version commands", () => {
  const values = createMachOIncidentalValues();
  const dylibName = `${values.nextLabel("lib")}.dylib`;
  const dylibNameBytes = encoder.encode(`${dylibName}\0`);
  const dylibTimestamp = values.nextUint32();
  const dylibCurrentVersion = packMachOVersion(1, 0, 2);
  const dylibCompatibilityVersion = packMachOVersion(1);
  const dylibBytes = new Uint8Array(24 + dylibNameBytes.length);
  const dylibView = new DataView(dylibBytes.buffer);
  dylibView.setUint32(8, 24, true);
  dylibView.setUint32(12, dylibTimestamp, true);
  dylibView.setUint32(16, dylibCurrentVersion, true);
  dylibView.setUint32(20, dylibCompatibilityVersion, true);
  dylibBytes.set(dylibNameBytes, 24);
  const dylibIssues: string[] = [];
  // mach-o/loader.h: LC_LOAD_DYLIB == 0x0c.
  const dylib = parseDylib(dylibView, 2, true, 0x0c, dylibIssues);
  assert.ok(dylib);
  assert.equal(dylib.name, dylibName);
  assert.deepEqual(dylibIssues, []);
  assert.equal(parseDylib(new DataView(new Uint8Array(8).buffer), 3, true, 0x0c, dylibIssues), null);

  const versionBytes = new Uint8Array(16);
  const versionView = new DataView(versionBytes.buffer);
  versionView.setUint32(8, packMachOVersion(13), true);
  versionView.setUint32(12, packMachOVersion(13, 2), true);
  const versionIssues: string[] = [];
  // mach-o/loader.h: LC_VERSION_MIN_MACOSX == 0x24.
  const version = parseVersionMin(versionView, 4, true, 0x24, versionIssues);
  assert.ok(version);
  assert.equal(version.version, packMachOVersion(13));
  assert.equal(version.sdk, packMachOVersion(13, 2));
  assert.equal(
    parseVersionMin(new DataView(new Uint8Array(12).buffer), 5, true, 0x24, versionIssues),
    null
  );
});

void test("Mach-O load-command string parsers warn on invalid offsets and missing terminators", () => {
  const values = createMachOIncidentalValues();
  const unterminatedRpath = values.nextLabel("path");
  const unterminatedDylinker = values.nextLabel("dyld");
  const unterminatedRpathBytes = encoder.encode(unterminatedRpath);
  const unterminatedDylinkerBytes = encoder.encode(unterminatedDylinker);
  const dylibBytes = new Uint8Array(24);
  const dylibView = new DataView(dylibBytes.buffer);
  dylibView.setUint32(8, 40, true);
  const dylibIssues: string[] = [];
  // mach-o/loader.h: LC_LOAD_DYLIB == 0x0c.
  const dylib = parseDylib(dylibView, 16, true, 0x0c, dylibIssues);
  assert.ok(dylib);
  assert.equal(dylib.name, "");
  assert.match(dylibIssues[0] || "", /dylib name offset 40 points outside the command/);

  const rpathBytes = new Uint8Array(12 + unterminatedRpathBytes.length);
  const rpathView = new DataView(rpathBytes.buffer);
  rpathView.setUint32(8, 12, true);
  rpathBytes.set(unterminatedRpathBytes, 12);
  const rpathIssues: string[] = [];
  const rpath = parseRpath(rpathView, 17, true, rpathIssues);
  assert.ok(rpath);
  assert.equal(rpath.path, unterminatedRpath);
  assert.match(rpathIssues[0] || "", /rpath path is not NUL-terminated within cmdsize/);

  const stringBytes = new Uint8Array(12 + unterminatedDylinkerBytes.length);
  const stringView = new DataView(stringBytes.buffer);
  stringView.setUint32(8, 12, true);
  stringBytes.set(unterminatedDylinkerBytes, 12);
  const stringIssues: string[] = [];
  // mach-o/loader.h: LC_LOAD_DYLINKER == 0x0e.
  const stringCommand = parseStringCommand(stringView, 18, true, 0x0e, stringIssues);
  assert.ok(stringCommand);
  assert.equal(stringCommand.value, unterminatedDylinker);
  assert.match(stringIssues[0] || "", /LC_LOAD_DYLINKER string is not NUL-terminated within cmdsize/);
});

void test("Mach-O load-command string parsers reject offsets into fixed command fields", () => {
  const values = createMachOIncidentalValues();
  const dylibBytes = new Uint8Array(24);
  const dylibView = new DataView(dylibBytes.buffer);
  // Offset 12 points at the timestamp field inside dylib_command.
  dylibView.setUint32(8, 12, true);
  dylibView.setUint32(12, values.nextUint32(), true);
  const dylibIssues: string[] = [];
  // mach-o/loader.h: LC_LOAD_DYLIB == 0x0c.
  const dylib = parseDylib(dylibView, 19, true, 0x0c, dylibIssues);
  assert.ok(dylib);
  assert.equal(dylib.name, "");
  assert.match(dylibIssues[0] || "", /dylib name offset 12 points inside the fixed command fields/);

  const rpathBytes = new Uint8Array(12);
  const rpathView = new DataView(rpathBytes.buffer);
  // Offset 8 points at the embedded lc_str field itself.
  rpathView.setUint32(8, 8, true);
  const rpathIssues: string[] = [];
  const rpath = parseRpath(rpathView, 20, true, rpathIssues);
  assert.ok(rpath);
  assert.equal(rpath.path, "");
  assert.match(rpathIssues[0] || "", /rpath path offset 8 points inside the fixed command fields/);

  const stringBytes = new Uint8Array(12);
  const stringView = new DataView(stringBytes.buffer);
  // Offset 8 points at the embedded lc_str field itself.
  stringView.setUint32(8, 8, true);
  const stringIssues: string[] = [];
  // mach-o/loader.h: LC_LOAD_DYLINKER == 0x0e.
  const stringCommand = parseStringCommand(stringView, 21, true, 0x0e, stringIssues);
  assert.ok(stringCommand);
  assert.equal(stringCommand.value, "");
  assert.match(
    stringIssues[0] || "",
    /LC_LOAD_DYLINKER string offset 8 points inside the fixed command fields/
  );

  const filesetBytes = new Uint8Array(32);
  const filesetView = new DataView(filesetBytes.buffer);
  // Offset 24 points at entry_id.offset inside fileset_entry_command.
  filesetView.setUint32(24, 24, true);
  const filesetIssues: string[] = [];
  const fileset = parseFileSetEntry(filesetView, 22, true, filesetIssues);
  assert.ok(fileset);
  assert.equal(fileset.entryId, "");
  assert.match(
    filesetIssues[0] || "",
    /fileset entry id offset 24 points inside the fixed command fields/
  );
});

void test("Mach-O load-command parsers decode build-version and dyld info payloads", () => {
  const values = createMachOIncidentalValues();
  const buildBytes = new Uint8Array(32);
  const buildView = new DataView(buildBytes.buffer);
  buildView.setUint32(8, 1, true);
  buildView.setUint32(12, packMachOVersion(13), true);
  buildView.setUint32(16, packMachOVersion(13, 2), true);
  buildView.setUint32(20, 2, true);
  buildView.setUint32(24, 3, true);
  buildView.setUint32(28, packMachOVersion(15), true);
  const buildIssues: string[] = [];
  const build = parseBuildVersion(buildView, 6, true, buildIssues);
  assert.ok(build);
  assert.equal(build.platform, 1);
  assert.equal(build.tools.length, 1);
  assert.match(buildIssues[0] || "", /missing 1 tool entries/);
  assert.equal(parseBuildVersion(new DataView(new Uint8Array(16).buffer), 7, true, buildIssues), null);

  const dyldBytes = new Uint8Array(48);
  const dyldView = new DataView(dyldBytes.buffer);
  dyldView.setUint32(8, values.nextUint8(), true);
  dyldView.setUint32(12, values.nextUint8(), true);
  dyldView.setUint32(16, values.nextUint8(), true);
  dyldView.setUint32(20, values.nextUint8(), true);
  dyldView.setUint32(24, values.nextUint8(), true);
  dyldView.setUint32(28, values.nextUint8(), true);
  dyldView.setUint32(32, values.nextUint8(), true);
  dyldView.setUint32(36, values.nextUint8(), true);
  dyldView.setUint32(40, values.nextUint8(), true);
  const expectedExportSize = values.nextUint8();
  dyldView.setUint32(44, expectedExportSize, true);
  const dyldIssues: string[] = [];
  // mach-o/loader.h: LC_DYLD_INFO == 0x22.
  const dyld = parseDyldInfo(dyldView, 8, true, 0x22, dyldIssues);
  assert.ok(dyld);
  assert.equal(dyld.exportSize, expectedExportSize);
  assert.deepEqual(dyldIssues, []);
  assert.equal(parseDyldInfo(new DataView(new Uint8Array(40).buffer), 9, true, 0x22, dyldIssues), null);
});

void test("Mach-O load-command parsers decode linkedit, encryption, and fileset records", () => {
  const values = createMachOIncidentalValues();
  const linkeditBytes = new Uint8Array(16);
  const linkeditView = new DataView(linkeditBytes.buffer);
  const linkeditOffset = (values.nextUint16() & 0x01f0) + 0x200;
  const linkeditSize = (values.nextUint8() & 0x3f) + 0x40;
  linkeditView.setUint32(8, linkeditOffset, true);
  linkeditView.setUint32(12, linkeditSize, true);
  const linkeditIssues: string[] = [];
  const linkedit = parseLinkeditData(linkeditView, 10, true, values.nextUint32(), linkeditIssues);
  assert.ok(linkedit);
  assert.equal(linkedit.dataoff, linkeditOffset);
  assert.equal(
    parseLinkeditData(new DataView(new Uint8Array(12).buffer), 11, true, values.nextUint32(), linkeditIssues),
    null
  );

  const encryptionBytes = new Uint8Array(24);
  const encryptionView = new DataView(encryptionBytes.buffer);
  const encryptionOffset = (values.nextUint16() & 0x01f0) + 0x300;
  const encryptionSize = (values.nextUint8() & 0x7f) + 0x80;
  const encryptionId = (values.nextUint8() & 0x07) + 1;
  encryptionView.setUint32(8, encryptionOffset, true);
  encryptionView.setUint32(12, encryptionSize, true);
  encryptionView.setUint32(16, encryptionId, true);
  const encryptionIssues: string[] = [];
  // mach-o/loader.h: LC_ENCRYPTION_INFO_64 == 0x2c.
  const encryption = parseEncryptionInfo(encryptionView, 12, true, 0x2c, encryptionIssues);
  assert.ok(encryption);
  assert.equal(encryption.cryptid, encryptionId);
  const truncatedEncryptionIssues: string[] = [];
  assert.equal(
    parseEncryptionInfo(
      new DataView(new Uint8Array(20).buffer),
      13,
      true,
      0x2c,
      truncatedEncryptionIssues
    ),
    null
  );
  assert.match(truncatedEncryptionIssues[0] || "", /LC_ENCRYPTION_INFO_64 is truncated/);

  const entryId = values.nextLabel("entry");
  const filesetBytes = new Uint8Array(40 + entryId.length);
  const filesetView = new DataView(filesetBytes.buffer);
  filesetView.setBigUint64(8, BigInt(values.nextUint16() + 0x1000), true);
  filesetView.setBigUint64(16, BigInt(values.nextUint16() + 0x200), true);
  filesetView.setUint32(24, 32, true);
  filesetBytes.set(encoder.encode(`${entryId}\0`), 32);
  const filesetIssues: string[] = [];
  const fileset = parseFileSetEntry(filesetView, 14, true, filesetIssues);
  assert.ok(fileset);
  assert.equal(fileset.entryId, entryId);
  assert.equal(parseFileSetEntry(new DataView(new Uint8Array(24).buffer), 15, true, filesetIssues), null);

  const badFilesetBytes = new Uint8Array(32);
  const badFilesetView = new DataView(badFilesetBytes.buffer);
  badFilesetView.setUint32(24, 40, true);
  const badFilesetIssues: string[] = [];
  const badFileset = parseFileSetEntry(badFilesetView, 16, true, badFilesetIssues);
  assert.ok(badFileset);
  assert.equal(badFileset.entryId, "");
  assert.match(badFilesetIssues[0] || "", /fileset entry id offset 40 points outside the command/);
});
