"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  LC_BUILD_VERSION,
  LC_DYLD_INFO,
  LC_ENCRYPTION_INFO_64,
  LC_LOAD_DYLIB,
  LC_LOAD_DYLINKER,
  LC_VERSION_MIN_MACOSX
} from "../../analyzers/macho/commands.js";
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

const encoder = new TextEncoder();

void test("Mach-O load-command parsers decode dylib and minimum-version commands", () => {
  const dylibBytes = new Uint8Array(40);
  const dylibView = new DataView(dylibBytes.buffer);
  dylibView.setUint32(8, 24, true);
  dylibView.setUint32(12, 123, true);
  dylibView.setUint32(16, 0x10002, true);
  dylibView.setUint32(20, 0x10000, true);
  dylibBytes.set(encoder.encode("libfoo.dylib\0"), 24);
  const dylibIssues: string[] = [];
  const dylib = parseDylib(dylibView, 2, true, LC_LOAD_DYLIB, dylibIssues);
  assert.ok(dylib);
  assert.equal(dylib.name, "libfoo.dylib");
  assert.deepEqual(dylibIssues, []);
  assert.equal(parseDylib(new DataView(new Uint8Array(8).buffer), 3, true, LC_LOAD_DYLIB, dylibIssues), null);

  const versionBytes = new Uint8Array(16);
  const versionView = new DataView(versionBytes.buffer);
  versionView.setUint32(8, 0x000d0000, true);
  versionView.setUint32(12, 0x000d0200, true);
  const versionIssues: string[] = [];
  const version = parseVersionMin(versionView, 4, true, LC_VERSION_MIN_MACOSX, versionIssues);
  assert.ok(version);
  assert.equal(version.version, 0x000d0000);
  assert.equal(version.sdk, 0x000d0200);
  assert.equal(
    parseVersionMin(new DataView(new Uint8Array(12).buffer), 5, true, LC_VERSION_MIN_MACOSX, versionIssues),
    null
  );
});

void test("Mach-O load-command string parsers warn on invalid offsets and missing terminators", () => {
  const dylibBytes = new Uint8Array(24);
  const dylibView = new DataView(dylibBytes.buffer);
  dylibView.setUint32(8, 40, true);
  const dylibIssues: string[] = [];
  const dylib = parseDylib(dylibView, 16, true, LC_LOAD_DYLIB, dylibIssues);
  assert.ok(dylib);
  assert.equal(dylib.name, "");
  assert.match(dylibIssues[0] || "", /dylib name offset 40 points outside the command/);

  const rpathBytes = new Uint8Array(16);
  const rpathView = new DataView(rpathBytes.buffer);
  rpathView.setUint32(8, 12, true);
  rpathBytes.set(encoder.encode("path"), 12);
  const rpathIssues: string[] = [];
  const rpath = parseRpath(rpathView, 17, true, rpathIssues);
  assert.ok(rpath);
  assert.equal(rpath.path, "path");
  assert.match(rpathIssues[0] || "", /rpath path is not NUL-terminated within cmdsize/);

  const stringBytes = new Uint8Array(16);
  const stringView = new DataView(stringBytes.buffer);
  stringView.setUint32(8, 12, true);
  stringBytes.set(encoder.encode("dyld"), 12);
  const stringIssues: string[] = [];
  const stringCommand = parseStringCommand(stringView, 18, true, LC_LOAD_DYLINKER, stringIssues);
  assert.ok(stringCommand);
  assert.equal(stringCommand.value, "dyld");
  assert.match(stringIssues[0] || "", /LC_LOAD_DYLINKER string is not NUL-terminated within cmdsize/);
});

void test("Mach-O load-command parsers decode build-version and dyld info payloads", () => {
  const buildBytes = new Uint8Array(32);
  const buildView = new DataView(buildBytes.buffer);
  buildView.setUint32(8, 1, true);
  buildView.setUint32(12, 0x000d0000, true);
  buildView.setUint32(16, 0x000d0200, true);
  buildView.setUint32(20, 2, true);
  buildView.setUint32(24, 3, true);
  buildView.setUint32(28, 0x0f0000, true);
  const buildIssues: string[] = [];
  const build = parseBuildVersion(buildView, 6, true, buildIssues);
  assert.ok(build);
  assert.equal(build.platform, 1);
  assert.equal(build.tools.length, 1);
  assert.match(buildIssues[0] || "", /missing 1 tool entries/);
  assert.equal(parseBuildVersion(new DataView(new Uint8Array(16).buffer), 7, true, buildIssues), null);

  const dyldBytes = new Uint8Array(48);
  const dyldView = new DataView(dyldBytes.buffer);
  dyldView.setUint32(8, 1, true);
  dyldView.setUint32(12, 2, true);
  dyldView.setUint32(16, 3, true);
  dyldView.setUint32(20, 4, true);
  dyldView.setUint32(24, 5, true);
  dyldView.setUint32(28, 6, true);
  dyldView.setUint32(32, 7, true);
  dyldView.setUint32(36, 8, true);
  dyldView.setUint32(40, 9, true);
  dyldView.setUint32(44, 10, true);
  const dyldIssues: string[] = [];
  const dyld = parseDyldInfo(dyldView, 8, true, LC_DYLD_INFO, dyldIssues);
  assert.ok(dyld);
  assert.equal(dyld.exportSize, 10);
  assert.deepEqual(dyldIssues, []);
  assert.equal(parseDyldInfo(new DataView(new Uint8Array(40).buffer), 9, true, LC_DYLD_INFO, dyldIssues), null);
});

void test("Mach-O load-command parsers decode linkedit, encryption, and fileset records", () => {
  const linkeditBytes = new Uint8Array(16);
  const linkeditView = new DataView(linkeditBytes.buffer);
  linkeditView.setUint32(8, 0x200, true);
  linkeditView.setUint32(12, 0x40, true);
  const linkeditIssues: string[] = [];
  const linkedit = parseLinkeditData(linkeditView, 10, true, LC_BUILD_VERSION, linkeditIssues);
  assert.ok(linkedit);
  assert.equal(linkedit.dataoff, 0x200);
  assert.equal(
    parseLinkeditData(new DataView(new Uint8Array(12).buffer), 11, true, LC_BUILD_VERSION, linkeditIssues),
    null
  );

  const encryptionBytes = new Uint8Array(20);
  const encryptionView = new DataView(encryptionBytes.buffer);
  encryptionView.setUint32(8, 0x300, true);
  encryptionView.setUint32(12, 0x80, true);
  encryptionView.setUint32(16, 1, true);
  const encryptionIssues: string[] = [];
  const encryption = parseEncryptionInfo(encryptionView, 12, true, LC_ENCRYPTION_INFO_64, encryptionIssues);
  assert.ok(encryption);
  assert.equal(encryption.cryptid, 1);
  assert.equal(
    parseEncryptionInfo(
      new DataView(new Uint8Array(12).buffer),
      13,
      true,
      LC_ENCRYPTION_INFO_64,
      encryptionIssues
    ),
    null
  );

  const filesetBytes = new Uint8Array(48);
  const filesetView = new DataView(filesetBytes.buffer);
  filesetView.setBigUint64(8, 0x1000n, true);
  filesetView.setBigUint64(16, 0x200n, true);
  filesetView.setUint32(24, 32, true);
  filesetBytes.set(encoder.encode("entry-id\0"), 32);
  const filesetIssues: string[] = [];
  const fileset = parseFileSetEntry(filesetView, 14, true, filesetIssues);
  assert.ok(fileset);
  assert.equal(fileset.entryId, "entry-id");
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
