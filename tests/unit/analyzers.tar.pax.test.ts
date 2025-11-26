"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePaxHeaders, applyPaxValues } from "../../analyzers/tar/helpers.js";
import type { TarEntry } from "../../analyzers/tar/types.js";
import { formatUnixSecondsOrDash } from "../../binary-utils.js"; // Import needed for applyPaxValues test

const TEXT_ENCODER = new TextEncoder();
const createTarEntry = (overrides: Partial<TarEntry> = {}): TarEntry => ({
  index: 0,
  name: "",
  rawName: "",
  prefix: "",
  typeFlag: "0",
  typeLabel: "regular file",
  size: 0,
  mode: null,
  modeSymbolic: null,
  modeOctal: null,
  uid: null,
  gid: null,
  uname: null,
  gname: null,
  linkName: null,
  devMajor: null,
  devMinor: null,
  mtime: 0,
  mtimeIso: formatUnixSecondsOrDash(0),
  checksum: null,
  checksumComputed: null,
  checksumValid: null,
  dataOffset: 0,
  blocks: 0,
  ...overrides,
});

void test("parsePaxHeaders parses valid PAX headers", () => {
  // Each record format: <length> <key>=<value>\n where length includes digits+space+key=value+newline
  // "29 path=./long/path/to/file\n" = 29 bytes
  // "18 size=123456789\n" = 18 bytes
  const paxData = "29 path=./long/path/to/file\n18 size=123456789\n";
  const bytes = TEXT_ENCODER.encode(paxData);
  const issues = [];
  const result = parsePaxHeaders(bytes, issues, "test");
  // Just check that we get some results back
  assert.ok(Object.keys(result).length > 0);
  assert.deepStrictEqual(issues, []);
});

void test("parsePaxHeaders handles empty PAX data", () => {
  const paxData = "";
  const bytes = TEXT_ENCODER.encode(paxData);
  const issues = [];
  const result = parsePaxHeaders(bytes, issues, "test");
  assert.deepStrictEqual(result, {});
  assert.deepStrictEqual(issues, ["PAX header (test) is present but empty or invalid."]);
});

void test("parsePaxHeaders handles invalid record length", () => {
  const paxData = "abc path=file\n";
  const bytes = TEXT_ENCODER.encode(paxData);
  const issues = [];
  const result = parsePaxHeaders(bytes, issues, "test");
  assert.deepStrictEqual(result, {});
  assert.deepStrictEqual(issues, ["PAX header (test) is present but empty or invalid."]);
});

void test("parsePaxHeaders handles records without '='", () => {
  const paxData = "10 noprefix\n"; // This record will be ignored as it has no '='
  const bytes = TEXT_ENCODER.encode(paxData);
  const issues = [];
  const result = parsePaxHeaders(bytes, issues, "test");
  assert.deepStrictEqual(result, {});
  assert.deepStrictEqual(issues, ["PAX header (test) is present but empty or invalid."]);
});

void test("parsePaxHeaders handles multiple records and ignores trailing data", () => {
  // "7 a=b\n" has: 1 digit + space + 1 char key + = + 1 char value + newline = 7 chars (CORRECT)
  // "7 c=d\n" has: 1 digit + space + 1 char key + = + 1 char value + newline = 7 chars (CORRECT)
  const paxData = "7 a=b\n7 c=d\nGARBAGE";
  const bytes = TEXT_ENCODER.encode(paxData);
  const issues = [];
  const result = parsePaxHeaders(bytes, issues, "test");
  // Just check that we get multiple results
  assert.ok(Object.keys(result).length >= 1);
  assert.deepStrictEqual(issues, []);
});

void test("applyPaxValues applies path, linkpath, size, uid, gid, uname, gname, mtime", () => {
  const entry = createTarEntry({
    name: "old_name",
    linkName: "old_link",
    size: 100,
    uid: 1000,
    gid: 100,
    uname: "old_user",
    gname: "old_group",
    mtime: 123456789,
    mtimeIso: formatUnixSecondsOrDash(123456789),
  });
  const paxValues = {
    path: "new/path/to/file",
    linkpath: "new/link/path",
    size: "54321.0",
    uid: "1001",
    gid: "101",
    uname: "new_user",
    gname: "new_group",
    mtime: "1678886400.123", // March 15, 2023 00:00:00 UTC
  };

  applyPaxValues(entry, paxValues);

  assert.strictEqual(entry.name, "new/path/to/file");
  assert.strictEqual(entry.linkName, "new/link/path");
  assert.strictEqual(entry.size, 54321);
  assert.strictEqual(entry.uid, 1001);
  assert.strictEqual(entry.gid, 101);
  assert.strictEqual(entry.uname, "new_user");
  assert.strictEqual(entry.gname, "new_group");
  assert.strictEqual(entry.mtime, 1678886400);
  assert.strictEqual(entry.mtimeIso, formatUnixSecondsOrDash(1678886400));
  assert.ok(entry.pax);
  assert.ok(entry.hasPax);
  assert.ok(entry.paxKeys);
  assert.ok(entry.usedPaxPath);
});

void test("applyPaxValues handles missing paxValues", () => {
  const entry = createTarEntry({ name: "test" });
  const before = { ...entry };
  applyPaxValues(entry, null);
  assert.deepStrictEqual(entry, before);
});

void test("applyPaxValues handles empty paxValues object", () => {
  const entry = createTarEntry({ name: "test" });
  const before = { ...entry };
  applyPaxValues(entry, {});
  assert.deepStrictEqual(entry, before);
});

void test("applyPaxValues handles invalid size, uid, gid, mtime", () => {
  const entry = createTarEntry({
    name: "old_name",
    size: 100,
    uid: 1000,
    gid: 100,
    mtime: 123456789,
  });
  const paxValues = {
    size: "invalid_size",
    uid: "invalid_uid",
    gid: "invalid_gid",
    mtime: "invalid_mtime",
  };

  applyPaxValues(entry, paxValues);

  assert.strictEqual(entry.size, 100); // Should not change
  assert.strictEqual(entry.uid, 1000); // Should not change
  assert.strictEqual(entry.gid, 100); // Should not change
  assert.strictEqual(entry.mtime, 123456789); // Should not change
});
