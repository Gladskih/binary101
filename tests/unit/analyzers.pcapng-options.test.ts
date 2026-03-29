"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  decodeUtf8,
  describeTimestampResolution,
  parsePcapNgOptions,
  readFilterOption,
  readInt64Option,
  readUint64Option
} from "../../analyzers/pcapng/options.js";

const makeOptionBlock = (
  littleEndian: boolean,
  options: Array<{ code: number; value: Uint8Array }>
): DataView => {
  const parts: number[] = [];
  for (const option of options) {
    const paddedLength = option.value.length + ((4 - (option.value.length % 4)) % 4);
    const bytes = new Uint8Array(4 + paddedLength);
    const dv = new DataView(bytes.buffer);
    dv.setUint16(0, option.code, littleEndian);
    dv.setUint16(2, option.value.length, littleEndian);
    bytes.set(option.value, 4);
    parts.push(...bytes);
  }
  parts.push(0, 0, 0, 0);
  return new DataView(Uint8Array.from(parts).buffer);
};

void test("parsePcapNgOptions decodes UTF-8 strings and integer options", () => {
  const view = makeOptionBlock(true, [
    { code: 2, value: new TextEncoder().encode("eth0") },
    { code: 4, value: Uint8Array.from([0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]) },
    { code: 5, value: Uint8Array.from([0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]) }
  ]);
  const issues: string[] = [];
  const options = parsePcapNgOptions(view, 0, view.byteLength, true, issue => issues.push(issue), "options");

  assert.deepStrictEqual(issues, []);
  assert.strictEqual(decodeUtf8(options[0]!.value), "eth0");
  assert.strictEqual(readUint64Option(options[1]!, true), 0x1122334455667788n);
  assert.strictEqual(readInt64Option(options[2]!, true), -10n);
});

void test("pcapng option helpers support decimal and binary timestamp resolutions", () => {
  const decimal = describeTimestampResolution(new Uint8Array([6]));
  const binary = describeTimestampResolution(new Uint8Array([0x8a]));
  const fallback = describeTimestampResolution(null);

  assert.deepStrictEqual(decimal, { unitsPerSecond: 1_000_000, label: "10^-6 s" });
  assert.deepStrictEqual(binary, { unitsPerSecond: 1024, label: "2^-10 s" });
  assert.deepStrictEqual(fallback, { unitsPerSecond: 1_000_000, label: "10^-6 s" });
});

void test("parsePcapNgOptions reports malformed trailing data and filter helper decodes text", () => {
  const badBytes = Uint8Array.from([0x02, 0x00, 0x04, 0x00, 0x65, 0x74, 0x68]);
  const issues: string[] = [];
  const options = parsePcapNgOptions(
    new DataView(badBytes.buffer),
    0,
    badBytes.length,
    true,
    issue => issues.push(issue),
    "bad-options"
  );

  assert.deepStrictEqual(options, []);
  assert.ok(issues.some(issue => issue.includes("runs past")));
  assert.strictEqual(readFilterOption({ code: 11, value: Uint8Array.from([0, 0x74, 0x63, 0x70]) }), "tcp");
  assert.match(
    readFilterOption({ code: 11, value: Uint8Array.from([2, 0xaa, 0xbb, 0xcc]) }),
    /Filter type 2/
  );
});

void test("parsePcapNgOptions reports trailing bytes after the last complete option", () => {
  const bytes = Uint8Array.from([
    0x02,
    0x00,
    0x01,
    0x00,
    0x61,
    0x00,
    0x00,
    0x00,
    0xde,
    0xad
  ]);
  const issues: string[] = [];

  const options = parsePcapNgOptions(
    new DataView(bytes.buffer),
    0,
    bytes.length,
    true,
    issue => issues.push(issue),
    "trailing-options"
  );

  assert.strictEqual(options.length, 1);
  assert.ok(issues.some(issue => issue.includes("trailing bytes")));
});
