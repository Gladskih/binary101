import assert from "node:assert/strict";
import { test } from "node:test";
import { readFirstSwfAttributes, readSwfTags } from "../../../../analyzers/swf/tags.js";
import type { SwfParseResult } from "../../../../analyzers/swf/types.js";
import { createSwfTag } from "../../../fixtures/swf-fixtures.js";
import { MockFile } from "../../../helpers/mock-file.js";

const scan = async (tags: Uint8Array[], version = 9, frameCount = 1): Promise<SwfParseResult> => {
  const bytes = Buffer.concat(tags);
  const result: SwfParseResult = { signature: "FWS", version, fileLength: bytes.length, tags: [], issues: [],
    movie: { xMin: 0, xMax: 12800, yMin: 0, yMax: 9600, frameRate: 7680, frameCount } };
  await readSwfTags(new MockFile(bytes), 0, result);
  return result;
};

const attributes = (flags = 8): Uint8Array => createSwfTag(69, Uint8Array.of(flags, 0, 0, 0));
const frame = (): Uint8Array => createSwfTag(1);
const end = (): Uint8Array => createSwfTag(0);

void test("readSwfTags skips a long unknown body and preserves its numeric code and exact bounds", async () => {
  const result = await scan([attributes(), createSwfTag(999, new Uint8Array(80)), frame(), end()]);

  assert.deepEqual(result.tags?.[1], { code: 999, count: 1, bodyBytes: 80 });
  assert.deepEqual(result.issues, []);
});

void test("readSwfTags checks metadata bounds and termination without decoding its body", async () => {
  const result = await scan([attributes(24), createSwfTag(77, new TextEncoder().encode("<rdf>текст</rdf>\0")),
    frame(), end()]);

  assert.deepEqual(result.tags?.find(tag => tag.code === 77), { code: 77, count: 1, bodyBytes: 22 });
  assert.deepEqual(result.issues, []);
});

const malformedTags: Array<[string, Uint8Array[], RegExp]> = [
  ["short header", [Uint8Array.of(0)], /tag header is truncated/],
  ["long header", [Uint8Array.of(0x7f, 0)], /tag header/],
  ["body bounds", [Uint8Array.of(0x41, 0)], /body extends/],
  ["nonempty End", [createSwfTag(0, Uint8Array.of(0))], /empty bodies/],
  ["nonempty ShowFrame", [createSwfTag(1, Uint8Array.of(0))], /empty bodies/],
  ["short attributes", [createSwfTag(69, Uint8Array.of(8))], /four bytes/],
  ["late attributes", [frame(), attributes()], /first tag/],
  ["duplicate attributes", [attributes(), attributes()], /duplicated/],
  ["empty metadata", [createSwfTag(77)], /Metadata tag is empty/],
  ["unterminated metadata", [createSwfTag(77, Uint8Array.of(65))], /NUL-terminated/],
];

for (const [name, tags, message] of malformedTags) {
  void test(`readSwfTags rejects ${name}`, async () => {
    await assert.rejects(scan(tags), message);
  });
}

void test("readSwfTags reports missing End, required attributes, frame mismatch and trailing bytes", async () => {
  const missingEnd = await scan([attributes(), frame()]);
  const missingAttributes = await scan([frame(), end()]);
  const mismatch = await scan([attributes(), end()]);
  const trailing = await scan([attributes(), frame(), end(), frame()]);

  assert.match(missingEnd.issues.join(), /End tag is missing/);
  assert.match(missingAttributes.issues.join(), /require FileAttributes/);
  assert.match(mismatch.issues.join(), /frame count/);
  assert.match(trailing.issues.join(), /after the End/);
});

void test("readSwfTags checks attribute consistency without inventing an interpretation of reserved bits", async () => {
  const reserved = await scan([attributes(0x88), frame(), end()]);
  const oldAs3 = await scan([attributes(), frame(), end()], 8);
  const oldGpu = await scan([attributes(0x60), frame(), end()]);
  const missingMetadata = await scan([attributes(24), frame(), end()]);
  const extraMetadata = await scan([attributes(), createSwfTag(77, Uint8Array.of(0)), frame(), end()]);

  assert.equal(reserved.fileAttributes, 0x88);
  assert.match(reserved.issues.join(), /reserved bits/);
  assert.match(oldAs3.issues.join(), /ActionScript3/);
  assert.match(oldGpu.issues.join(), /GPU/);
  assert.match(missingMetadata.issues.join(), /Metadata tag disagree/);
  assert.match(extraMetadata.issues.join(), /Metadata tag disagree/);
});

void test("readSwfTags permits older SWF without FileAttributes and SWF 10 hardware flags", async () => {
  const old = await scan([frame(), end()], 7);
  const current = await scan([attributes(0x60), frame(), end()], 10);

  assert.deepEqual(old.issues, []);
  assert.deepEqual(current.issues, []);
});

void test("readSwfTags has no metadata size cutoff and reports duplicate metadata", async () => {
  const large = await scan([attributes(24), createSwfTag(77, new Uint8Array(100000)), frame(), end()]);
  const duplicate = await scan([attributes(24), createSwfTag(77, Uint8Array.of(0)),
    createSwfTag(77, Uint8Array.of(0)), frame(), end()]);

  assert.deepEqual(large.issues, []);
  assert.match(duplicate.issues.join(), /duplicated/);
});

void test("readSwfTags validates a distant metadata terminator and aggregates repeated body sizes", async () => {
  const metadata = new Uint8Array(100000);
  metadata[metadata.length - 1] = 65;
  const repeated = await scan([attributes(), createSwfTag(999, Uint8Array.of(7, 8)),
    createSwfTag(999, Uint8Array.of(9)), frame(), end()]);

  await assert.rejects(scan([attributes(24), createSwfTag(77, metadata), frame(), end()]), /NUL-terminated/);
  assert.deepEqual(repeated.tags?.find(tag => tag.code === 999), { code: 999, count: 2, bodyBytes: 3 });
});

for (const tag of [createSwfTag(68, new Uint8Array(4)), createSwfTag(69, new Uint8Array(3)),
  Uint8Array.of(0x7f, 0x11, 4), Uint8Array.of(0x44, 0x11, 8)]) {
  void test(`readFirstSwfAttributes rejects a SWF 8 lookalike ${Buffer.from(tag).toString("hex")}`, async () => {
    const result: SwfParseResult = { signature: "CWS", version: 8, fileLength: tag.length, issues: [] };

    await assert.rejects(readFirstSwfAttributes(new MockFile(tag), 0, result), /first tag/);
    assert.equal(result.fileAttributes, undefined);
  });
}

void test("readFirstSwfAttributes accepts long-form headers and leaves older missing attributes unknown", async () => {
  // RECORDHEADER long form is allowed even for a short body (Adobe SWF v19, chapter 2).
  const long = new MockFile(Uint8Array.of(0x7f, 0x11, 4, 0, 0, 0, 8, 0, 0, 0));
  const older: SwfParseResult = { signature: "CWS", version: 7, fileLength: 30, issues: [] };
  const current: SwfParseResult = { ...older, version: 9, issues: [] };

  await readFirstSwfAttributes(long, 0, current);
  await readFirstSwfAttributes(new MockFile(Uint8Array.of(0, 0)), 0, older);
  const scanned = await scan([long.data, frame(), end()]);

  assert.equal(current.fileAttributes, 8);
  assert.equal(older.fileAttributes, undefined);
  assert.deepEqual(scanned.issues, []);
  await assert.rejects(readFirstSwfAttributes(new MockFile(Uint8Array.of(0)), 0, current), /first tag/);
});
