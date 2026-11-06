import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeSwfBody, parseSwf, parseSwfRange } from "../../../../analyzers/swf/index.js";
import { createSwf, createCws, createZws, createSwfTag } from "../../../fixtures/swf-fixtures.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { detectBinaryType } from "../../../../analyzers/detect-binary-type.js";
import { parseForUi } from "../../../../analyzers/parse-for-ui.js";

class UnreadableSwfFile extends MockFile {
  override slice(): Blob { throw new Error("unavailable"); }
}

void test("parseSwf reads FWS movie properties and verifies the complete outer tag chain", async () => {
  const file = new MockFile(createSwf());

  const result = await parseSwf(file);

  assert.equal(result?.signature, "FWS");
  assert.deepEqual(result?.movie, { xMin: 0, xMax: 12800, yMin: 0, yMax: 9600,
    frameRate: 7680, frameCount: 1 });
  assert.equal(result?.fileAttributes, 8);
  assert.deepEqual(result?.tags?.map(tag => tag.code), [69, 1, 0]);
  assert.equal(result?.tagEnd, file.size);
  assert.deepEqual(result?.issues, []);
});

void test("CWS prefix inspection defers tag and stream verification until explicitly requested", async () => {
  const file = new MockFile(createCws());

  const header = await parseSwf(file);
  assert.ok(header);
  const result = await analyzeSwfBody(file, 0, file.size, header);

  assert.equal(header.signature, "CWS");
  assert.equal(header.movie?.frameCount, 1);
  assert.equal(header.fileAttributes, 8);
  assert.equal(header.tags, undefined);
  assert.deepEqual(result.tags?.map(tag => tag.code), [69, 1, 0]);
  assert.deepEqual(result.issues, []);
});

void test("ZWS inspection keeps undecoded movie fields unknown and can decode the body on request", async () => {
  const file = new MockFile(createZws());

  const header = await parseSwf(file);
  assert.ok(header);
  const result = await analyzeSwfBody(file, 0, file.size, header);

  assert.equal(header.signature, "ZWS");
  assert.equal(header.movie, undefined);
  assert.equal(header.tags, undefined);
  assert.deepEqual(header.issues, []);
  assert.equal(result.movie?.frameCount, 1);
  assert.deepEqual(result.lzma, header.lzma);
  assert.deepEqual(result.tags?.map(tag => tag.code), [69, 1, 0]);
  assert.deepEqual(result.issues, []);
});

void test("compressed body failures become issues and CWS version 6 remains supported", async () => {
  const older = createSwf();
  older[3] = 6;
  // Before SWF 9 the AS3 flag must be clear.
  older[23] = 0;
  const oldFile = new MockFile(createCws(older));
  const zws = new MockFile(createZws());
  const header = await parseSwf(zws);
  assert.ok(header);

  assert.deepEqual((await parseSwf(oldFile))?.issues, []);
  assert.ok((await analyzeSwfBody(zws, 0, zws.size - 6, header)).issues.length > 0);
  assert.match((await parseSwf(new MockFile(createSwf().subarray(0, 8))))?.issues.join() ?? "", /length differs/);
});

void test("standalone SWF reaches detection and the UI parse contract", async () => {
  const file = new MockFile(createSwf(), "arbitrary.bin");

  assert.equal(await detectBinaryType(file), "Flash SWF (v9, FWS)");
  const result = await parseForUi(file);
  assert.ok(result.analyzer === "swf");
  assert.equal(result.parsed.signature, "FWS");
});

void test("parseSwf rejects invalid prefixes, failed I/O and malformed file/movie/tag data", async () => {
  const failed = new UnreadableSwfFile(createSwf());
  const wrongLength = createSwf();
  new DataView(wrongLength.buffer).setUint32(4, wrongLength.length + 1, true);
  const missingEnd = createSwf();
  missingEnd[missingEnd.length - 2] = 0x40; // ShowFrame replaces the outer End tag.

  assert.equal(await parseSwf(new MockFile(new Uint8Array(20))), null);
  assert.equal(await parseSwf(failed), null);
  assert.equal(await parseSwf(failed, new DataView(new ArrayBuffer(8))), null);
  assert.match((await parseSwf(new MockFile(wrongLength)))?.issues.join() ?? "", /length differs/);
  assert.match((await parseSwf(new MockFile(missingEnd)))?.issues.join() ?? "", /End tag is missing/);
});

void test("CWS rejects versions before zlib support and body inspection detects a damaged stream", async () => {
  const old = createCws();
  old[3] = 5;
  const damaged = createCws();
  damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1;
  const file = new MockFile(damaged);

  const header = await parseSwf(file);
  assert.ok(header);
  const body = await analyzeSwfBody(file, 0, file.size, header);

  assert.match((await parseSwf(new MockFile(old)))?.issues.join() ?? "", /SWF 6/);
  assert.ok(body.issues.length > 0);
});

void test("parseSwf aggregates all tags without a count cutoff", async () => {
  const bytes = createSwf(Array.from({ length: 600 }, () => createSwfTag(999)));

  const result = await parseSwf(new MockFile(bytes));

  assert.deepEqual(result?.tags?.find(tag => tag.code === 999), { code: 999, count: 600, bodyBytes: 0 });
  assert.deepEqual(result?.issues, []);
});

void test("parseSwfRange rejects nonintegral, negative, reversed and out-of-file ranges", async () => {
  const file = new MockFile(createSwf());

  assert.equal(await parseSwfRange(file, -1, file.size), null);
  assert.equal(await parseSwfRange(file, 0.5, file.size), null);
  assert.equal(await parseSwfRange(file, 0, file.size + 1), null);
  assert.equal(await parseSwfRange(file, file.size, 0), null);
  assert.equal(await parseSwfRange(file, 0, Number.NaN), null);
});

void test("movie header anomalies and invalid compressed body ranges remain explicit failures", async () => {
  const reversed = new MockFile(createSwf([], [12800, 0, 0, 9600]));
  const file = new MockFile(createCws());
  const header = await parseSwf(file);
  assert.ok(header);

  assert.match((await parseSwf(reversed))?.issues.join() ?? "", /reversed coordinates/);
  assert.match((await analyzeSwfBody(file, -1, file.size, header)).issues.join(), /range or signature/);
  assert.match((await analyzeSwfBody(file, 0, file.size, { ...header, signature: "FWS" })).issues.join(), /range or signature/);
});
