import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeFlashProjector, isValidatedProjectorMovie } from "../../../../analyzers/pe/flash-projector.js";
import type { SwfParseResult } from "../../../../analyzers/swf/types.js";
import { createFlashProjector, createFlashProjectorPe, createCws, createZws, createSwf,
  createSwfTag } from "../../../fixtures/swf-fixtures.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { analyzePePayloads, resolveProjectorCandidate, subtractExplainedPeOverlay } from "../../../../analyzers/pe/payloads.js";
import { analyzeSwfBody } from "../../../../analyzers/swf/index.js";
import { parsePe, isPeWindowsParseResult } from "../../../../analyzers/pe/index.js";

const verifiedMovie = (): SwfParseResult => ({ signature: "FWS", version: 9, fileLength: 31, tagEnd: 31,
  movie: { xMin: 0, xMax: 12800, yMin: 0, yMax: 9600, frameRate: 7680, frameCount: 1 },
  tags: [], issues: [] });

void test("Projector publication requires a checked outer boundary and a nonempty movie, not only a prefix", () => {
  const swf = verifiedMovie();
  const missingMovie = verifiedMovie();
  delete missingMovie.movie;

  assert.equal(isValidatedProjectorMovie(swf), true);
  assert.equal(isValidatedProjectorMovie({ ...swf, issues: ["bad body"] }), false);
  assert.equal(isValidatedProjectorMovie({ ...swf, tagEnd: 30 }), false);
  assert.equal(isValidatedProjectorMovie(missingMovie), false);
  assert.equal(isValidatedProjectorMovie({ ...swf, movie: { ...swf.movie!, frameCount: 0 } }), false);
  assert.equal(isValidatedProjectorMovie({ ...swf, movie: { ...swf.movie!, frameRate: 0 } }), false);
  assert.equal(isValidatedProjectorMovie({ ...swf, movie: { ...swf.movie!, xMax: 0 } }), false);
  assert.equal(isValidatedProjectorMovie({ ...swf, movie: { ...swf.movie!, yMax: 0 } }), false);
});

void test("analyzeFlashProjector confirms footer, outer SWF structure and exact payload bounds", async () => {
  const file = createFlashProjector();

  const result = await analyzeFlashProjector(file, 64);

  assert.equal(result?.start, 128);
  assert.equal(result?.end, file.size - 8);
  assert.deepEqual(result?.swf.issues, []);
});

void test("PE parsing exposes the confirmed SWF as a downloadable payload", async () => {
  const file = createFlashProjectorPe();

  const result = await parsePe(file);

  assert.ok(result && isPeWindowsParseResult(result));
  assert.equal(result.payloads?.entries[0]?.format, "swf");
  assert.equal(result.overlay, undefined);
});

void test("analyzeFlashProjector supports a validated CWS and arbitrary player prefix sizes", async () => {
  const file = createFlashProjector(createCws(), 513);

  const result = await analyzeFlashProjector(file, 513);

  assert.equal(result?.start, 513);
  assert.equal(result?.swf.signature, "CWS");
});

void test("compressed Projector candidates are not published before their complete bodies are checked", async () => {
  const file = createFlashProjector(createCws());
  const overlay = { ranges: [{ start: 64, end: file.size, size: file.size - 64, findings: [] }] };

  const pending = await analyzePePayloads(file, file, overlay, null);
  assert.ok(pending?.projectorCandidate);
  const body = await analyzeSwfBody(file, 128, file.size - 8, pending.projectorCandidate.swf);
  const resolved = resolveProjectorCandidate(pending, body);

  assert.deepEqual(pending.entries, []);
  assert.equal(resolved.projectorCandidate, undefined);
  assert.equal(resolved.entries[0]?.format, "swf");
  assert.equal(resolved.entries[0]?.start, 128);
  assert.equal(resolveProjectorCandidate(resolved, body), resolved);
});

void test("ZWS footer/header evidence remains an internal candidate and failed body checks do not create a finding", async () => {
  const file = createFlashProjector(createZws());
  const overlay = { ranges: [{ start: 64, end: file.size, size: file.size - 64, findings: [] }] };

  const pending = await analyzePePayloads(file, file, overlay, null);
  assert.ok(pending?.projectorCandidate);
  const rejected = resolveProjectorCandidate(pending, { ...pending.projectorCandidate.swf, issues: ["bad body"] });

  assert.deepEqual(pending.entries, []);
  assert.equal(pending.projectorCandidate.swf.movie, undefined);
  assert.deepEqual(rejected.entries, []);
  assert.deepEqual(rejected.projectorCandidate?.swf.issues, ["bad body"]);
});

void test("analyzeFlashProjector rejects arbitrary footer markers, lengths and payload locations", async () => {
  const file = createFlashProjector();
  const marker = file.data.slice();
  marker[marker.length - 8] = marker[marker.length - 8]! ^ 1;
  const length = file.data.slice();
  new DataView(length.buffer).setUint32(length.length - 4, 0xffffffff, true);
  const zeroLength = file.data.slice();
  new DataView(zeroLength.buffer).setUint32(zeroLength.length - 4, 0, true);

  assert.equal(await analyzeFlashProjector(new MockFile(marker), 64), null);
  assert.equal(await analyzeFlashProjector(new MockFile(length), 64), null);
  assert.equal(await analyzeFlashProjector(new MockFile(zeroLength), 64), null);
  assert.equal(await analyzeFlashProjector(file, 129), null);
  assert.equal(await analyzeFlashProjector(file, -1), null);
  assert.equal(await analyzeFlashProjector(file, Number.NaN), null);
  assert.equal(await analyzeFlashProjector(new MockFile(new Uint8Array(8)), 0), null);
});

void test("analyzeFlashProjector requires SWF structure and does not search before EOF", async () => {
  const invalid = createFlashProjector(new Uint8Array(32));
  const complete = createFlashProjector();
  const suffixed = Buffer.concat([complete.data, Uint8Array.of(0)]);

  assert.equal(await analyzeFlashProjector(invalid, 64), null);
  assert.equal(await analyzeFlashProjector(new MockFile(suffixed), 64), null);
});

void test("analyzeFlashProjector does not cap a dense tag chain", async () => {
  const dense = createFlashProjector(createSwf(Array.from({ length: 600 }, () => createSwfTag(999))));

  const result = await analyzeFlashProjector(dense, 64);

  assert.equal(result?.swf.tags?.find(tag => tag.code === 999)?.count, 600);
  assert.deepEqual(result?.swf.issues, []);
});

void test("analyzeFlashProjector rejects inconsistent tag chains and unsupported compression", async () => {
  const mismatch = createSwf();
  new DataView(mismatch.buffer).setUint16(19, 2, true); // Fixture movie header FrameCount.
  const zws = createSwf();
  zws[0] = 0x5a;
  zws[3] = 13;

  assert.equal(await analyzeFlashProjector(createFlashProjector(mismatch), 64), null);
  assert.equal(await analyzeFlashProjector(createFlashProjector(zws), 64), null);
});

void test("Projector payload spans contradictory SECURITY gaps and removes only confirmed payload/footer bytes", async () => {
  const file = createFlashProjector(createSwf(), 128);
  const overlay = { ranges: [
    { start: 64, end: 136, size: 72, findings: [] },
    { start: 144, end: file.size, size: file.size - 144, findings: [] }
  ] };

  const payloads = await analyzePePayloads(file, file, overlay, null);
  const remaining = await subtractExplainedPeOverlay(file, null, overlay, null, payloads);

  assert.equal(payloads?.entries.length, 1);
  assert.equal(payloads?.entries[0]?.format, "swf");
  assert.deepEqual(payloads?.entries[0]?.provenance, { location: "overlay", discovery: "projector-footer",
    association: "flash-projector", validation: "projector-footer" });
  assert.deepEqual(remaining?.ranges, [{ start: 64, end: 128, size: 64, findings: [] }]);
});
