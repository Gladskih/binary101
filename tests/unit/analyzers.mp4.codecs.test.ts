"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { readEsds } from "../../analyzers/mp4/audio-codecs.js";
import { parsePasp, readAv1C, readAvcC, readHvcC, readVpcc } from "../../analyzers/mp4/codecs.js";
import { buildMp4Label, parseMp4 } from "../../analyzers/mp4/index.js";
import { parseStsd } from "../../analyzers/mp4/sample-description.js";
import { parseMinf, parseStbl } from "../../analyzers/mp4/sample-tables.js";
import { parseTrak } from "../../analyzers/mp4/track.js";
import type { Mp4ParseResult } from "../../analyzers/mp4/types.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  buildAudioSampleEntry,
  buildCo64Box,
  buildEsdsBox,
  buildSampleEntry,
  buildStcoBox,
  buildStsdBox,
  buildStssBox,
  buildStszBox,
  buildSttsBox,
  buildTrakBox,
  buildVideoSampleEntry,
  concatParts,
  makeBox
} from "../helpers/mp4-test-builders.js";

void test("parseStsd reports truncated box", () => {
  const issues: string[] = [];
  const result = parseStsd(new DataView(new Uint8Array(4).buffer), 0, 4, null, issues);
  assert.strictEqual(result, null);
  assert.ok(issues.some(msg => msg.includes("stsd box truncated")));
});
void test("parseStsd reports empty sample description table", () => {
  const payload = concatParts([new Uint8Array(8).fill(0)]);
  const issues: string[] = [];
  const result = parseStsd(new DataView(payload.buffer), 0, payload.length, null, issues);
  assert.strictEqual(result, null);
  assert.ok(issues.some(msg => msg.includes("has no sample descriptions")));
});
void test("parseStsd reads visual sample entry", () => {
  const entry = buildStsdBox([buildVideoSampleEntry()]);
  const issues: string[] = [];
  const result = parseStsd(new DataView(entry.buffer), 8, entry.length - 8, "vide", issues);
  assert.ok(result);
  assert.strictEqual(result?.width, 640);
  assert.strictEqual(result?.height, 360);
  assert.strictEqual(result?.pixelAspectRatio, "4:3");
  assert.strictEqual(result?.codecString, "avc1.42001e");
  assert.strictEqual(result?.description, "H264");
  assert.strictEqual(issues.length, 0);
});
void test("parseStsd reads audio sample entry", () => {
  const entry = buildStsdBox([buildAudioSampleEntry()]);
  const result = parseStsd(new DataView(entry.buffer), 8, entry.length - 8, "soun", []);
  assert.ok(result);
  assert.strictEqual(result?.channels, 2);
  assert.strictEqual(result?.sampleRate, 48000);
  assert.strictEqual(result?.codecString, "mp4a.40.2");
});
void test("parseStsd reads generic sample entry", () => {
  const entry = buildStsdBox([buildSampleEntry("text", new Uint8Array(8), [])]);
  const issues: string[] = [];
  const result = parseStsd(new DataView(entry.buffer), 8, entry.length - 8, null, issues);
  assert.ok(result);
  assert.strictEqual(result?.codecString, "text");
  assert.strictEqual(issues.length, 0);
});
void test("parsePasp rejects too-small payloads", () => {
  assert.strictEqual(parsePasp(new DataView(new Uint8Array(4).buffer), 0, 4), null);
  assert.strictEqual(parsePasp(new DataView(new Uint8Array(8).buffer), 0, 8), null);
});
void test("parsePasp reads pixel aspect ratio", () => {
  const payload = new Uint8Array(8);
  const dv = new DataView(payload.buffer);
  dv.setUint32(0, 16, false);
  dv.setUint32(4, 9, false);
  assert.strictEqual(parsePasp(new DataView(payload.buffer), 0, 8), "16:9");
});
void test("readAvcC builds codec string and profile", () => {
  const avc = readAvcC(new DataView(new Uint8Array([0x01, 0x4a, 0x00, 0x1e]).buffer), 0, 4, "avc1");
  assert.strictEqual(avc.codecString, "avc1.4a001e");
  assert.strictEqual(avc.profile, "Profile 74");
});
void test("readAvcC returns null string for short payload", () => {
  const avc = readAvcC(new DataView(new Uint8Array([0x01]).buffer), 0, 1, "avc1");
  assert.strictEqual(avc.codecString, null);
});
void test("readHvcC handles truncated payload", () => {
  const small = readHvcC(new DataView(new Uint8Array(4).buffer), 0, 4, "hvc1");
  assert.strictEqual(small.codecString, null);
});
void test("readHvcC parses profile and level", () => {
  const payload = new Uint8Array(16).fill(0);
  const dv = new DataView(payload.buffer);
  dv.setUint8(1, 2);
  dv.setUint8(12, 60);
  const full = readHvcC(new DataView(payload.buffer), 0, payload.length, "hvc1");
  assert.strictEqual(full.profile, "Main 10");
  assert.strictEqual(full.level, "Level 2");
});
void test("readAv1C handles short payload", () => {
  const small = readAv1C(new DataView(new Uint8Array(2).buffer), 0, 2, "av01");
  assert.strictEqual(small.codecString, null);
});
void test("readAv1C parses bit depth and codec string", () => {
  const payload = new Uint8Array([0x10, 0x2f, 0x50, 0x00]);
  const full = readAv1C(new DataView(payload.buffer), 0, payload.length, "av01");
  assert.strictEqual(full.codecString, "av01.1.15");
  assert.strictEqual(full.bitDepth, 12);
});
void test("readVpcc handles short payload", () => {
  const small = readVpcc(new DataView(new Uint8Array(2).buffer), 0, 2, "vp09");
  assert.strictEqual(small.codecString, null);
});
void test("readVpcc parses bit depth and codec string", () => {
  const payload = new Uint8Array([0x02, 0x1e, 0x0a, 0x00]);
  const full = readVpcc(new DataView(payload.buffer), 0, payload.length, "vp09");
  assert.strictEqual(full.codecString, "vp09.02.30");
  assert.strictEqual(full.bitDepth, 10);
});
void test("readEsds falls back to declared sample rate and channels", () => {
  const codec = readEsds(new DataView(new Uint8Array(0).buffer), 0, 0, "mp4a", 44100, 2);
  assert.strictEqual(codec.sampleRate, 44100);
  assert.strictEqual(codec.channels, 2);
});
void test("readEsds ignores non-esds tag", () => {
  const bytes = new Uint8Array(8).fill(0);
  bytes[4] = 0xff;
  const codec = readEsds(new DataView(bytes.buffer), 0, bytes.length, "mp4a", null, null);
  assert.strictEqual(codec.codecString, "mp4a");
});
void test("readEsds parses decoder specific info", () => {
  const esds = buildEsdsBox();
  const codec = readEsds(new DataView(esds.buffer), 8, esds.length - 8, "mp4a", null, null);
  assert.strictEqual(codec.codecString, "mp4a.40.2");
  assert.strictEqual(codec.sampleRate, 48000);
});
void test("parseMinf aggregates codec and table summaries", () => {
  const stsd = buildStsdBox([buildVideoSampleEntry()]);
  const stts = buildSttsBox(2, 90000);
  const stsz = buildStszBox(0, 2);
  const stco = buildCo64Box(3);
  const stss = buildStssBox(1);
  const stbl = makeBox("stbl", concatParts([stsd, stts, stsz, stco, stss]));
  const minfBox = makeBox("minf", stbl);
  const minf = parseMinf(new DataView(minfBox.buffer), 8, minfBox.length - 8, "vide", []);
  assert.ok(minf.codec);
  assert.strictEqual(minf.tables.stts?.sampleCount, 2);
  assert.strictEqual(minf.tables.stco?.chunkCount, 3);
  assert.strictEqual(minf.tables.stss?.keyframeCount, 1);
});
void test("parseStbl returns codec and table data", () => {
  const stsd = buildStsdBox([buildVideoSampleEntry()]);
  const stts = buildSttsBox(2, 90000);
  const stsz = buildStszBox(0, 2);
  const stco = buildCo64Box(3);
  const stss = buildStssBox(1);
  const stbl = makeBox("stbl", concatParts([stsd, stts, stsz, stco, stss]));
  const parsed = parseStbl(new DataView(stbl.buffer), 8, stbl.length - 8, "vide", []);
  assert.ok(parsed.codec);
  assert.strictEqual(parsed.tables.stsz?.sampleCount, 2);
});
void test("parseTrak merges tkhd and mdia data", () => {
  const stsd = buildStsdBox([buildAudioSampleEntry()]);
  const stts = buildSttsBox(4, 12000);
  const stsz = buildStszBox(1024, 4);
  const stco = buildStcoBox(2);
  const stss = buildStssBox(0);
  const stbl = makeBox("stbl", concatParts([stsd, stts, stsz, stco, stss]));
  const trak = buildTrakBox("subt", "Captions", 24000, 48000, stbl);
  const issues: string[] = [];
  const parsed = parseTrak(new DataView(trak.buffer), 8, trak.length - 8, issues);
  assert.ok(parsed);
  assert.strictEqual(parsed?.kind, "subtitles");
  assert.strictEqual(parsed?.durationSeconds, 2);
  assert.strictEqual(parsed?.sampleCount, 4);
  assert.strictEqual(parsed?.chunkCount, 2);
  assert.strictEqual(parsed?.handlerName, "Captions");
  assert.strictEqual(issues.length, 0);
});
void test("parseTrak returns null for empty payload", () => {
  const parsed = parseTrak(new DataView(new Uint8Array(0).buffer), 0, 0, []);
  assert.strictEqual(parsed, null);
});
void test("parseMp4 returns null for non-MP4 data", async () => {
  const tiny = new MockFile(new Uint8Array(4), "small.bin", "application/octet-stream");
  assert.strictEqual(await parseMp4(tiny), null);
});
void test("parseMp4 returns null for wrong first box type", async () => {
  const bytes = new Uint8Array(12).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 12, false);
  const wrongFile = new MockFile(bytes, "wrong.mp4", "video/mp4");
  assert.strictEqual(await parseMp4(wrongFile), null);
});
void test("parseMp4 reports missing movie metadata", async () => {
  const ftyp = makeBox("ftyp", new Uint8Array([0, 0, 0, 0]));
  const moof = makeBox("moof", new Uint8Array());
  const mdat = makeBox("mdat", new Uint8Array([1, 2, 3, 4]));
  const moov = makeBox("moov", new Uint8Array());
  const bytes = concatParts([ftyp, mdat, moof, moov]);
  const parsed = await parseMp4(new MockFile(bytes, "warn.mp4", "video/mp4"));
  assert.ok(parsed);
  assert.strictEqual(parsed.fragmentCount, 1);
  assert.strictEqual(parsed.mdatBytes, mdat.length);
  assert.strictEqual(parsed.fastStart, false);
  assert.ok(parsed.warnings.some(msg => msg.includes("ftyp box is too small")));
  assert.ok(parsed.warnings.some(msg => msg.includes("Movie header not found")));
  assert.ok(parsed.warnings.some(msg => msg.includes("No tracks were parsed")));
});
void test("buildMp4Label formats audio-only track", () => {
  const parsed: Mp4ParseResult = {
    isMp4: true,
    brands: { majorBrand: "dash", minorVersion: 0, compatibleBrands: [] },
    movieHeader: {
      creationTime: null,
      modificationTime: null,
      timescale: 1000,
      duration: 9876,
      durationSeconds: 9.876,
      rate: 1,
      volume: 1,
      nextTrackId: 1
    },
    tracks: [
      {
        id: 1,
        kind: "audio",
        handlerType: "soun",
        handlerName: null,
        creationTime: null,
        modificationTime: null,
        duration: 9876,
        durationSeconds: 9.876,
        timescale: 1000,
        language: "eng",
        width: null,
        height: null,
        volume: 1,
        sampleCount: 5,
        keyframeCount: null,
        chunkCount: null,
        sampleSizeConstant: null,
        codec: {
          format: "mp4a",
          codecString: null,
          profile: null,
          level: null,
          description: "AAC LC",
          width: null,
          height: null,
          pixelAspectRatio: null,
          channels: 2,
          sampleRate: 44100,
          bitDepth: 16,
          bitrate: null
        },
        warnings: []
      }
    ],
    fragmentCount: 0,
    mdatBytes: 0,
    fastStart: null,
    topLevelBoxes: [],
    warnings: []
  };
  const label = buildMp4Label(parsed);
  assert.ok(label?.startsWith("dash MP4"));
  assert.ok(label?.includes("audio: AAC LC, 44100 Hz, 2 ch"));
  assert.ok(label?.includes("9.876 s"));
});
void test("buildMp4Label uses movie header duration for formatting", () => {
  const parsed: Mp4ParseResult = {
    isMp4: true,
    brands: null,
    movieHeader: {
      creationTime: null,
      modificationTime: null,
      timescale: 1000,
      duration: 123456,
      durationSeconds: 123.456,
      rate: 1,
      volume: 1,
      nextTrackId: 1
    },
    tracks: [],
    fragmentCount: 0,
    mdatBytes: 0,
    fastStart: null,
    topLevelBoxes: [],
    warnings: []
  };
  const label = buildMp4Label(parsed);
  assert.ok(label?.includes("123.5 s"));
});
