"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseCreationTime,
  parseLanguage,
  readBoxHeaderFromFile,
  readBoxHeaderFromView,
  readUint16Safe,
  toFourCcFromView
} from "../../analyzers/mp4/boxes.js";
import { parseMvhd } from "../../analyzers/mp4/movie-header.js";
import { parseCo64, parseStco, parseStss, parseStsz, parseStts } from "../../analyzers/mp4/sample-tables.js";
import { parseHdlr, parseMdhd, parseTkhd } from "../../analyzers/mp4/track.js";
import { MockFile } from "../helpers/mock-file.js";
import { buildHdlrBox } from "../helpers/mp4-test-builders.js";

const encoder = new TextEncoder();

void test("toFourCc and helpers decode values safely", () => {
  const fourCcView = new DataView(Uint8Array.from([0x66, 0x74, 0x79, 0x70]).buffer);
  assert.strictEqual(toFourCcFromView(fourCcView, 0), "ftyp");
  assert.strictEqual(toFourCcFromView(fourCcView, 1), "");
  assert.strictEqual(readUint16Safe(fourCcView, 2), 0x7970);
  assert.strictEqual(readUint16Safe(fourCcView, 3), null);
  assert.strictEqual(parseLanguage(0x15c7), "eng");
  assert.strictEqual(parseLanguage(0), null);
  assert.strictEqual(parseCreationTime(0), null);
  assert.strictEqual(parseCreationTime(2082844800), "1970-01-01T00:00:00.000Z");
  assert.strictEqual(parseCreationTime(-1), null);
  assert.strictEqual(parseCreationTime(Number.NaN), null);
});

void test("readBoxHeaderFromFile warns on missing header bytes", async () => {
  const tooSmallFile = new MockFile(new Uint8Array([0]), "tiny.bin", "application/octet-stream");
  const issues: string[] = [];
  const header = await readBoxHeaderFromFile(tooSmallFile, 0, issues, "MP4");
  assert.strictEqual(header, null);
  assert.ok(issues.some(msg => msg.includes("not enough data")));
});

void test("readBoxHeaderFromFile rejects invalid box size", async () => {
  const bytes = new Uint8Array(16);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 4, false);
  bytes.set(encoder.encode("bad!"), 4);
  const issues: string[] = [];
  const header = await readBoxHeaderFromFile(new MockFile(bytes, "bad.mp4", "video/mp4"), 0, issues, "MP4");
  assert.strictEqual(header, null);
  assert.ok(issues.some(msg => msg.includes("invalid size")));
});

void test("readBoxHeaderFromFile reads large-size box and notes truncation", async () => {
  const bytes = new Uint8Array(20);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 1, false);
  bytes.set(encoder.encode("wide"), 4);
  dv.setBigUint64(8, BigInt(40), false);
  const issues: string[] = [];
  const header = await readBoxHeaderFromFile(new MockFile(bytes, "wide.mp4", "video/mp4"), 0, issues, "MP4");
  assert.ok(header);
  assert.strictEqual(header?.headerSize, 16);
  assert.strictEqual(header?.size, 40);
  assert.strictEqual(header?.truncated, true);
  assert.strictEqual(header?.end, bytes.length);
});

void test("readBoxHeaderFromView reports truncated header", () => {
  const view = new DataView(new Uint8Array([0, 0, 0, 0]).buffer);
  const issues: string[] = [];
  const header = readBoxHeaderFromView(view, 0, 100, issues);
  assert.strictEqual(header, null);
  assert.ok(issues.some(msg => msg.includes("header truncated")));
});

void test("readBoxHeaderFromView rejects truncated large-size header", () => {
  const bytes = new Uint8Array(12);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 1, false);
  bytes.set(encoder.encode("long"), 4);
  const issues: string[] = [];
  const header = readBoxHeaderFromView(new DataView(bytes.buffer), 0, 200, issues);
  assert.strictEqual(header, null);
  assert.ok(issues.some(msg => msg.includes("Large size header truncated")));
});

void test("readBoxHeaderFromView marks truncated box end", () => {
  const bytes = new Uint8Array(12);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 20, false);
  bytes.set(encoder.encode("data"), 4);
  const issues: string[] = [];
  const header = readBoxHeaderFromView(new DataView(bytes.buffer), 0, 300, issues);
  assert.ok(header);
  assert.strictEqual(header?.truncated, true);
  assert.strictEqual(header?.end, 312);
});

void test("parseMvhd reads version 0 payload", () => {
  const payload = new Uint8Array(32).fill(0);
  const dv = new DataView(payload.buffer);
  dv.setUint32(4, 1, false);
  dv.setUint32(8, 2, false);
  dv.setUint32(12, 1000, false);
  dv.setUint32(16, 2000, false);
  dv.setUint32(20, 0x00010000, false);
  dv.setUint16(24, 0x0100, false);
  dv.setUint32(28, 9, false);
  const issues: string[] = [];
  const mvhd = parseMvhd(new DataView(payload.buffer), 0, payload.length, issues);
  assert.ok(mvhd);
  assert.strictEqual(mvhd?.durationSeconds, 2);
  assert.strictEqual(mvhd?.rate, 1);
  assert.strictEqual(mvhd?.volume, 1);
  assert.strictEqual(mvhd?.nextTrackId, 9);
  assert.strictEqual(issues.length, 0);
});

void test("parseMvhd flags truncated version 1 payload", () => {
  const payload = new Uint8Array(28).fill(0);
  payload[0] = 1;
  const issues: string[] = [];
  const mvhd = parseMvhd(new DataView(payload.buffer), 0, payload.length, issues);
  assert.strictEqual(mvhd, null);
  assert.ok(issues.some(msg => msg.includes("version 1 box truncated")));
});

void test("parseMvhd reads version 1 payload", () => {
  const payload = new Uint8Array(48).fill(0);
  const dv = new DataView(payload.buffer);
  dv.setUint8(0, 1);
  dv.setBigUint64(4, BigInt(2), false);
  dv.setBigUint64(12, BigInt(4), false);
  dv.setUint32(20, 50, false);
  dv.setBigUint64(24, BigInt(500), false);
  dv.setUint32(32, 0x00020000, false);
  dv.setUint16(36, 0x0180, false);
  dv.setUint32(44, 7, false);
  const issues: string[] = [];
  const mvhd = parseMvhd(new DataView(payload.buffer), 0, payload.length, issues);
  assert.ok(mvhd);
  assert.strictEqual(mvhd?.durationSeconds, 10);
  assert.strictEqual(mvhd?.rate, 2);
  assert.strictEqual(mvhd?.volume, 1.5);
  assert.strictEqual(mvhd?.nextTrackId, 7);
});

void test("parseTkhd reports truncated payloads", () => {
  const issues: string[] = [];
  const tkhd = parseTkhd(new DataView(new Uint8Array(10).buffer), 0, 10, issues);
  assert.strictEqual(tkhd, null);
  assert.ok(issues.some(msg => msg.includes("tkhd box truncated")));
});

void test("parseTkhd reads version 1 payload", () => {
  const payload = new Uint8Array(96).fill(0);
  const dv = new DataView(payload.buffer);
  dv.setUint8(0, 1);
  dv.setBigUint64(4, BigInt(1), false);
  dv.setBigUint64(12, BigInt(2), false);
  dv.setUint32(20, 5, false);
  dv.setBigUint64(28, BigInt(1000), false);
  dv.setUint16(48, 0x0100, false);
  dv.setUint32(88, 640 << 16, false);
  dv.setUint32(92, 360 << 16, false);
  const tkhd = parseTkhd(new DataView(payload.buffer), 0, payload.length, []);
  assert.ok(tkhd);
  assert.strictEqual(tkhd?.id, 5);
  assert.strictEqual(tkhd?.duration, 1000);
  assert.strictEqual(tkhd?.volume, 1);
  assert.strictEqual(tkhd?.width, 640);
  assert.strictEqual(tkhd?.height, 360);
});

void test("parseMdhd reports truncated payloads", () => {
  const issues: string[] = [];
  const mdhd = parseMdhd(new DataView(new Uint8Array(8).buffer), 0, 8, issues);
  assert.strictEqual(mdhd, null);
  assert.ok(issues.some(msg => msg.includes("mdhd box truncated")));
});

void test("parseMdhd reads version 0 payload", () => {
  const payload = new Uint8Array(22).fill(0);
  const dv = new DataView(payload.buffer);
  dv.setUint32(4, 3, false);
  dv.setUint32(8, 4, false);
  dv.setUint32(12, 48000, false);
  dv.setUint32(16, 4800, false);
  dv.setUint16(20, 0x55c4, false);
  const mdhd = parseMdhd(new DataView(payload.buffer), 0, payload.length, []);
  assert.ok(mdhd);
  assert.strictEqual(mdhd?.durationSeconds, 0.1);
  assert.strictEqual(mdhd?.language, "und");
});

void test("parseHdlr reports truncated payloads", () => {
  const issues: string[] = [];
  const hdlr = parseHdlr(new DataView(new Uint8Array(8).buffer), 0, 8, issues);
  assert.strictEqual(hdlr, null);
  assert.ok(issues.some(msg => msg.includes("hdlr box truncated")));
});

void test("parseHdlr reads handler type and name", () => {
  const box = buildHdlrBox("subt", "Subs");
  const hdlr = parseHdlr(new DataView(box.buffer), 8, box.length - 8, []);
  assert.ok(hdlr);
  assert.strictEqual(hdlr?.handlerType, "subt");
  assert.strictEqual(hdlr?.handlerName, "Subs");
});

void test("parseStts reports truncated entry table", () => {
  const buffer = new Uint8Array(12).fill(0);
  const dv = new DataView(buffer.buffer);
  dv.setUint32(4, 2, false);
  dv.setUint32(8, 1, false);
  const issues: string[] = [];
  const stts = parseStts(new DataView(buffer.buffer), 0, buffer.length, issues);
  assert.ok(stts);
  assert.ok(issues.some(msg => msg.includes("stts entries truncated")));
});

void test("parseStts accumulates sample counts and durations", () => {
  const buffer = new Uint8Array(24).fill(0);
  const dv = new DataView(buffer.buffer);
  dv.setUint32(4, 2, false);
  dv.setUint32(8, 3, false);
  dv.setUint32(12, 100, false);
  dv.setUint32(16, 2, false);
  dv.setUint32(20, 50, false);
  const stts = parseStts(new DataView(buffer.buffer), 0, buffer.length, []);
  assert.ok(stts);
  assert.strictEqual(stts?.sampleCount, 5);
  assert.strictEqual(stts?.totalDuration, 400);
});

void test("parseStsz reports truncated header", () => {
  const issues: string[] = [];
  const stsz = parseStsz(new DataView(new Uint8Array(10).buffer), 0, 10, issues);
  assert.strictEqual(stsz, null);
  assert.ok(issues.some(msg => msg.includes("stsz box truncated")));
});

void test("parseStsz notes truncated sample size table", () => {
  const buffer = new Uint8Array(16).fill(0);
  const dv = new DataView(buffer.buffer);
  dv.setUint32(4, 0, false);
  dv.setUint32(8, 2, false);
  const issues: string[] = [];
  const stsz = parseStsz(new DataView(buffer.buffer), 0, buffer.length, issues);
  assert.ok(stsz);
  assert.ok(issues.some(msg => msg.includes("stsz sample size table truncated")));
  assert.strictEqual(stsz?.sampleSizeConstant, null);
  assert.strictEqual(stsz?.sampleCount, 2);
});

void test("parseStco reports truncated entries", () => {
  const buffer = new Uint8Array(12).fill(0);
  const dv = new DataView(buffer.buffer);
  dv.setUint32(4, 3, false);
  const issues: string[] = [];
  const stco = parseStco(new DataView(buffer.buffer), 0, buffer.length, issues);
  assert.ok(stco);
  assert.ok(issues.some(msg => msg.includes("stco entries truncated")));
});

void test("parseCo64 reports truncated entries", () => {
  const buffer = new Uint8Array(16).fill(0);
  const dv = new DataView(buffer.buffer);
  dv.setUint32(4, 2, false);
  const issues: string[] = [];
  const co64 = parseCo64(new DataView(buffer.buffer), 0, buffer.length, issues);
  assert.ok(co64);
  assert.ok(issues.some(msg => msg.includes("co64 entries truncated")));
});

void test("parseStss reports truncated keyframe entries", () => {
  const buffer = new Uint8Array(12).fill(0);
  const dv = new DataView(buffer.buffer);
  dv.setUint32(4, 2, false);
  const issues: string[] = [];
  const stss = parseStss(new DataView(buffer.buffer), 0, buffer.length, issues);
  assert.ok(stss);
  assert.ok(issues.some(msg => msg.includes("stss entries truncated")));
});
