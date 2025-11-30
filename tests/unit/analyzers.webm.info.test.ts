"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseEbmlHeader, validateDocTypeCompatibility } from "../../analyzers/webm/info.js";
import { readElementAt } from "../../analyzers/webm/ebml.js";
import { parseSegment } from "../../analyzers/webm/segment.js";
import { createWebmFile } from "../fixtures/sample-files.js";
import type { WebmParseResult } from "../../analyzers/webm/types.js";

void test("parseEbmlHeader extracts docType and versions", async () => {
  const file = createWebmFile();
  const issues: string[] = [];
  const header = await readElementAt(file, 0, issues);
  assert.ok(header);
  const result = await parseEbmlHeader(file, header!, issues);
  assert.strictEqual(result.docType, "webm");
  assert.ok(result.ebmlHeader.docTypeVersion);
  assert.ok(issues.length === 0);
});

void test("validateDocTypeCompatibility reports version mismatch", () => {
  const issues: string[] = [];
  const header = {
    docType: "webm",
    docTypeVersion: 2,
    docTypeReadVersion: 3,
    ebmlVersion: null,
    ebmlReadVersion: null,
    maxIdLength: null,
    maxSizeLength: null
  } satisfies WebmParseResult["ebmlHeader"];
  validateDocTypeCompatibility(issues, "webm", header);
  assert.ok(issues.some(msg => msg.toLowerCase().includes("doctype")));
});

void test("parseInfo extracts duration and timecode scale", async () => {
  const file = createWebmFile();
  const issues: string[] = [];
  const ebmlHeader = await readElementAt(file, 0, issues);
  assert.ok(ebmlHeader);
  assert.notStrictEqual(ebmlHeader?.size, null);
  const segOffset = ebmlHeader!.dataOffset + (ebmlHeader!.size as number);
  const segmentHeader = await readElementAt(file, segOffset, issues);
  assert.ok(segmentHeader);
  const segment = await parseSegment(file, segmentHeader, issues, "webm");
  assert.ok(segment.info);
  assert.ok(segment.info?.durationSeconds && segment.info.durationSeconds > 1);
  assert.strictEqual(segment.info?.timecodeScale, 1000000);
});
