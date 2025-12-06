"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { guidToString, numberOrString, parseObjectList } from "../../analyzers/asf/shared.js";
import { ASF_HEADER_GUID, OBJECT_HEADER_SIZE } from "../../analyzers/asf/constants.js";
import { createSampleAsfFile } from "../fixtures/asf-fixtures.js";

const toDataView = (bytes: number[]): DataView => new DataView(new Uint8Array(bytes).buffer);

void test("guidToString decodes ASF header GUID", () => {
  const headerBytes = [
    0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11,
    0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c
  ];
  assert.strictEqual(guidToString(toDataView(headerBytes), 0), ASF_HEADER_GUID);
});

void test("numberOrString returns readable fallback for large values", () => {
  const huge = BigInt(Number.MAX_SAFE_INTEGER) + 10n;
  assert.strictEqual(numberOrString(huge), huge.toString());
});

void test("parseObjectList reports invalid and truncated objects", async () => {
  const file = createSampleAsfFile();
  const view = new DataView(await file.arrayBuffer());
  const issues: string[] = [];
  const headerSize = view.getUint32(16, true);
  const result = parseObjectList(view, 24 + 6, headerSize, issues, "Header");
  assert.ok(result.objects.length >= 3);
  assert.strictEqual(result.truncatedCount, 0);

  const malformed = new Uint8Array(OBJECT_HEADER_SIZE);
  const mdv = new DataView(malformed.buffer);
  mdv.setUint32(16, 8, true); // invalid size
  const malformedIssues: string[] = [];
  const parsed = parseObjectList(mdv, 0, malformed.length, malformedIssues, "Test");
  assert.strictEqual(parsed.objects.length, 0);
  assert.ok(malformedIssues[0]?.includes("invalid size"));

  const shortEndIssues: string[] = [];
  mdv.setUint32(16, OBJECT_HEADER_SIZE + 4, true);
  const truncatedResult = parseObjectList(mdv, 0, OBJECT_HEADER_SIZE + 2, shortEndIssues, "Test");
  assert.strictEqual(truncatedResult.truncatedCount, 1);
});
