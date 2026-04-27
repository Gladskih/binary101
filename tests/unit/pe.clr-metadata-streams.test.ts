"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseClrMetadataTablesFromStreams } from "../../analyzers/pe/clr/metadata-streams.js";
import type { PeClrMeta } from "../../analyzers/pe/clr/types.js";

const makeReader = (bytes: Uint8Array) => ({
  availableSize: bytes.length,
  readAt: async (relativeOffset: number, byteLength: number): Promise<DataView | null> => {
    if (relativeOffset < 0 || relativeOffset + byteLength > bytes.length) return null;
    return new DataView(bytes.buffer, bytes.byteOffset + relativeOffset, byteLength);
  }
});

const createMeta = (streams: PeClrMeta["streams"]): PeClrMeta => ({
  streams,
  version: "v4.0.30319"
});

void test("parseClrMetadataTablesFromStreams returns null when no table stream is present", async () => {
  const issues: string[] = [];
  const tables = await parseClrMetadataTablesFromStreams(
    makeReader(Uint8Array.of()),
    createMeta([{ name: "#Strings", offset: 0, size: 0 }]),
    0,
    issues
  );

  assert.strictEqual(tables, null);
  assert.deepStrictEqual(issues, []);
});

void test("parseClrMetadataTablesFromStreams reports out-of-bounds and truncated streams", async () => {
  const outOfBoundsIssues: string[] = [];
  const outOfBounds = await parseClrMetadataTablesFromStreams(
    makeReader(Uint8Array.of(0)),
    createMeta([{ name: "#~", offset: 10, size: 1 }]),
    2,
    outOfBoundsIssues
  );
  const truncatedIssues: string[] = [];
  const truncated = await parseClrMetadataTablesFromStreams(
    makeReader(Uint8Array.of(0, 1, 2)),
    createMeta([{ name: "#~", offset: 0, size: 8 }]),
    8,
    truncatedIssues
  );

  assert.strictEqual(outOfBounds, null);
  assert.ok(outOfBoundsIssues.some(issue => /outside/i.test(issue)));
  assert.strictEqual(truncated, null);
  assert.ok(truncatedIssues.some(issue => /truncated|smaller/i.test(issue)));
});
