"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseArchiveProperties, parseHeader } from "../../analyzers/sevenz/header-sections.js";

const makeCtx = bytes => ({
  dv: new DataView(Uint8Array.from(bytes).buffer),
  offset: 0,
  issues: []
});

void test("parseArchiveProperties skips invalid size and records issue", () => {
  // property id=0x01, size=0x05 (but only 2 bytes remain)
  const ctx = makeCtx([0x01, 0x05, 0x00]);
  const props = parseArchiveProperties(ctx);
  assert.equal(props.count, 0);
  assert.ok(ctx.issues.some(msg => msg.includes("exceeds available data")));
});

void test("parseHeader stops on unknown section id", () => {
  const ctx = makeCtx([0x02, 0x00, 0x09]);
  const header = parseHeader(ctx);
  assert.deepEqual(header.archiveProperties, { count: 0 });
  assert.ok(ctx.issues.some(msg => msg.includes("Unknown header section id")));
});