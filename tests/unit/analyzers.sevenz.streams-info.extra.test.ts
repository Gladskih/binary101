"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseStreamsInfo } from "../../analyzers/sevenz/streams-info.js";

const makeCtx = (bytes: ArrayLike<number>) => ({
  dv: new DataView(Uint8Array.from(bytes).buffer),
  offset: 0,
  issues: [] as string[]
});

void test("parseStreamsInfo records unknown field ids", () => {
  const ctx = makeCtx([0x09]); // unknown id, not terminated
  const info = parseStreamsInfo(ctx);
  assert.deepEqual(info, {});
  assert.ok(ctx.issues[0].includes("Unknown StreamsInfo field id"));
});
