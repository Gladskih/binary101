"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseUnpackInfo } from "../../dist/analyzers/sevenz/unpack-info.js";

const makeCtx = bytes => ({
  dv: new DataView(Uint8Array.from(bytes).buffer),
  offset: 0,
  issues: []
});

test("parseUnpackInfo handles external flag and missing end marker", () => {
  // folderId=0x0b, folderCount=1, external=1 -> treated as external, then end marker != 0
  const ctx = makeCtx([0x0b, 0x01, 0x01, 0x99]);
  const info = parseUnpackInfo(ctx);
  assert.equal(info.external, true);
  assert.equal(info.folders.length, 0);
  assert.ok(ctx.issues.some(msg => msg.includes("did not terminate")));
});
