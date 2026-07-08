"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType } from "../../../../analyzers/index.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("detectBinaryType reports ar archives before text or audio fallbacks", async () => {
  const arHeader = Buffer.from("!<arch>\n", "ascii");
  const textLikeMember = Buffer.from("example.o/       0           0     0     644     0         `\n", "ascii");
  const bytes = new Uint8Array(arHeader.length + textLikeMember.length);
  bytes.set(arHeader);
  bytes.set(textLikeMember, arHeader.length);
  const label = await detectBinaryType(new MockFile(bytes, "libexample.a", "application/x-archive"));
  assert.strictEqual(label, "Unix ar archive (static library)");
});
