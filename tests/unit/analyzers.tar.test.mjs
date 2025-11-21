"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseTar } from "../../analyzers/tar/index.js";
import { createTarFile } from "../fixtures/sample-files.mjs";
import { createTarWithBadChecksum, createTarWithShortFile } from "../fixtures/tar-fixtures.mjs";

test("parseTar detects invalid checksum", async () => {
  const tar = await parseTar(createTarWithBadChecksum());
  assert.ok(tar);
  assert.ok(tar.issues.some(issue => issue.toLowerCase().includes("two zero blocks")));
});

test("parseTar handles short payloads gracefully", async () => {
  const tar = await parseTar(createTarWithShortFile());
  assert.ok(tar);
  assert.ok(tar.issues.some(issue => issue.toLowerCase().includes("not aligned")));
});

test("parseTar parses valid minimal tar", async () => {
  const tar = await parseTar(createTarFile());
  assert.strictEqual(tar.isTar, true);
  assert.ok(Array.isArray(tar.entries));
});
