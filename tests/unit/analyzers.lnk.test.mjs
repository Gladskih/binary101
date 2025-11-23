"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLnk } from "../../analyzers/lnk/index.js";
import { createLnkFile } from "../fixtures/sample-files.mjs";

test("parseLnk reads Shell Link header and targets", async () => {
  const file = createLnkFile();
  const lnk = await parseLnk(file);
  assert.ok(lnk);
  assert.strictEqual(lnk.header.clsid, "00021401-0000-0000-c000-000000000046");
  assert.ok(lnk.header.creationTime.iso.startsWith("2024-01-02"));
  assert.strictEqual(lnk.stringData.relativePath, ".\\Example\\app.exe");
  assert.strictEqual(lnk.stringData.arguments, "--demo");
  assert.strictEqual(lnk.linkInfo.localBasePath, "C:\\Program Files\\Example");
  assert.strictEqual(lnk.linkInfo.commonPathSuffix, "app.exe");
  assert.strictEqual(lnk.linkInfo.volume.driveTypeName, "Fixed drive");
  assert.ok(Array.isArray(lnk.extraData.blocks));
  assert.ok(lnk.extraData.blocks.length >= 2);
});

test("parseLnk reports extra data details", async () => {
  const lnk = await parseLnk(createLnkFile());
  const envBlock = lnk.extraData.blocks.find(block => block.signature === 0xa0000001);
  const knownFolder = lnk.extraData.blocks.find(block => block.signature === 0xa000000b);
  assert.ok(envBlock?.parsed?.unicode);
  assert.strictEqual(envBlock.parsed.unicode, "%USERPROFILE%\\Example\\app.exe");
  assert.ok(knownFolder?.parsed?.knownFolderId);
  assert.strictEqual(
    knownFolder.parsed.knownFolderId,
    "fdd39ad0-238f-46af-adb4-6c85480369c7"
  );
});
