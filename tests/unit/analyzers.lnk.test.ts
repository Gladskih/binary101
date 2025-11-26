"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLnk } from "../../analyzers/lnk/index.js";
import { createLnkFile } from "../fixtures/sample-files.js";

type LnkParseShape = {
  header: { clsid?: string; creationTime?: { iso?: string } };
  stringData: { relativePath?: string; arguments?: string };
  linkInfo: {
    localBasePath?: string;
    commonPathSuffix?: string;
    volume?: { driveTypeName?: string };
  };
  idList: {
    items: Array<{ typeName?: string; clsid?: string; longName?: string; fileSize?: number; attributes?: number }>;
    resolvedPath?: string;
  };
  extraData: { blocks: Array<{ signature: number; parsed?: Record<string, unknown> }> };
};

void test("parseLnk reads Shell Link header and targets", async () => {
  const file = createLnkFile();
  const lnk = (await parseLnk(file)) as unknown as LnkParseShape;
  assert.ok(lnk);
  assert.strictEqual(lnk.header.clsid, "00021401-0000-0000-c000-000000000046");
  assert.ok(lnk.header.creationTime.iso.startsWith("2024-01-02"));
  assert.strictEqual(lnk.stringData.relativePath, ".\\Example\\app.exe");
  assert.strictEqual(lnk.stringData.arguments, "--demo");
  assert.strictEqual(lnk.linkInfo.localBasePath, "C:\\Program Files\\Example");
  assert.strictEqual(lnk.linkInfo.commonPathSuffix, "app.exe");
  assert.strictEqual(lnk.linkInfo.volume.driveTypeName, "Fixed drive");
  assert.ok(Array.isArray(lnk.idList.items));
  assert.strictEqual(lnk.idList.items.length, 5);
  assert.strictEqual(lnk.idList.items[0].clsid, "20d04fe0-3aea-1069-a2d8-08002b30309d");
  const fileItem = lnk.idList.items.find(item => item.typeName === "File");
  assert.ok(fileItem);
  assert.strictEqual(fileItem.longName, "app.exe");
  assert.strictEqual(fileItem.fileSize, 12345);
  assert.strictEqual(fileItem.attributes, 0x0020);
  assert.strictEqual(lnk.idList.resolvedPath, "C:\\Program Files\\Example\\app.exe");
  assert.ok(Array.isArray(lnk.extraData.blocks));
  assert.ok(lnk.extraData.blocks.length >= 3);
});

interface Property {
  id: number;
  name: string;
  value: string;
}

interface Storage {
  properties: Property[];
}

void test("parseLnk reports extra data details", async () => {
  const lnk = (await parseLnk(createLnkFile())) as unknown as LnkParseShape;
  const envBlock = lnk.extraData.blocks.find(block => block.signature === 0xa0000001);
  const knownFolder = lnk.extraData.blocks.find(block => block.signature === 0xa000000b);
  const propertyStore = lnk.extraData.blocks.find(block => block.signature === 0xa0000009);
  assert.ok(envBlock?.parsed?.unicode);
  assert.strictEqual(envBlock.parsed.unicode, "%USERPROFILE%\\Example\\app.exe");
  assert.ok(knownFolder?.parsed?.knownFolderId);
  assert.strictEqual(
    knownFolder.parsed.knownFolderId,
    "fdd39ad0-238f-46af-adb4-6c85480369c7"
  );
  const storages = propertyStore?.parsed?.storages as Storage[];
  assert.ok(storages?.length);
  const firstStorage = storages[0];
  const volumeProperty = firstStorage.properties.find(prop => prop.id === 104);
  assert.ok(volumeProperty);
  assert.strictEqual(volumeProperty.name, "System.VolumeId");
  assert.strictEqual(volumeProperty.value, "8e44de00-5103-3a0b-4785-67a8d9b71bc0");
});
