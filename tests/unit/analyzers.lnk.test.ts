"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLnk } from "../../analyzers/lnk/index.js";
import type {
  LnkEnvironmentBlock,
  LnkExtraDataBlock,
  LnkKnownFolderBlock,
  LnkPropertyStoreBlock
} from "../../analyzers/lnk/types.js";
import { createLnkFile } from "../fixtures/lnk-sample-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const isEnvironmentBlock = (block: LnkExtraDataBlock): block is LnkEnvironmentBlock =>
  block.signature === 0xa0000001;

const isKnownFolderBlock = (block: LnkExtraDataBlock): block is LnkKnownFolderBlock =>
  block.signature === 0xa000000b;

const isPropertyStoreBlock = (block: LnkExtraDataBlock): block is LnkPropertyStoreBlock =>
  block.signature === 0xa0000009;

void test("parseLnk reads Shell Link header and targets", async () => {
  const file = createLnkFile();
  const lnk = expectDefined(await parseLnk(file));
  assert.strictEqual(lnk.header.clsid, "00021401-0000-0000-c000-000000000046");
  const createdIso = lnk.header.creationTime.iso;
  assert.ok(createdIso);
  assert.ok(createdIso.startsWith("2024-01-02"));
  assert.strictEqual(lnk.stringData.relativePath, ".\\Example\\app.exe");
  assert.strictEqual(lnk.stringData.arguments, "--demo");
  assert.ok(lnk.linkInfo);
  assert.strictEqual(lnk.linkInfo.localBasePath, "C:\\Program Files\\Example");
  assert.strictEqual(lnk.linkInfo.commonPathSuffix, "app.exe");
  assert.ok(lnk.linkInfo.volume);
  assert.strictEqual(lnk.linkInfo.volume.driveTypeName, "Fixed drive");
  assert.ok(lnk.idList);
  assert.ok(Array.isArray(lnk.idList.items));
  assert.strictEqual(lnk.idList.items.length, 5);
  const firstItem = expectDefined(lnk.idList.items[0]);
  assert.strictEqual(firstItem.clsid, "20d04fe0-3aea-1069-a2d8-08002b30309d");
  const fileItem = lnk.idList.items.find(item => item.typeName === "File");
  assert.ok(fileItem);
  assert.strictEqual(fileItem.longName, "app.exe");
  assert.strictEqual(fileItem.fileSize, 12345);
  assert.strictEqual(fileItem.attributes, 0x0020);
  assert.strictEqual(lnk.idList.resolvedPath, "C:\\Program Files\\Example\\app.exe");
  assert.ok(Array.isArray(lnk.extraData.blocks));
  assert.ok(lnk.extraData.blocks.length >= 3);
});

void test("parseLnk reports extra data details", async () => {
  const lnk = expectDefined(await parseLnk(createLnkFile()));
  const envBlock = expectDefined(lnk.extraData.blocks.find(isEnvironmentBlock));
  assert.ok(envBlock.parsed);
  assert.strictEqual(envBlock.parsed.unicode, "%USERPROFILE%\\Example\\app.exe");
  const knownFolder = expectDefined(lnk.extraData.blocks.find(isKnownFolderBlock));
  assert.ok(knownFolder.parsed);
  assert.strictEqual(
    expectDefined(knownFolder.parsed).knownFolderId,
    "fdd39ad0-238f-46af-adb4-6c85480369c7"
  );
  const propertyStore = expectDefined(lnk.extraData.blocks.find(isPropertyStoreBlock));
  const parsedStore = expectDefined(propertyStore.parsed);
  const { storages } = parsedStore;
  assert.ok(storages.length);
  const firstStorage = expectDefined(storages[0]);
  const volumeProperty = firstStorage.properties.find(prop => prop.id === 104);
  const definedVolumeProperty = expectDefined(volumeProperty);
  assert.strictEqual(definedVolumeProperty.name, "System.VolumeId");
  assert.strictEqual(definedVolumeProperty.value, "8e44de00-5103-3a0b-4785-67a8d9b71bc0");
});
