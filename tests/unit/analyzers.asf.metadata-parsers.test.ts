"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ASF_CODEC_LIST_GUID,
  ASF_CONTENT_DESCRIPTION_GUID,
  ASF_EXTENDED_CONTENT_DESCRIPTION_GUID,
  ASF_HEADER_EXTENSION_GUID
} from "../../analyzers/asf/constants.js";
import {
  parseCodecList,
  parseContentDescription,
  parseExtendedContent,
  parseHeaderExtension
} from "../../analyzers/asf/metadata-parsers.js";
import { parseObjectList } from "../../analyzers/asf/shared.js";
import { createSampleAsfFile } from "../fixtures/asf-fixtures.js";

void test("metadata parsers extract textual fields", async () => {
  const file = createSampleAsfFile();
  const view = new DataView(await file.arrayBuffer());
  const issues: string[] = [];
  const headerSize = view.getUint32(16, true);
  const children = parseObjectList(view, 30, headerSize, issues, "Header");
  const metaObj = children.objects.find(obj => obj.guid === ASF_CONTENT_DESCRIPTION_GUID);
  const meta = metaObj
    ? parseContentDescription(view, metaObj.offset + 24, (metaObj.size ?? 0) - 24, issues)
    : null;
  assert.ok(meta);
  assert.strictEqual(meta?.title, "Sample");
  assert.strictEqual(meta?.author, "Author");

  const extObj = children.objects.find(obj => obj.guid === ASF_EXTENDED_CONTENT_DESCRIPTION_GUID);
  const ext = extObj
    ? parseExtendedContent(view, extObj.offset + 24, (extObj.size ?? 0) - 24, issues)
    : [];
  assert.ok(ext.some(tag => tag.name === "WM/AlbumTitle"));
  assert.ok(ext.some(tag => tag.valueType.startsWith("DWORD")));

  const codecObj = children.objects.find(obj => obj.guid === ASF_CODEC_LIST_GUID);
  const codecs = codecObj
    ? parseCodecList(view, codecObj.offset + 24, (codecObj.size ?? 0) - 24, issues)
    : [];
  assert.ok(codecs.some(codec => codec.type.includes("Audio")));
  assert.ok(codecs.some(codec => codec.type.includes("Video")));
});

void test("header extension values and nested objects are readable", async () => {
  const file = createSampleAsfFile();
  const view = new DataView(await file.arrayBuffer());
  const issues: string[] = [];
  const headerSize = view.getUint32(16, true);
  const children = parseObjectList(view, 30, headerSize, issues, "Header");
  const extObj = children.objects.find(obj => obj.guid === ASF_HEADER_EXTENSION_GUID);
  assert.ok(extObj);
  const ext = parseHeaderExtension(view, (extObj?.offset ?? 0) + 24, (extObj?.size ?? 0) - 24, issues);
  assert.ok(ext);
  assert.strictEqual(ext?.reserved2, 0x0006);
  assert.strictEqual(ext?.objects.length, 0);
});

void test("metadata parsers warn on truncated payloads", () => {
  const dv = new DataView(new Uint8Array(4).buffer);
  const issues: string[] = [];
  const meta = parseContentDescription(dv, 0, 4, issues);
  assert.strictEqual(meta, null);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("truncated")));

  const ext = parseHeaderExtension(dv, 0, 4, issues);
  assert.strictEqual(ext.truncated, true);
});
