"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { enrichResourcePreviews } from "../../analyzers/pe/resources/preview/index.js";
import type { ResourceTree } from "../../analyzers/pe/resources/core.js";
import { createPngFile } from "../fixtures/image-sample-files.js";
import {
  buildSingleEntryGroupCursorResource,
  buildSingleEntryGroupIconResource,
  createPreviewDetailGroup,
  createPreviewFixture,
  createPreviewLangEntry,
  createPreviewTree
} from "../helpers/pe-resource-preview-fixture.js";
import { parseManifestTestXmlDocument } from "../helpers/manifest-test-parser.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();
// MESSAGE_RESOURCE_ENTRY.Flags uses 0 for ANSI and 1 for Unicode strings. Source:
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-message_resource_entry
const MESSAGE_RESOURCE_ENTRY_FLAG = { ansi: 0, unicode: 1 } as const;
const UTF16LE_CODE_PAGE = 1200;
// VS_FIXEDFILEINFO.dwSignature is fixed at 0xFEEF04BD. Source:
// https://learn.microsoft.com/en-us/windows/win32/menurc/vs-fixedfileinfo
const VERSION_INFO_FIXED_FILE_INFO_SIGNATURE = 0xfeef04bd;
// sizeof(VS_FIXEDFILEINFO) is 52 bytes. Source:
// https://learn.microsoft.com/en-us/windows/win32/menurc/vs-fixedfileinfo
const VERSION_INFO_FIXED_FILE_INFO_SIZE = 52;

type ResourceDetail = ResourceTree["detail"][number];
type ResourcePreviewResult = Awaited<ReturnType<typeof enrichResourcePreviews>>;
type PreviewResourceLang = ResourceDetail["entries"][number]["langs"][number] & {
  previewKind?: string;
  previewMime?: string;
  textPreview?: string;
  textEncoding?: string | null;
  previewFields?: Array<{ label: string; value: string }>;
  stringTable?: Array<{ id: number | null; text: string }>;
  messageTable?: { messages: Array<{ id: number; strings: string[] }>; truncated: boolean };
  previewIssues?: string[];
  versionInfo?: { fileVersionString?: string; productVersionString?: string };
};

const writeUtf16 = (bytes: Uint8Array, offset: number, text: string): void => {
  for (let index = 0; index < text.length; index += 1) {
    const codeUnit = text.charCodeAt(index);
    bytes[offset + index * 2] = codeUnit & 0xff;
    bytes[offset + index * 2 + 1] = codeUnit >>> 8;
  }
};

const buildStringTableResource = (): Uint8Array => {
  const bytes = new Uint8Array(24).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 5, true);
  writeUtf16(bytes, 2, "Hello");
  view.setUint16(12, 6, true); // Deliberately too large for the remaining payload.
  writeUtf16(bytes, 14, "Hi");
  return bytes;
};

const buildMessageTableResource = (): Uint8Array => {
  const bytes = new Uint8Array(80).fill(0);
  const view = new DataView(bytes.buffer);
  const firstEntryOffset = 32;
  const secondEntryOffset = firstEntryOffset + 6;
  view.setUint32(0, 1, true);
  view.setUint32(4, 10, true);
  view.setUint32(8, 11, true);
  view.setUint32(12, firstEntryOffset, true);
  view.setUint16(firstEntryOffset, 6, true);
  view.setUint16(firstEntryOffset + 2, MESSAGE_RESOURCE_ENTRY_FLAG.ansi, true);
  bytes[firstEntryOffset + 4] = "O".charCodeAt(0);
  bytes[firstEntryOffset + 5] = "K".charCodeAt(0);
  view.setUint16(secondEntryOffset, 8, true);
  view.setUint16(secondEntryOffset + 2, MESSAGE_RESOURCE_ENTRY_FLAG.unicode, true);
  writeUtf16(bytes, secondEntryOffset + 4, "Hi");
  return bytes;
};

const buildVersionResource = (): Uint8Array => {
  const bytes = new Uint8Array(96).fill(0);
  const view = new DataView(bytes.buffer);
  const key = "VS_VERSION_INFO";
  view.setUint16(0, bytes.length, true);
  view.setUint16(2, VERSION_INFO_FIXED_FILE_INFO_SIZE, true);
  writeUtf16(bytes, 6, key);
  const valueStart = (6 + key.length * 2 + 2 + 3) & ~3;
  view.setUint32(valueStart, VERSION_INFO_FIXED_FILE_INFO_SIGNATURE, true);
  view.setUint32(valueStart + 4, 0x00010000, true);
  view.setUint32(valueStart + 8, 0x00090000, true);
  view.setUint32(valueStart + 12, 0x521e0008, true);
  view.setUint32(valueStart + 16, 0x00090000, true);
  view.setUint32(valueStart + 20, 0x521e0008, true);
  return bytes;
};

const getPreviewLang = (result: ResourcePreviewResult, typeName: string): PreviewResourceLang => {
  const group = expectDefined(result.detail.find(entry => entry.typeName === typeName));
  const resourceEntry = expectDefined(group.entries[0]);
  return expectDefined(resourceEntry.langs[0]) as PreviewResourceLang;
};

void test("enrichResourcePreviews builds text previews for MANIFEST and HTML", async () => {
  const fixture = createPreviewFixture(256);
  const manifest = fixture.appendData(encoder.encode('<?xml version="1.0"?><assembly/>'));
  const html = fixture.appendData(encoder.encode("<html><body>hi</body></html>"));
  const tree = createPreviewTree([
    createPreviewDetailGroup("MANIFEST", 3, createPreviewLangEntry(manifest.offset, manifest.size, 65001, null)),
    createPreviewDetailGroup("HTML", 4, createPreviewLangEntry(html.offset, html.size, 65001, 1031))
  ]);

  const result = await enrichResourcePreviews(
    new MockFile(fixture.fileBytes),
    tree,
    parseManifestTestXmlDocument
  );
  assert.strictEqual(getPreviewLang(result, "MANIFEST").previewKind, "text");
  assert.match(expectDefined(getPreviewLang(result, "MANIFEST").textPreview), /assembly/);
  assert.strictEqual(getPreviewLang(result, "HTML").previewKind, "html");
  assert.match(expectDefined(getPreviewLang(result, "HTML").textPreview), /<body>hi/);
});

void test("enrichResourcePreviews builds STRING, MESSAGETABLE, and VERSION previews", async () => {
  const fixture = createPreviewFixture(1024);
  const stringTable = fixture.appendData(buildStringTableResource());
  const messageTable = fixture.appendData(buildMessageTableResource());
  const version = fixture.appendData(buildVersionResource());
  const tree = createPreviewTree([
    createPreviewDetailGroup(
      "STRING",
      1,
      createPreviewLangEntry(stringTable.offset, stringTable.size, UTF16LE_CODE_PAGE, 1031)
    ),
    createPreviewDetailGroup(
      "MESSAGETABLE",
      5,
      createPreviewLangEntry(messageTable.offset, messageTable.size, 0, 2057)
    ),
    createPreviewDetailGroup(
      "VERSION",
      6,
      createPreviewLangEntry(version.offset, version.size, UTF16LE_CODE_PAGE, 3082)
    )
  ]);

  const result = await enrichResourcePreviews(
    new MockFile(fixture.fileBytes),
    tree,
    parseManifestTestXmlDocument
  );
  const stringLang = getPreviewLang(result, "STRING");
  const messageLang = getPreviewLang(result, "MESSAGETABLE");
  const versionLang = getPreviewLang(result, "VERSION");

  assert.strictEqual(stringLang.previewKind, "stringTable");
  assert.ok(expectDefined(stringLang.stringTable).length >= 1);
  assert.ok((stringLang.previewIssues || []).length > 0);
  assert.strictEqual(messageLang.previewKind, "messageTable");
  assert.deepEqual(expectDefined(messageLang.messageTable), {
    messages: [
      { id: 10, strings: ["OK"] },
      { id: 11, strings: ["Hi"] }
    ],
    truncated: false
  });
  assert.match((messageLang.previewIssues || []).join(" "), /supported code page/i);
  assert.strictEqual(versionLang.previewKind, "version");
  assert.strictEqual(versionLang.versionInfo?.fileVersionString, "9.0.21022.8");
  assert.strictEqual(versionLang.versionInfo?.productVersionString, "9.0.21022.8");
});

void test("enrichResourcePreviews leaves GROUP_ICON entries without preview when the referenced ICON leaf is missing", async () => {
  const fixture = createPreviewFixture(256);
  const groupIcon = fixture.appendData(buildSingleEntryGroupIconResource(createPngFile().data.length, 99));
  const tree = createPreviewTree([
    createPreviewDetailGroup("GROUP_ICON", 12, createPreviewLangEntry(groupIcon.offset, groupIcon.size, 0, 1033))
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const groupLang = getPreviewLang(result, "GROUP_ICON");

  assert.notStrictEqual(groupLang.previewKind, "image");
});

void test("enrichResourcePreviews reports unmapped GROUP_ICON leaf payload RVAs", async () => {
  const fixture = createPreviewFixture(256);
  const groupIcon = fixture.appendData(buildSingleEntryGroupIconResource(createPngFile().data.length, 1));
  const tree = createPreviewTree(
    [
      createPreviewDetailGroup("ICON", 1, createPreviewLangEntry(0x2000, createPngFile().data.length, 0, 1033)),
      createPreviewDetailGroup(
        "GROUP_ICON",
        12,
        createPreviewLangEntry(groupIcon.offset, groupIcon.size, 0, 1033)
      )
    ],
    value => (value === groupIcon.offset ? groupIcon.offset : null)
  );

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const groupLang = getPreviewLang(result, "GROUP_ICON");

  assert.ok((groupLang.previewIssues || []).some(issue => /GROUP_ICON references ICON leaf ID 1/i.test(issue)));
});

void test("enrichResourcePreviews reports unmapped GROUP_CURSOR leaf payload RVAs", async () => {
  const fixture = createPreviewFixture(256);
  const groupCursor = fixture.appendData(buildSingleEntryGroupCursorResource(32, 4, 7, 9));
  const tree = createPreviewTree(
    [
      createPreviewDetailGroup("CURSOR", 4, createPreviewLangEntry(0x2400, 32, 0, 1033)),
      createPreviewDetailGroup(
        "GROUP_CURSOR",
        13,
        createPreviewLangEntry(groupCursor.offset, groupCursor.size, 0, 1033)
      )
    ],
    value => (value === groupCursor.offset ? groupCursor.offset : null)
  );

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const groupLang = getPreviewLang(result, "GROUP_CURSOR");

  assert.ok((groupLang.previewIssues || []).some(issue => /GROUP_CURSOR references CURSOR leaf ID 4/i.test(issue)));
});

void test("enrichResourcePreviews uses the resource code page to decode UTF-16LE HTML without a BOM", async () => {
  const fixture = createPreviewFixture(256);
  const htmlBytes = new Uint8Array("<html>".length * 2);
  writeUtf16(htmlBytes, 0, "<html>");
  const html = fixture.appendData(htmlBytes);
  const tree = createPreviewTree([
    createPreviewDetailGroup(
      "HTML",
      7,
      createPreviewLangEntry(html.offset, html.size, UTF16LE_CODE_PAGE, 1033)
    )
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const htmlLang = getPreviewLang(result, "HTML");

  assert.strictEqual(htmlLang.previewKind, "html");
  assert.strictEqual(htmlLang.textPreview, "<html>");
  assert.strictEqual(htmlLang.textEncoding, "UTF-16LE");
});

void test("enrichResourcePreviews warns when resource preview reads fewer bytes than the declared data size", async () => {
  const fixture = createPreviewFixture(96);
  const manifest = fixture.appendData(encoder.encode("<assembly/>"));
  const tree = createPreviewTree([
    createPreviewDetailGroup(
      "MANIFEST",
      8,
      createPreviewLangEntry(manifest.offset, manifest.size + 16, 65001, 1033)
    )
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const manifestLang = getPreviewLang(result, "MANIFEST");

  assert.strictEqual(manifestLang.previewKind, "text");
  assert.ok((manifestLang.previewIssues || []).some(issue => /truncated|short|declared/i.test(issue)));
});

void test("enrichResourcePreviews does not read VS_FIXEDFILEINFO past the declared VS_VERSIONINFO length", async () => {
  const fixture = createPreviewFixture(256);
  const versionBytes = new Uint8Array(96).fill(0);
  const view = new DataView(versionBytes.buffer);
  const key = "VS_VERSION_INFO";
  // wLength intentionally ends before a full VS_FIXEDFILEINFO, while wValueLength still advertises sizeof(VS_FIXEDFILEINFO).
  view.setUint16(0, 40, true);
  view.setUint16(2, VERSION_INFO_FIXED_FILE_INFO_SIZE, true);
  writeUtf16(versionBytes, 6, key);
  const valueStart = (6 + key.length * 2 + 2 + 3) & ~3;
  view.setUint32(valueStart, VERSION_INFO_FIXED_FILE_INFO_SIGNATURE, true);
  view.setUint32(valueStart + 4, 0x00010000, true);
  view.setUint32(valueStart + 8, 0x00090000, true);
  view.setUint32(valueStart + 12, 0x521e0008, true);
  view.setUint32(valueStart + 16, 0x00090000, true);
  view.setUint32(valueStart + 20, 0x521e0008, true);
  const version = fixture.appendData(versionBytes);
  const tree = createPreviewTree([
    createPreviewDetailGroup(
      "VERSION",
      9,
      createPreviewLangEntry(version.offset, version.size, UTF16LE_CODE_PAGE, 1033)
    )
  ]);

  const result = await enrichResourcePreviews(new MockFile(fixture.fileBytes), tree);
  const versionLang = getPreviewLang(result, "VERSION");

  assert.notStrictEqual(versionLang.previewKind, "version");
  assert.ok((versionLang.previewIssues || []).some(issue => /too small|truncated|length/i.test(issue)));
});
