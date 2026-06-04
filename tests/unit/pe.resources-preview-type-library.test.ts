"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMuiResourceConfiguration } from "../../analyzers/pe/resources/mui-config.js";
import { addTypeLibraryPreview } from "../../analyzers/pe/resources/preview/type-library.js";
import type { MuiResourceConfiguration } from "../../analyzers/pe/resources/mui-config.js";
import {
  buildMuiResourceConfigurationFixture
} from "../fixtures/pe-mui-resource-config-fixture.js";

const encoder = new TextEncoder();
// MSFT and SLTG type library signatures are four ASCII bytes. Source:
// https://doxygen.reactos.org/d1/daf/typelib__struct_8h_source.html
const TYPELIB_SIGNATURE_SIZE = 4;
// ReactOS/Wine MSFT_Header is 0x54 bytes and MSFT_SegDir has 15 0x10-byte entries.
// Source: https://doxygen.reactos.org/d1/daf/typelib__struct_8h_source.html
const MSFT_HEADER_SIZE = 0x54;
const MSFT_SEGMENT_SIZE = 0x10;
const MSFT_SEGMENT_COUNT = 15;
const MSFT_SEGMENT_DIRECTORY_SIZE = MSFT_SEGMENT_SIZE * MSFT_SEGMENT_COUNT;
const FIXTURE_TYPE_INFO_NAMES = ["fixture-library", "fixture-interface"];
const FIXTURE_TYPELIB_NAMES = ["Library", "Interface", "Method"];
const FIXTURE_IMPORT_NAMES = ["stdole"];
const MSFT_FIXTURE_SEGMENT_PAYLOAD_SIZE = MSFT_SEGMENT_SIZE * FIXTURE_TYPE_INFO_NAMES.length;
// Offsets match ReactOS/Wine tagMSFT_Header and MSFT_pSeg fields. Source:
// https://doxygen.reactos.org/d1/daf/typelib__struct_8h_source.html
const MSFT_OFFSET = {
  signature: 0,
  version: 4,
  libraryGuidOffset: 8,
  localeId: 12,
  localeId2: 16,
  typeInfoCount: 32,
  nameTableEntries: 48,
  nameTableChars: 52,
  nameOffset: 56,
  importInfoCount: 80,
  segmentLength: 4
} as const;
// ReactOS/Wine initialize unused MSFT_pSeg slots with offset -1 and length 0.
// https://doxygen.reactos.org/d4/df2/write__msft_8c_source.html
const MSFT_ABSENT_SEGMENT_OFFSET = -1;
// Microsoft documents 0x409 / 1033 as English (United States) LangID.
// Source: https://learn.microsoft.com/en-us/windows/win32/intl/resource-utilities
const WINDOWS_EN_US_LANG_ID = 0x0409;

const createMuiResourceConfigurationFixture = (): MuiResourceConfiguration => {
  const config = parseMuiResourceConfiguration(buildMuiResourceConfigurationFixture());
  assert.ok(config);
  return config;
};

const writeAscii = (data: Uint8Array, offset: number, value: string): void => {
  data.set(encoder.encode(value), offset);
};

const readHeaderFieldValue = (
  result: ReturnType<typeof addTypeLibraryPreview>,
  label: string
): string | undefined =>
  result?.preview?.typeLibrary?.headerFields.find(field => field.label === label)?.value;

const buildMsftTypeLibrary = (): Uint8Array => {
  const data = new Uint8Array(
    MSFT_HEADER_SIZE + MSFT_SEGMENT_DIRECTORY_SIZE + MSFT_FIXTURE_SEGMENT_PAYLOAD_SIZE
  );
  const view = new DataView(data.buffer);
  writeAscii(data, MSFT_OFFSET.signature, "MSFT");
  view.setUint32(MSFT_OFFSET.version, TYPELIB_SIGNATURE_SIZE, true);
  view.setInt32(MSFT_OFFSET.libraryGuidOffset, MSFT_ABSENT_SEGMENT_OFFSET, true);
  view.setUint32(MSFT_OFFSET.localeId, WINDOWS_EN_US_LANG_ID, true);
  view.setUint32(MSFT_OFFSET.localeId2, WINDOWS_EN_US_LANG_ID, true);
  view.setUint32(MSFT_OFFSET.typeInfoCount, FIXTURE_TYPE_INFO_NAMES.length, true);
  view.setUint32(MSFT_OFFSET.nameTableEntries, FIXTURE_TYPELIB_NAMES.length, true);
  view.setUint32(MSFT_OFFSET.nameTableChars, FIXTURE_TYPELIB_NAMES.join("").length, true);
  view.setInt32(MSFT_OFFSET.nameOffset, MSFT_HEADER_SIZE + MSFT_SEGMENT_DIRECTORY_SIZE, true);
  view.setUint32(MSFT_OFFSET.importInfoCount, FIXTURE_IMPORT_NAMES.length, true);
  view.setInt32(MSFT_HEADER_SIZE, MSFT_HEADER_SIZE + MSFT_SEGMENT_DIRECTORY_SIZE, true);
  view.setInt32(
    MSFT_HEADER_SIZE + MSFT_OFFSET.segmentLength,
    MSFT_FIXTURE_SEGMENT_PAYLOAD_SIZE,
    true
  );
  for (let index = 1; index < MSFT_SEGMENT_COUNT; index += 1) {
    const offset = MSFT_HEADER_SIZE + index * MSFT_SEGMENT_SIZE;
    view.setInt32(offset, MSFT_ABSENT_SEGMENT_OFFSET, true);
  }
  return data;
};

void test(
  "addTypeLibraryPreview parses MSFT type library headers and segment directory bounds",
  () => {
    const result = addTypeLibraryPreview(buildMsftTypeLibrary(), "TYPELIB", null);

    assert.equal(result?.preview?.previewKind, "typeLibrary");
    assert.equal(result?.preview?.typeLibrary?.format, "MSFT");
    assert.equal(result?.preview?.typeLibrary?.segments.length, MSFT_SEGMENT_COUNT);
    // The fixture writes the four-byte signature size into the version field.
    assert.equal(readHeaderFieldValue(result, "Format version"), "0x00000004");
    assert.equal(readHeaderFieldValue(result, "Library GUID offset"), "-1");
    // The fixture LCID is the documented English (United States) LangID.
    assert.equal(readHeaderFieldValue(result, "LCID"), "0x00000409");
    assert.equal(result?.issues, undefined);
  }
);

void test("addTypeLibraryPreview reports truncated MSFT headers", () => {
  const data = new Uint8Array(TYPELIB_SIGNATURE_SIZE);
  writeAscii(data, MSFT_OFFSET.signature, "MSFT");

  const result = addTypeLibraryPreview(data, "TYPELIB", null);

  assert.equal(result?.preview, undefined);
  assert.ok(result?.issues?.some(issue => /header is truncated/i.test(issue)));
});

void test("addTypeLibraryPreview reports MSFT segments outside the resource payload", () => {
  const data = buildMsftTypeLibrary();
  new DataView(data.buffer).setInt32(
    MSFT_HEADER_SIZE + MSFT_OFFSET.segmentLength,
    data.length,
    true
  );

  const result = addTypeLibraryPreview(data, "TYPELIB", null);

  assert.equal(result?.preview?.typeLibrary?.format, "MSFT");
  assert.ok(result?.issues?.some(issue => /TypeInfoTab points outside/i.test(issue)));
});

void test("addTypeLibraryPreview recognizes SLTG and MUI placeholder resources", () => {
  const sltg = new Uint8Array(TYPELIB_SIGNATURE_SIZE);
  writeAscii(sltg, MSFT_OFFSET.signature, "SLTG");

  const placeholder = encoder.encode("placeholder\0\0");
  const sltgResult = addTypeLibraryPreview(sltg, "TYPELIB", null);
  const placeholderResult = addTypeLibraryPreview(
    placeholder,
    "TYPELIB",
    createMuiResourceConfigurationFixture()
  );

  assert.equal(sltgResult?.preview?.typeLibrary?.format, "SLTG");
  assert.equal(placeholderResult?.preview?.typeLibrary?.format, "placeholder");
});

void test(
  "addTypeLibraryPreview leaves unknown signatures as typed summaries without warnings",
  () => {
    const result = addTypeLibraryPreview(encoder.encode("????"), "TYPELIB", null);

    assert.equal(result?.preview?.typeLibrary?.format, "unknown");
    assert.equal(result?.issues, undefined);
  }
);
