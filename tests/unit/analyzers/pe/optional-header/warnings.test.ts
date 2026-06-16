"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../../../../../analyzers/pe/optional-header/magic.js";
import { collectWindowsOptionalHeaderWarnings } from "../../../../../analyzers/pe/optional-header/warnings.js";

const PE32_OPTIONAL_HEADER_MAGIC = 0x10b;
const PE32_WINDOWS_FIELDS_SIZE = 96;
const PE32_PLUS_WINDOWS_FIELDS_SIZE = 112;
const WINDOWS_FIELDS_SIZE_WARNING =
  "SizeOfOptionalHeader is too small to contain the complete PE32/PE32+ optional header before data directories.";
const PE32_DATA_DIRECTORY_START = PE32_WINDOWS_FIELDS_SIZE;

void test("collectWindowsOptionalHeaderWarnings reports undersized PE32 and PE32+ headers", () => {
  assert.ok(collectWindowsOptionalHeaderWarnings(
    PE32_WINDOWS_FIELDS_SIZE - 1,
    PE32_OPTIONAL_HEADER_MAGIC,
    0,
    PE32_DATA_DIRECTORY_START
  ).includes(WINDOWS_FIELDS_SIZE_WARNING));
  assert.ok(collectWindowsOptionalHeaderWarnings(
    PE32_PLUS_WINDOWS_FIELDS_SIZE - 1,
    PE32_PLUS_OPTIONAL_HEADER_MAGIC,
    0,
    PE32_PLUS_WINDOWS_FIELDS_SIZE
  ).includes(WINDOWS_FIELDS_SIZE_WARNING));
});

void test("collectWindowsOptionalHeaderWarnings reports directory counts that do not fit", () => {
  assert.deepStrictEqual(collectWindowsOptionalHeaderWarnings(
    PE32_WINDOWS_FIELDS_SIZE + 3 * 8,
    PE32_OPTIONAL_HEADER_MAGIC,
    4,
    PE32_DATA_DIRECTORY_START
  ), [
    "NumberOfRvaAndSizes declares 4 data directories, but only 3 fit in SizeOfOptionalHeader."
  ]);
});

void test("collectWindowsOptionalHeaderWarnings accepts complete fitting headers", () => {
  assert.deepStrictEqual(collectWindowsOptionalHeaderWarnings(
    PE32_WINDOWS_FIELDS_SIZE + 3 * 8,
    PE32_OPTIONAL_HEADER_MAGIC,
    3,
    PE32_DATA_DIRECTORY_START
  ), []);
});
