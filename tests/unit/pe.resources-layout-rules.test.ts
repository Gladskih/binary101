"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  validateResourceLayout,
  type ResourceDataEntryLayout,
  type ResourceLayoutRange
} from "../../analyzers/pe/resources/layout-rules.js";

const RESOURCE_RVA = 0x1000;
const RESOURCE_SIZE = 0x80;
const RESOURCE_BASE = 0;
const RESOURCE_LIMIT_END = RESOURCE_BASE + RESOURCE_SIZE;

const collectIssues = (
  maxDirectoryEnd: number,
  resourceStringRanges: ResourceLayoutRange[],
  resourceDataEntries: ResourceDataEntryLayout[],
  resourceSubdirectoryTargets: number[],
  fileSize = RESOURCE_LIMIT_END
): string[] =>
  validateResourceLayout(
    maxDirectoryEnd,
    resourceStringRanges,
    resourceDataEntries,
    resourceSubdirectoryTargets,
    RESOURCE_RVA,
    RESOURCE_SIZE,
    RESOURCE_BASE,
    fileSize
  );

void test("validateResourceLayout reports directory, string, and subdirectory ordering issues", () => {
  const issues = collectIssues(
    0x30,
    [{ start: 0x20, end: 0x24 }],
    [],
    [0x40, 0x40]
  );

  assert.match(issues.join(" "), /string area begins/i);
  assert.match(issues.join(" "), /outside the Resource Directory area/i);
  assert.match(issues.join(" "), /multiple parents/i);
});

void test("validateResourceLayout chooses the earliest string range and preserves boundary equality", () => {
  const issues = collectIssues(
    0x30,
    [{ start: 0x30, end: 0x34 }, { start: 0x18, end: 0x1c }],
    [],
    [0x18]
  );

  assert.deepStrictEqual(issues, [
    "Resource string area begins at 0x18, before the last resource directory entry ends at 0x30.",
    "Resource subdirectory at 0x18 points outside the Resource Directory area "
      + "and into the later string or data-entry region."
  ]);
});

void test("validateResourceLayout uses parsed payload file offsets for mapping checks", () => {
  const issues = collectIssues(
    0x20,
    [],
    [
      { start: 0x10, end: 0x20, dataRva: 0x2000, dataFileOffset: null, size: 4 },
      { start: 0x30, end: 0x40, dataRva: RESOURCE_RVA + 0x30, dataFileOffset: 0x90, size: 4 },
      { start: 0x50, end: 0x60, dataRva: RESOURCE_RVA + 0x50, dataFileOffset: null, size: 0 }
    ],
    [],
    0x100
  );

  assert.match(issues.join(" "), /data entry area begins/i);
  assert.match(issues.join(" "), /outside the declared \.rsrc RVA span/i);
  assert.match(issues.join(" "), /could not be mapped/i);
  assert.match(issues.join(" "), /maps outside the \.rsrc file span/i);
});

void test("validateResourceLayout reports exact data-entry area ordering diagnostics", () => {
  const issues = collectIssues(
    0x20,
    [],
    [{ start: 0x10, end: 0x20, dataRva: RESOURCE_RVA + 0x10, dataFileOffset: 0x10, size: 4 }],
    []
  );

  assert.deepStrictEqual(issues, [
    "Resource data entry area begins at 0x10, before the resource directory area ends at 0x20."
  ]);
});

void test("validateResourceLayout reports truncated and overlapping resource payloads", () => {
  const issues = collectIssues(
    0x10,
    [],
    [
      { start: 0x20, end: 0x30, dataRva: RESOURCE_RVA + 0x10, dataFileOffset: 0x70, size: 0x20 },
      { start: 0x30, end: 0x40, dataRva: RESOURCE_RVA + 0x30, dataFileOffset: 0x30, size: 4 },
      { start: 0x40, end: 0x50, dataRva: RESOURCE_RVA + 0x32, dataFileOffset: 0x40, size: 4 }
    ],
    []
  );

  assert.match(issues.join(" "), /truncated by end of file/i);
  assert.match(issues.join(" "), /payload ranges overlap/i);
});

void test("validateResourceLayout reports each payload span issue independently", () => {
  assert.deepStrictEqual(collectIssues(0x10, [], [{
    start: 0x20,
    end: 0x30,
    dataRva: RESOURCE_RVA - 1,
    dataFileOffset: 0x20,
    size: 1
  }], []), [
    "Resource data payload at RVA 0xfff lies outside the declared .rsrc RVA span."
  ]);
  assert.deepStrictEqual(collectIssues(0x10, [], [{
    start: 0x20,
    end: 0x30,
    dataRva: RESOURCE_RVA + 1,
    dataFileOffset: -1,
    size: 1
  }], []), [
    "Resource data payload at RVA 0x1001 is truncated by end of file."
  ]);
  assert.deepStrictEqual(collectIssues(0x10, [], [{
    start: 0x20,
    end: 0x30,
    dataRva: RESOURCE_RVA + 1,
    dataFileOffset: RESOURCE_LIMIT_END,
    size: 1
  }], [], RESOURCE_LIMIT_END + 1), [
    "Resource data payload at RVA 0x1001 maps outside the .rsrc file span."
  ]);
});

void test("validateResourceLayout reports exact interleaved string and data-entry layout", () => {
  const issues = collectIssues(
    0x10,
    [{ start: 0x20, end: 0x50 }, { start: 0x60, end: 0x70 }],
    [{ start: 0x40, end: 0x50, dataRva: RESOURCE_RVA + 0x40, dataFileOffset: 0x40, size: 4 }],
    []
  );

  assert.deepStrictEqual(issues, [
    "Resource string area and Resource Data entry area are interleaved: first resource data "
      + "entry at 0x40, first late resource string at 0x20, and the string area ends at 0x70."
  ]);
});

void test("validateResourceLayout treats string ranges ending at data-entry start as non-interleaved", () => {
  const issues = collectIssues(
    0x10,
    [{ start: 0x20, end: 0x40 }],
    [{ start: 0x40, end: 0x50, dataRva: RESOURCE_RVA + 0x40, dataFileOffset: 0x40, size: 4 }],
    []
  );

  assert.deepStrictEqual(issues, []);
});

void test("validateResourceLayout uses the first data-entry start for interleaving checks", () => {
  const issues = collectIssues(
    0x10,
    [{ start: 0x20, end: 0x50 }],
    [
      { start: 0x80, end: 0x90, dataRva: RESOURCE_RVA + 0x70, dataFileOffset: 0x70, size: 4 },
      { start: 0x40, end: 0x50, dataRva: RESOURCE_RVA + 0x40, dataFileOffset: 0x40, size: 4 }
    ],
    []
  );

  assert.deepStrictEqual(issues, [
    "Resource string area and Resource Data entry area are interleaved: first resource data "
      + "entry at 0x40, first late resource string at 0x20, and the string area ends at 0x50."
  ]);
});

void test("validateResourceLayout accepts payloads exactly on file and resource boundaries", () => {
  const issues = collectIssues(
    0x10,
    [],
    [
      {
        start: 0x20,
        end: 0x30,
        dataRva: RESOURCE_RVA,
        dataFileOffset: RESOURCE_BASE,
        size: RESOURCE_SIZE
      }
    ],
    []
  );

  assert.deepStrictEqual(issues, []);
});

void test("validateResourceLayout reports payload file offsets before the resource file span", () => {
  const issues = validateResourceLayout(
    0x10,
    [],
    [{ start: 0x20, end: 0x30, dataRva: RESOURCE_RVA + 1, dataFileOffset: 0x20, size: 1 }],
    [],
    RESOURCE_RVA,
    RESOURCE_SIZE,
    0x40,
    0x200
  );

  assert.deepStrictEqual(issues, [
    "Resource data payload at RVA 0x1001 maps outside the .rsrc file span."
  ]);
});

void test("validateResourceLayout ignores zero-sized payloads for span and overlap checks", () => {
  const issues = collectIssues(
    0x10,
    [],
    [
      { start: 0x20, end: 0x30, dataRva: 0, dataFileOffset: null, size: 0 },
      { start: 0x30, end: 0x40, dataRva: RESOURCE_RVA + 1, dataFileOffset: 1, size: 2 }
    ],
    []
  );

  assert.deepStrictEqual(issues, []);
});

void test("validateResourceLayout sorts payload ranges before checking overlap", () => {
  const issues = collectIssues(
    0x10,
    [],
    [
      { start: 0x40, end: 0x50, dataRva: RESOURCE_RVA + 0x30, dataFileOffset: 0x30, size: 0x10 },
      { start: 0x20, end: 0x30, dataRva: RESOURCE_RVA + 0x10, dataFileOffset: 0x10, size: 0x10 },
      { start: 0x30, end: 0x40, dataRva: RESOURCE_RVA + 0x20, dataFileOffset: 0x20, size: 0x10 }
    ],
    []
  );

  assert.deepStrictEqual(issues, []);
});

void test("validateResourceLayout ignores zero-sized payloads inside non-empty payload ranges", () => {
  const issues = collectIssues(
    0x10,
    [],
    [
      { start: 0x20, end: 0x30, dataRva: RESOURCE_RVA + 0x20, dataFileOffset: 0x20, size: 0x10 },
      { start: 0x30, end: 0x40, dataRva: RESOURCE_RVA + 0x24, dataFileOffset: 0x24, size: 0 }
    ],
    []
  );

  assert.deepStrictEqual(issues, []);
});
