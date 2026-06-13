"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createResourceDetailEntries } from "../../analyzers/pe/resources/tree-detail.js";
import type { ResourceLeafPath } from "../../analyzers/pe/resources/tree-types.js";

const leaf = (
  nameNode: ResourceLeafPath["nodes"][number],
  lang: number | null,
  size: number
): ResourceLeafPath => ({
  nodes: [{ id: 3, name: null }, nameNode, { id: lang, name: null }],
  size,
  codePage: 1252,
  dataRVA: 0x2000 + size,
  dataFileOffset: 0x40 + size,
  reserved: 0
});

void test("createResourceDetailEntries groups language leaves by numeric resource ID", () => {
  const entries = createResourceDetailEntries([
    leaf({ id: 1, name: null }, 1033, 4),
    leaf({ id: 1, name: null }, 1031, 8)
  ]);

  assert.deepStrictEqual(entries, [{
    id: 1,
    name: null,
    langs: [
      { lang: 1033, size: 4, codePage: 1252, dataRVA: 0x2004, dataFileOffset: 0x44, reserved: 0 },
      { lang: 1031, size: 8, codePage: 1252, dataRVA: 0x2008, dataFileOffset: 0x48, reserved: 0 }
    ]
  }]);
});

void test("createResourceDetailEntries keeps named and numeric resources separate", () => {
  const entries = createResourceDetailEntries([
    leaf({ id: null, name: "MAIN" }, null, 4),
    leaf({ id: 1, name: null }, null, 8),
    leaf({ id: null, name: "MAIN" }, 1033, 12),
    leaf({ id: null, name: "ALT" }, 1033, 16),
    leaf({ id: 2, name: null }, 1033, 20),
    leaf({ id: null, name: null }, 1033, 24)
  ]);

  assert.deepStrictEqual(entries.map(entry => ({
    id: entry.id,
    name: entry.name,
    sizes: entry.langs.map(lang => lang.size)
  })), [
    { id: null, name: "MAIN", sizes: [4, 12] },
    { id: 1, name: null, sizes: [8] },
    { id: null, name: "ALT", sizes: [16] },
    { id: 2, name: null, sizes: [20] },
    { id: null, name: null, sizes: [24] }
  ]);
});

void test("createResourceDetailEntries ignores non-canonical paths", () => {
  const entries = createResourceDetailEntries([{
    ...leaf({ id: 1, name: null }, 1033, 4),
    nodes: [{ id: 3, name: null }, { id: 1, name: null }]
  }]);

  assert.deepStrictEqual(entries, []);
});
