"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildResourceLeafIndex,
  chooseResourceLeafRecord
} from "../../analyzers/pe/resources/preview/leaf-index.js";
import type { ResourceDetailGroup } from "../../analyzers/pe/resources/preview/types.js";

const createDetail = (): ResourceDetailGroup[] => [
  {
    typeName: "ICON",
    entries: [
      {
        id: 1,
        name: null,
        langs: [
          { lang: 1033, size: 4, codePage: 0, dataRVA: 0x2000, dataFileOffset: 0x40, reserved: 0 },
          { lang: 1031, size: 4, codePage: 0, dataRVA: 0, dataFileOffset: 0, reserved: 0 }
        ]
      },
      {
        id: null,
        name: "named-icon",
        langs: [
          { lang: 1033, size: 4, codePage: 0, dataRVA: 0x3000, dataFileOffset: 0x80, reserved: 0 }
        ]
      }
    ]
  },
  {
    typeName: "CURSOR",
    entries: [
      {
        id: 2,
        name: null,
        langs: [
          { lang: 1033, size: 4, codePage: 0, dataRVA: 0x4000, dataFileOffset: 0xc0, reserved: 0 }
        ]
      }
    ]
  }
];

void test("buildResourceLeafIndex records only numeric leaves for the selected type", () => {
  const index = buildResourceLeafIndex(createDetail(), "ICON");

  assert.deepStrictEqual(index.get(1), [{ lang: 1033, dataFileOffset: 0x40, size: 4 }]);
  assert.equal(index.has(2), false);
});

void test("buildResourceLeafIndex returns an empty index when the type group is absent", () => {
  assert.deepStrictEqual([...buildResourceLeafIndex(createDetail(), "BITMAP")], []);
});

void test("buildResourceLeafIndex omits numeric entries without valid leaf records", () => {
  const index = buildResourceLeafIndex([
    {
      typeName: "ICON",
      entries: [{
        id: 1,
        name: null,
        langs: [
          { lang: 1033, size: 0, codePage: 0, dataRVA: 0x2000, dataFileOffset: 0x40, reserved: 0 },
          { lang: 1031, size: 4, codePage: 0, dataRVA: 0, dataFileOffset: 0x80, reserved: 0 }
        ]
      }]
    }
  ], "ICON");

  assert.equal(index.has(1), false);
});

void test("chooseResourceLeafRecord prefers exact languages and falls back to the first record", () => {
  const neutral = { lang: null, dataFileOffset: 0x10, size: 2 };
  const german = { lang: 1031, dataFileOffset: 0x20, size: 3 };
  const index = new Map([[9, [neutral, german]]]);

  assert.strictEqual(chooseResourceLeafRecord(index, 9, 1031), german);
  assert.strictEqual(chooseResourceLeafRecord(index, 9, 1033), neutral);
  assert.equal(chooseResourceLeafRecord(index, 10, 1033), null);
});
