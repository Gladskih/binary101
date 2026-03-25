"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildResourceTree } from "../../analyzers/pe/resources-core.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  createResourceDirectoryFixture,
  IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
  IMAGE_RESOURCE_DIRECTORY_SIZE,
  resourceNameString
} from "../helpers/pe-resource-fixture.js";

void test("buildResourceTree warns when a named resource entry appears after an ID entry", async () => {
  const firstRootEntryOffset = IMAGE_RESOURCE_DIRECTORY_SIZE;
  // A one-character UTF-16 resource name needs 2 bytes for the length prefix
  // plus 2 bytes for the code unit payload.
  const nameStringOffset = 0x30;

  // 0x40 is the smallest fixture that still fits:
  // - the 16-byte root directory header,
  // - two 8-byte root entries,
  // - a 4-byte length-prefixed UTF-16 string at 0x30.
  const fixture = createResourceDirectoryFixture(0x40);
  fixture.writeDirectory(0, 1, 1);
  // Microsoft PE/COFF specification, "The .rsrc Section" -> "Resource Directory Table":
  // NumberOfNameEntries entries are followed immediately by NumberOfIdEntries entries.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
  // Microsoft PE/COFF specification, "Resource Directory Entries":
  // all Name entries precede all ID entries, and each group is sorted in ascending order.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-entries
  // Zero target is enough here because this regression exercises only root-entry ordering,
  // not child directory traversal.
  fixture.writeDirectoryEntry(
    firstRootEntryOffset,
    5, // RT_DIALOG in Win32 resource type ids.
    0
  );
  fixture.writeDirectoryEntry(
    firstRootEntryOffset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
    resourceNameString(nameStringOffset),
    0
  );
  fixture.writeUtf16Label(nameStringOffset, "A");

  const tree = await buildResourceTree(
    new MockFile(fixture.bytes, "resource-entry-order.bin"),
    [
      {
        name: "RESOURCE",
        // Any non-zero RVA works with the identity mapper below; zero would make
        // buildResourceTree treat the RESOURCE directory as absent.
        rva: 1,
        size: fixture.bytes.length
      }
    ],
    () => 0,
    () => {}
  );
  assert.ok(tree);

  assert.deepStrictEqual(tree.top, [
    { typeName: "DIALOG", kind: "id", leafCount: 0 },
    { typeName: "A", kind: "name", leafCount: 0 }
  ]);
  assert.match(
    (tree.issues || []).join(" "),
    /name entries.*id entries|named entries.*before.*id entries|sorted/i
  );
});
