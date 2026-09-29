import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { createItaniumRecords } from "../../../../analyzers/itanium-rtti/records.js";
import type { ItaniumRttiImage } from "../../../../analyzers/itanium-rtti/types.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("batches sparse names physically and never repeats the preparation pass", async () => {
  // 32 distant name windows exceed the shared reader's cache; candidate order zigzags.
  const bytes = new Uint8Array(34 * 65536);
  const pointers = new Map<number, number>();
  const names = new TextEncoder().encode("4Base\0");
  for (let index = 0; index < 512; index++) {
    const table = 32 + index * 32;
    const type = 65536 + index * 16;
    const name = (2 + index % 32) * 65536 + Math.floor(index / 32) * 16;
    pointers.set(table - 8, type);
    pointers.set(table, bytes.length);
    pointers.set(table + 8, bytes.length);
    pointers.set(type + 8, name);
    bytes.set(names, name);
  }
  const file = new MockFile(bytes);
  const slice = file.slice.bind(file);
  let physicalReads = 0;
  file.slice = (start, end, type) => { physicalReads++; return slice(start, end, type); };
  const reader = createFileRangeReader(file, 0, file.size);
  const image: ItaniumRttiImage = { pointers, pointerSize: 8, relocations: new Set(pointers.keys()),
    readOrder: address => address, read: reader.read, isExecutable: address => address === bytes.length };
  const records = createItaniumRecords(image);
  assert.equal((await records.prepare()).length, 512);
  assert.ok(physicalReads <= 36, `Expected one read per physical window, got ${physicalReads}`);
  const before = physicalReads;
  await records.prepare();
  assert.equal(physicalReads, before);
});
