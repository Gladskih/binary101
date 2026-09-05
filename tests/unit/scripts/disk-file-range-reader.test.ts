"use strict";

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { openDiskFileRangeReader } from "../../../scripts/disk-file-range-reader.js";

const withTemporaryFile = async (bytes: Uint8Array, run: (path: string) => Promise<void>): Promise<void> => {
  const directory = await mkdtemp(join(tmpdir(), "binary101-disk-reader-"));
  const path = join(directory, "sample.bin");
  try {
    await writeFile(path, bytes);
    await run(path);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
};

void test("disk range reader bounds reads and closes its file handle", async () => {
  await withTemporaryFile(new Uint8Array([0x10, 0x20, 0x30, 0x40]), async path => {
    const diskFile = await openDiskFileRangeReader(path, 4);
    try {
      assert.deepEqual([...await diskFile.reader.readBytes(1, 8)], [0x20, 0x30, 0x40]);
      assert.equal((await diskFile.reader.read(-1, 2)).byteLength, 0);
      assert.equal((await diskFile.reader.read(4, 1)).byteLength, 0);
    } finally {
      await diskFile.close();
    }
  });
});

void test("disk range reader fills a caller-owned bounded buffer", async () => {
  await withTemporaryFile(new Uint8Array([0x10, 0x20, 0x30, 0x40]), async path => {
    const diskFile = await openDiskFileRangeReader(path, 4);
    try {
      const destination = new Uint8Array(4);
      const filled = await diskFile.reader.readInto(2, destination);
      assert.equal(filled.byteLength, 2);
      assert.deepEqual([...filled], [0x30, 0x40]);
    } finally {
      await diskFile.close();
    }
  });
});
