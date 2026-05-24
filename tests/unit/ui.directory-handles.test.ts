"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  collectDirectoryRows,
  getDroppedDirectoryHandle,
  getDroppedFileSystemHandles
} from "../../ui/directory-handles.js";
import type {
  BrowserDirectoryHandle,
  BrowserFileHandle,
  BrowserFileSystemHandle
} from "../../ui/directory-handles.js";

class FakeFileHandle implements BrowserFileHandle {
  readonly kind = "file";
  constructor(readonly name: string) {}
  async getFile(): Promise<File> {
    return new File([], this.name);
  }
}

class FakeDirectoryHandle implements BrowserDirectoryHandle {
  readonly kind = "directory";
  constructor(readonly name: string, private readonly children: BrowserFileSystemHandle[]) {}
  async *entries(): AsyncIterableIterator<[string, BrowserFileSystemHandle]> {
    for (const child of this.children) yield [child.name, child];
  }
}

class UnsupportedHandle implements BrowserFileSystemHandle {
  constructor(readonly kind: string, readonly name: string) {}
}

class FailingDirectoryHandle extends FakeDirectoryHandle {
  constructor(name: string) {
    super(name, []);
  }
  override entries(): AsyncIterableIterator<[string, BrowserFileSystemHandle]> {
    throw new Error("blocked");
  }
}

void test("collectDirectoryRows lists nested files and warning rows in path order", async () => {
  const root = new FakeDirectoryHandle("root", [
    new UnsupportedHandle("device", "pipe"),
    new FakeDirectoryHandle("docs", [
      new FakeDirectoryHandle("deep", [new FakeFileHandle("payload.bin")]),
      new FakeFileHandle("note.txt")
    ])
  ]);

  const rows = await collectDirectoryRows(root, () => true);

  assert.deepEqual(rows?.map(row => [row.kind, row.path]), [
    ["directory", "docs"],
    ["warning", "pipe"]
  ]);
  assert.deepEqual(
    rows
      ?.filter(row => row.kind === "directory")
      .map(row => row.kind === "directory" ? row.childCounts : null),
    [{ directFileCount: 1, directFolderCount: 1, totalFileCount: 2, totalFolderCount: 1 }]
  );
  assert.equal(rows?.[1]?.kind === "warning" ? rows[1].message : "", "Unsupported entry kind: device");
});

void test("collectDirectoryRows reports unreadable folders without throwing", async () => {
  const rows = await collectDirectoryRows(new FailingDirectoryHandle("blocked"), () => true);

  assert.deepEqual(rows?.map(row => [row.kind, row.path]), [["warning", "blocked"]]);
  assert.equal(
    rows?.[0]?.kind === "warning" ? rows[0].message : "",
    "Unable to list folder: blocked"
  );
});

void test("collectDirectoryRows stops when a newer scan supersedes it", async () => {
  const root = new FakeDirectoryHandle("root", [new FakeFileHandle("ignored.bin")]);

  const rows = await collectDirectoryRows(root, () => false);

  assert.equal(rows, null);
});

void test("getDroppedDirectoryHandle uses modern dropped File System Access handles", async () => {
  const root = new FakeDirectoryHandle("root", []);
  const dropped = await getDroppedDirectoryHandle({
    length: 2,
    item: index => index === 0
      ? { kind: "file", getAsFileSystemHandle: async () => new FakeFileHandle("single.bin") }
      : { kind: "file", getAsFileSystemHandle: async () => root }
  });

  assert.equal(dropped, root);
});

void test("getDroppedFileSystemHandles returns supported file and folder handles", async () => {
  const file = new FakeFileHandle("single.bin");
  const folder = new FakeDirectoryHandle("root", []);
  const dropped = await getDroppedFileSystemHandles({
    length: 3,
    item: index => [
      { kind: "string" },
      { kind: "file", getAsFileSystemHandle: async () => file },
      { kind: "file", getAsFileSystemHandle: async () => folder }
    ][index] ?? null
  });

  assert.deepEqual(dropped, [file, folder]);
});

void test("getDroppedDirectoryHandle ignores non-file and legacy-only dropped items", async () => {
  const dropped = await getDroppedDirectoryHandle({
    length: 2,
    item: index => index === 0 ? { kind: "string" } : { kind: "file" }
  });

  assert.equal(dropped, null);
});
