"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createDirectoryRootForFiles,
  createDirectoryRootForHandles
} from "../../../../ui/directory-virtual-roots.js";
import type {
  BrowserDirectoryHandle,
  BrowserFileHandle,
  BrowserFileSystemHandle
} from "../../../../ui/directory-handles.js";

class FakeDirectoryHandle implements BrowserDirectoryHandle {
  readonly kind = "directory";
  constructor(readonly name: string, private readonly children: BrowserFileSystemHandle[] = []) {}
  async *entries(): AsyncIterableIterator<[string, BrowserFileSystemHandle]> {
    for (const child of this.children) yield [child.name, child];
  }
}

class FakeFileHandle implements BrowserFileHandle {
  readonly kind = "file";
  constructor(readonly name: string) {}
  async getFile(): Promise<File> {
    return new File([], this.name);
  }
}

const collectEntryNames = async (root: BrowserDirectoryHandle): Promise<string[]> => {
  const names: string[] = [];
  for await (const [name] of root.entries()) names.push(name);
  return names;
};

void test("createDirectoryRootForFiles exposes files as a virtual directory", async () => {
  const root = createDirectoryRootForFiles("Selected files", [
    new File(["a"], "alpha.txt"),
    new File(["b"], "beta.txt")
  ]);

  assert.ok(root);
  assert.equal(root.name, "Selected files");
  assert.deepEqual(await collectEntryNames(root), ["alpha.txt", "beta.txt"]);
});

void test("createDirectoryRootForFiles keeps duplicate selected names addressable", async () => {
  const root = createDirectoryRootForFiles("Selected files", [
    new File(["a"], "same.txt"),
    new File(["b"], "same.txt")
  ]);

  assert.ok(root);
  assert.deepEqual(await collectEntryNames(root), ["same.txt", "same.txt (2)"]);
});

void test("createDirectoryRootForHandles keeps one directory and wraps many handles", async () => {
  const oneDirectory = new FakeDirectoryHandle("docs");
  const selectedDirectory = createDirectoryRootForHandles("Ignored", [oneDirectory]);
  const mixedRoot = createDirectoryRootForHandles("Dropped items", [
    oneDirectory,
    new FakeFileHandle("payload.bin")
  ]);

  assert.equal(selectedDirectory, oneDirectory);
  assert.ok(mixedRoot);
  assert.equal(mixedRoot.name, "Dropped items");
  assert.deepEqual(await collectEntryNames(mixedRoot), ["docs", "payload.bin"]);
});

void test("createDirectoryRootForHandles returns null for empty selections", () => {
  assert.equal(createDirectoryRootForHandles("Empty", []), null);
  assert.equal(createDirectoryRootForFiles("Empty", []), null);
});
