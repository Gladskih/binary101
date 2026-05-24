"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  clearDirectoryTables,
  renderDirectoryTables,
  setFileMetadataCells,
  setUnreadableFileCells
} from "../../ui/directory-table-rendering.js";
import type {
  BrowserDirectoryHandle,
  BrowserFileHandle,
  BrowserFileSystemHandle,
  DirectoryRow
} from "../../ui/directory-handles.js";
import type { DirectoryTableElements } from "../../ui/directory-table-rendering.js";

type FakeBrowserGlobals = { document?: unknown };

class FakeElement {
  readonly children: FakeElement[] = [];
  className = "";
  dataset: Record<string, string> = {};
  hidden = false;
  tabIndex = -1;
  textContent: string | null = "";
  title = "";
  append(...nodes: FakeElement[]): void {
    this.children.push(...nodes);
  }
  replaceChildren(...nodes: FakeElement[]): void {
    this.children.splice(0, this.children.length, ...nodes);
  }
}

class FakeFileHandle implements BrowserFileHandle {
  readonly kind = "file";
  constructor(readonly name: string) {}
  async getFile(): Promise<File> {
    return new File([], this.name);
  }
}

class FakeDirectoryHandle implements BrowserDirectoryHandle {
  readonly kind = "directory";
  constructor(readonly name: string, private readonly children: BrowserFileSystemHandle[] = []) {}
  async *entries(): AsyncIterableIterator<[string, BrowserFileSystemHandle]> {
    for (const child of this.children) yield [child.name, child];
  }
}

const createElements = () => ({
  folderSectionElement: new FakeElement(),
  fileSectionElement: new FakeElement(),
  warningSectionElement: new FakeElement(),
  folderTableBodyElement: new FakeElement(),
  fileTableBodyElement: new FakeElement(),
  warningTableBodyElement: new FakeElement()
});

const asTableElements = (elements: ReturnType<typeof createElements>): DirectoryTableElements => ({
  folderSectionElement: elements.folderSectionElement as unknown as HTMLElement,
  fileSectionElement: elements.fileSectionElement as unknown as HTMLElement,
  warningSectionElement: elements.warningSectionElement as unknown as HTMLElement,
  folderTableBodyElement: elements.folderTableBodyElement as unknown as HTMLElement,
  fileTableBodyElement: elements.fileTableBodyElement as unknown as HTMLElement,
  warningTableBodyElement: elements.warningTableBodyElement as unknown as HTMLElement
});

const installFakeDocument = (): { restore: () => void } => {
  const globals = globalThis as unknown as FakeBrowserGlobals;
  const originalDocument = globals.document;
  globals.document = { createElement: () => new FakeElement() };
  return { restore: () => { globals.document = originalDocument; } };
};

const rowTexts = (body: FakeElement): string[][] =>
  body.children.map(row => row.children.map(cell => cell.textContent ?? ""));

void test("renderDirectoryTables separates folders, files, and warnings", () => {
  const browser = installFakeDocument();
  const elements = createElements();
  const rows: DirectoryRow[] = [
    {
      kind: "directory",
      path: "docs",
      handle: new FakeDirectoryHandle("docs"),
      childCounts: { directFileCount: 1, directFolderCount: 0, totalFileCount: 1, totalFolderCount: 0 }
    },
    { kind: "file", path: "docs/readme.txt", handle: new FakeFileHandle("readme.txt") },
    { kind: "warning", path: "pipe", message: "Unsupported entry kind: device" }
  ];
  try {
    const fileCells = renderDirectoryTables(asTableElements(elements), rows);
    assert.equal(elements.folderSectionElement.hidden, false);
    assert.equal(elements.fileSectionElement.hidden, false);
    assert.equal(elements.warningSectionElement.hidden, false);
    assert.deepEqual(rowTexts(elements.folderTableBodyElement), [["docs/", "0", "1", "0", "1"]]);
    assert.deepEqual(rowTexts(elements.fileTableBodyElement), [["docs/readme.txt", "Queued", "Queued", "Queued", "Queued"]]);
    assert.deepEqual(rowTexts(elements.warningTableBodyElement), [["pipe", "Unsupported entry kind: device"]]);
    const readmeCells = fileCells.get("docs/readme.txt");
    assert.ok(readmeCells);
    setFileMetadataCells(
      readmeCells,
      new File([new Uint8Array([0x61])], "readme.txt", {
        type: "text/plain",
        lastModified: Date.UTC(2024, 0, 2, 3, 4, 5)
      })
    );
    assert.deepEqual(rowTexts(elements.fileTableBodyElement), [
      ["docs/readme.txt", "1 B (1 bytes)", "text/plain", "2024-01-02T03:04:05.000Z", "Queued"]
    ]);
  } finally {
    browser.restore();
  }
});

void test("directory table rendering reports unreadable files and clears sections", () => {
  const browser = installFakeDocument();
  const elements = createElements();
  try {
    const fileCells = renderDirectoryTables(asTableElements(elements), [
      { kind: "file", path: "locked.bin", handle: new FakeFileHandle("locked.bin") }
    ]);
    const lockedCells = fileCells.get("locked.bin");
    assert.ok(lockedCells);
    setUnreadableFileCells(lockedCells, "denied");
    assert.deepEqual(rowTexts(elements.fileTableBodyElement), [
      ["locked.bin", "Unavailable", "Unavailable", "Unavailable", "Unable to read: denied"]
    ]);
    clearDirectoryTables(asTableElements(elements));
    assert.deepEqual(rowTexts(elements.fileTableBodyElement), []);
    assert.equal(elements.fileSectionElement.hidden, true);
  } finally {
    browser.restore();
  }
});
