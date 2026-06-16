"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { scanDirectoryFileRows } from "../../../../ui/directory-file-scanning.js";
import type { BrowserFileHandle, DirectoryRow } from "../../../../ui/directory-handles.js";
import type { DirectoryFileCells } from "../../../../ui/directory-table-rendering.js";

class FakeElement {
  dataset: Record<string, string> = {};
  hidden = true;
  max = 0;
  textContent: string | null = "";
  title = "";
  value = 0;
}

class FakeFileHandle implements BrowserFileHandle {
  readonly kind = "file";
  constructor(readonly name: string, private readonly file: File | Error) {}
  async getFile(): Promise<File> {
    if (this.file instanceof Error) throw this.file;
    return this.file;
  }
}

const createCells = (): DirectoryFileCells => ({
  rowElement: new FakeElement() as unknown as HTMLTableRowElement,
  sizeCell: new FakeElement() as unknown as HTMLElement,
  mimeTypeCell: new FakeElement() as unknown as HTMLElement,
  modifiedCell: new FakeElement() as unknown as HTMLElement,
  typeCell: new FakeElement() as unknown as HTMLElement
});

const createFile = (name: string): File =>
  new File([new Uint8Array([0x61])], name, {
    type: "text/plain",
    lastModified: Date.UTC(2024, 0, 2, 3, 4, 5)
  });

void test("scanDirectoryFileRows fills metadata and visible read failures", async () => {
  const goodCells = createCells();
  const blockedCells = createCells();
  const rows: DirectoryRow[] = [
    { kind: "file", path: "good.txt", handle: new FakeFileHandle("good.txt", createFile("good.txt")) },
    { kind: "file", path: "blocked.bin", handle: new FakeFileHandle("blocked.bin", new Error("denied")) }
  ];
  const scanned = await scanDirectoryFileRows(
    {
      progressWrapElement: new FakeElement() as unknown as HTMLElement,
      progressElement: new FakeElement() as unknown as HTMLProgressElement,
      progressTextElement: new FakeElement() as unknown as HTMLElement,
      detectFileType: async () => "Text file",
      yieldToBrowser: async () => undefined
    },
    rows,
    new Map([["good.txt", goodCells], ["blocked.bin", blockedCells]]),
    () => true
  );

  assert.equal(scanned, 2);
  assert.equal(goodCells.sizeCell.textContent, "1 B (1 bytes)");
  assert.equal(goodCells.mimeTypeCell.textContent, "text/plain");
  assert.equal(goodCells.modifiedCell.textContent, "2024-01-02T03:04:05.000Z");
  assert.equal(goodCells.typeCell.textContent, "Text file");
  assert.equal(blockedCells.typeCell.textContent, "Unable to read: denied");
});

void test("scanDirectoryFileRows reports detector failures and cancellation", async () => {
  const cells = createCells();
  const rows: DirectoryRow[] = [
    { kind: "file", path: "unknown.bin", handle: new FakeFileHandle("unknown.bin", createFile("unknown.bin")) }
  ];
  const detected = await scanDirectoryFileRows(
    {
      progressWrapElement: new FakeElement() as unknown as HTMLElement,
      progressElement: new FakeElement() as unknown as HTMLProgressElement,
      progressTextElement: new FakeElement() as unknown as HTMLElement,
      detectFileType: async () => { throw new Error("probe failed"); },
      yieldToBrowser: async () => undefined
    },
    rows,
    new Map([["unknown.bin", cells]]),
    () => true
  );
  const cancelled = await scanDirectoryFileRows(
    {
      progressWrapElement: new FakeElement() as unknown as HTMLElement,
      progressElement: new FakeElement() as unknown as HTMLProgressElement,
      progressTextElement: new FakeElement() as unknown as HTMLElement
    },
    rows,
    new Map([["unknown.bin", createCells()]]),
    () => false
  );

  assert.equal(detected, 1);
  assert.equal(cells.typeCell.textContent, "Unable to detect: probe failed");
  assert.equal(cancelled, null);
});
