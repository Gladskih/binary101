"use strict";
import assert from "node:assert/strict";
import { test } from "node:test";
import { createDirectoryInspectionController } from "../../../../ui/directory-inspection.js";
import type { DirectoryInspectionConfig } from "../../../../ui/directory-inspection.js";
type FakeBrowserGlobals = {
  document?: unknown;
  window?: unknown;
};
class FakeElement {
  readonly children: FakeElement[] = [];
  className = "";
  dataset: Record<string, string> = {};
  hidden = false;
  max = 0;
  tabIndex = -1;
  innerHTML = ""; textContent: string | null = "";
  title = "";
  value = 0;
  #listeners = new Map<string, Array<(event: Event) => void>>();
  addEventListener(name: string, listener: (event: Event) => void): void {
    this.#listeners.set(name, [...(this.#listeners.get(name) ?? []), listener]);
  }
  append(...nodes: FakeElement[]): void {
    this.children.push(...nodes);
  }
  click(): void {
    (this.#listeners.get("click") ?? []).forEach(listener => listener({ target: this } as unknown as Event));
  }
  replaceChildren(...nodes: FakeElement[]): void {
    this.children.splice(0, this.children.length, ...nodes);
  }
  querySelectorAll(): FakeElement[] {
    return [];
  }
}
class FakeFileHandle {
  readonly kind = "file";
  constructor(readonly name: string, private readonly file: File | Error) {}
  async getFile(): Promise<File> {
    if (this.file instanceof Error) throw this.file;
    return this.file;
  }
}
class FakeDirectoryHandle {
  readonly kind = "directory";
  constructor(readonly name: string, private readonly children: Array<FakeDirectoryHandle | FakeFileHandle>) {}
  async *entries(): AsyncIterableIterator<[string, FakeDirectoryHandle | FakeFileHandle]> {
    for (const child of this.children) yield [child.name, child];
  }
}
class FailingDirectoryHandle extends FakeDirectoryHandle {
  constructor(name: string) {
    super(name, []);
  }
  override entries(): AsyncIterableIterator<[string, FakeDirectoryHandle | FakeFileHandle]> {
    throw new Error("blocked");
  }
}
interface FakeDropItem {
  kind: string;
  getAsFileSystemHandle?: () => Promise<FakeDirectoryHandle | FakeFileHandle | null>;
}
const createElements = () => ({
  openButtonElement: new FakeElement(),
  cardElement: new FakeElement(),
  nameElement: new FakeElement(),
  contextElements: {
    objectElement: new FakeElement(),
    relativePathElement: new FakeElement(),
    relativePathTermElement: new FakeElement(),
    sourceElement: new FakeElement()
  },
  summaryElement: new FakeElement(),
  progressWrapElement: new FakeElement(),
  progressElement: new FakeElement(),
  progressTextElement: new FakeElement(),
  folderSectionElement: new FakeElement(),
  fileSectionElement: new FakeElement(),
  warningSectionElement: new FakeElement(),
  folderTableBodyElement: new FakeElement(),
  fileTableBodyElement: new FakeElement(),
  warningTableBodyElement: new FakeElement()
});
const createController = (
  elements: ReturnType<typeof createElements>,
  config: Partial<DirectoryInspectionConfig> = {}
) => createDirectoryInspectionController({
  openButtonElement: elements.openButtonElement as unknown as HTMLButtonElement,
  cardElement: elements.cardElement as unknown as HTMLElement,
  nameElement: elements.nameElement as unknown as HTMLElement,
  contextElements: {
    objectElement: elements.contextElements.objectElement as unknown as HTMLElement,
    relativePathElement: elements.contextElements.relativePathElement as unknown as HTMLElement,
    relativePathTermElement: elements.contextElements.relativePathTermElement as unknown as HTMLElement,
    sourceElement: elements.contextElements.sourceElement as unknown as HTMLElement
  },
  summaryElement: elements.summaryElement as unknown as HTMLElement,
  progressWrapElement: elements.progressWrapElement as unknown as HTMLElement,
  progressElement: elements.progressElement as unknown as HTMLProgressElement,
  progressTextElement: elements.progressTextElement as unknown as HTMLElement,
  folderSectionElement: elements.folderSectionElement as unknown as HTMLElement,
  fileSectionElement: elements.fileSectionElement as unknown as HTMLElement,
  warningSectionElement: elements.warningSectionElement as unknown as HTMLElement,
  folderTableBodyElement: elements.folderTableBodyElement as unknown as HTMLElement,
  fileTableBodyElement: elements.fileTableBodyElement as unknown as HTMLElement,
  warningTableBodyElement: elements.warningTableBodyElement as unknown as HTMLElement,
  resetFileInspection: () => undefined,
  setStatusMessage: () => undefined,
  openFile: async () => undefined,
  openDirectory: () => undefined,
  ...config
});
const installFakeBrowser = (
  root: FakeDirectoryHandle | null
): { restore: () => void } => {
  const globals = globalThis as unknown as FakeBrowserGlobals;
  const originalDocument = globals.document;
  const originalWindow = globals.window;
  globals.document = { createElement: () => new FakeElement() };
  globals.window = root ? { showDirectoryPicker: async () => root } : {};
  return {
    restore: () => {
      globals.document = originalDocument;
      globals.window = originalWindow;
    }
  };
};
const rowTexts = (body: FakeElement): string[][] =>
  body.children.map(row => row.children.map(cell => cell.textContent ?? ""));
const createDropItems = (...items: FakeDropItem[]) => ({
  length: items.length,
  item: (index: number): FakeDropItem | null => items[index] ?? null
});
const STABLE_FILE_MODIFIED_MS = Date.UTC(2024, 0, 2, 3, 4, 5);
const STABLE_FILE_MODIFIED_ISO = "2024-01-02T03:04:05.000Z";
const createFile = (name: string, bytes: number[], type: string): File =>
  new File([new Uint8Array(bytes)], name, { type, lastModified: STABLE_FILE_MODIFIED_MS });
const folderRow = (
  path: string,
  directFolders = "0",
  directFiles = "1",
  totalFolders = "0",
  totalFiles = "1"
): string[] => [path, directFolders, directFiles, totalFolders, totalFiles];
const fileRow = (path: string, mimeType: string, detectedType: string): string[] => [
  path,
  "1 B (1 bytes)",
  mimeType,
  STABLE_FILE_MODIFIED_ISO,
  detectedType
];

void test("directory inspection lists nested entries and shallow-scans file rows", async () => {
  const root = new FakeDirectoryHandle("fixture", [
    new FakeDirectoryHandle("docs", [
      new FakeFileHandle("readme.txt", createFile("readme.txt", [0x61], "text/plain"))
    ]),
    new FakeFileHandle("image.png", createFile("image.png", [0x89], "image/png"))
  ]);
  const browser = installFakeBrowser(root);
  const elements = createElements();
  const messages: Array<string | null | undefined> = [];
  let resetCount = 0;
  let clockMs = 0;
  try {
    const controller = createController(elements, {
      resetFileInspection: () => { resetCount += 1; },
      setStatusMessage: message => messages.push(message),
      detectFileType: async file => {
        clockMs += 600;
        return file.name.endsWith(".png") ? "PNG image" : "Text file";
      },
      now: () => clockMs,
      yieldToBrowser: async () => undefined
    });

    await controller.open();

    assert.equal(resetCount, 1);
    assert.equal(elements.cardElement.hidden, false);
    assert.match(elements.contextElements.sourceElement.innerHTML, />Selection<\/span>/);
    assert.match(elements.contextElements.objectElement.innerHTML, />Directory<\/span>/);
    assert.deepEqual(rowTexts(elements.folderTableBodyElement), [
      folderRow("docs/"),
    ]);
    assert.deepEqual(rowTexts(elements.fileTableBodyElement), [
      fileRow("image.png", "image/png", "PNG image")
    ]);
    assert.deepEqual(rowTexts(elements.warningTableBodyElement), []);
    assert.equal(elements.progressWrapElement.hidden, true);
    assert.equal(elements.progressElement.max, 1);
    assert.equal(elements.progressElement.value, 1);
    assert.equal(elements.progressTextElement.textContent, "Scanned 1 / 1 files");
    assert.equal(messages.at(-1), "Folder scan complete: 1 file.");
  } finally {
    browser.restore();
  }
});

void test("directory inspection reports unsupported browsers and per-file read failures", async () => {
  new FakeElement().click();
  const unsupportedBrowser = installFakeBrowser(null);
  const unsupportedElements = createElements();
  const unsupportedMessages: Array<string | null | undefined> = [];
  try {
    const controller = createController(unsupportedElements, {
      setStatusMessage: message => unsupportedMessages.push(message)
    });
    await controller.open();
    assert.equal(unsupportedMessages.at(-1), "Folder picker is not supported by this browser.");
  } finally {
    unsupportedBrowser.restore();
  }

  const failingRoot = new FakeDirectoryHandle("fixture", [
    new FakeFileHandle("locked.bin", new Error("denied"))
  ]);
  const failingBrowser = installFakeBrowser(failingRoot);
  const failingElements = createElements();
  try {
    const controller = createController(failingElements, {
      yieldToBrowser: async () => undefined
    });
    await controller.open();
    assert.deepEqual(rowTexts(failingElements.fileTableBodyElement), [
      ["locked.bin", "Unavailable", "Unavailable", "Unavailable", "Unable to read: denied"]
    ]);
  } finally {
    failingBrowser.restore();
  }

  const warningBrowser = installFakeBrowser(new FailingDirectoryHandle("blocked"));
  const warningElements = createElements();
  try {
    const controller = createController(warningElements, {
      yieldToBrowser: async () => undefined
    });
    await controller.open();
    assert.deepEqual(rowTexts(warningElements.warningTableBodyElement), [
      ["blocked", "Unable to list folder: blocked"]
    ]);
    assert.equal(warningElements.summaryElement.textContent, "0 files, 0 folders, 0/0 files scanned, 1 warning");
  } finally {
    warningBrowser.restore();
  }
});

void test("directory inspection opens dropped folder handles without the native picker", async () => {
  const root = new FakeDirectoryHandle("drop-root", [
    new FakeDirectoryHandle("bin", [
      new FakeFileHandle("payload.dat", createFile("payload.dat", [0x42], "application/octet-stream"))
    ])
  ]);
  const browser = installFakeBrowser(null);
  const elements = createElements();
  let resetCount = 0;
  try {
    const controller = createController(elements, {
      resetFileInspection: () => { resetCount += 1; },
      detectFileType: async () => "Unknown binary type",
      yieldToBrowser: async () => undefined
    });
    const opened = await controller.openDroppedItems(createDropItems({
      kind: "file",
      getAsFileSystemHandle: async () => root
    }));
    assert.equal(opened, true);
    assert.equal(resetCount, 1);
    assert.equal(elements.nameElement.textContent, "drop-root");
    assert.match(elements.contextElements.sourceElement.innerHTML, />Drop<\/span>/);
    assert.match(elements.contextElements.objectElement.innerHTML, />Directory<\/span>/);
    assert.deepEqual(rowTexts(elements.folderTableBodyElement), [
      folderRow("bin/"),
    ]);
    assert.deepEqual(rowTexts(elements.fileTableBodyElement), []);
  } finally {
    browser.restore();
  }
});

void test("directory inspection leaves regular file drops to the file picker path", async () => {
  const browser = installFakeBrowser(null);
  const elements = createElements();
  let resetCount = 0;
  try {
    const controller = createController(elements, { resetFileInspection: () => { resetCount += 1; } });
    const opened = await controller.openDroppedItems(createDropItems({
      kind: "file",
      getAsFileSystemHandle: async () => { throw new Error("file-handle probe rejected"); }
    }));
    assert.equal(opened, false);
    assert.equal(resetCount, 0);
    assert.deepEqual(rowTexts(elements.folderTableBodyElement), []);
    assert.deepEqual(rowTexts(elements.fileTableBodyElement), []);
    assert.deepEqual(rowTexts(elements.warningTableBodyElement), []);
  } finally {
    browser.restore();
  }
});
