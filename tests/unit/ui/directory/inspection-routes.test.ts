"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createDirectoryInspectionController } from "../../../../ui/directory-inspection.js";
import type {
  DirectoryInspectionConfig,
  DirectoryInspectionRoute
} from "../../../../ui/directory-inspection.js";

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
  replaceChildren(...nodes: FakeElement[]): void {
    this.children.splice(0, this.children.length, ...nodes);
  }
  querySelectorAll(): FakeElement[] {
    return [];
  }
}

class FakeFileHandle {
  readonly kind = "file";
  constructor(readonly name: string, private readonly file: File) {}
  async getFile(): Promise<File> {
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
  config: Partial<DirectoryInspectionConfig>
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

const installFakeBrowser = (root: FakeDirectoryHandle): { restore: () => void } => {
  const globals = globalThis as unknown as FakeBrowserGlobals;
  const originalDocument = globals.document;
  const originalWindow = globals.window;
  globals.document = { createElement: () => new FakeElement() };
  globals.window = { showDirectoryPicker: async () => root };
  return {
    restore: () => {
      globals.document = originalDocument;
      globals.window = originalWindow;
    }
  };
};

const rowTexts = (body: FakeElement): string[][] =>
  body.children.map(row => row.children.map(cell => cell.textContent ?? ""));

void test("directory inspection emits and restores browser history routes", async () => {
  const docs = new FakeDirectoryHandle("docs", [
    new FakeFileHandle("readme.txt", new File(["a"], "readme.txt", {
      lastModified: Date.UTC(2024, 0, 2, 3, 4, 5),
      type: "text/plain"
    }))
  ]);
  const root = new FakeDirectoryHandle("fixture", [docs]);
  const browser = installFakeBrowser(root);
  const elements = createElements();
  const routes: DirectoryInspectionRoute[] = [];
  try {
    const controller = createController(elements, {
      openDirectory: route => routes.push(route),
      detectFileType: async () => "Text file",
      yieldToBrowser: async () => undefined
    });
    await controller.open();
    await controller.showRoute({
      context: { source: "navigation", object: "directory", relativePath: "fixture/docs" },
      locations: [
        { handle: root, name: "fixture", relativePath: "fixture" },
        { handle: docs, name: "docs", relativePath: "fixture/docs" }
      ]
    });
    assert.equal(routes.length, 1);
    assert.equal(routes[0]?.locations[0]?.name, "fixture");
    assert.equal(elements.nameElement.textContent, "docs");
    assert.match(elements.contextElements.sourceElement.innerHTML, />Navigation<\/span>/);
    assert.match(elements.contextElements.objectElement.innerHTML, />Directory<\/span>/);
    assert.equal(elements.contextElements.relativePathElement.textContent, "fixture/docs");
    assert.deepEqual(rowTexts(elements.fileTableBodyElement), [
      ["readme.txt", "1 B (1 bytes)", "text/plain", "2024-01-02T03:04:05.000Z", "Text file"]
    ]);
  } finally {
    browser.restore();
  }
});
