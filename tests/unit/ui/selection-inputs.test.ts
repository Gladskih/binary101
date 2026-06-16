"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { attachSelectionInputs } from "../../../ui/selection-inputs.js";
import type { DirectoryInspectionController } from "../../../ui/directory-inspection.js";

type FakeBrowserGlobals = {
  HTMLInputElement?: unknown;
  window?: unknown;
};

class FakeElement {
  readonly classNames = new Set<string>();
  readonly listeners = new Map<string, Array<(event: Event) => void>>();
  readonly classList = {
    add: (className: string) => { this.classNames.add(className); },
    remove: (className: string) => { this.classNames.delete(className); }
  };
  addEventListener(name: string, listener: (event: Event) => void): void {
    this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]);
  }
  dispatch(name: string, event: Event): void {
    (this.listeners.get(name) ?? []).forEach(listener => listener(event));
  }
}

class FakeInputElement extends FakeElement {
  clickCount = 0;
  files: FileList | null = null;
  value = "selected";
  click(): void {
    this.clickCount += 1;
  }
}

class FakeWindow {
  readonly listeners = new Map<string, Array<(event: Event) => void>>();
  addEventListener(name: string, listener: (event: Event) => void): void {
    this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]);
  }
  dispatch(name: string, event: Event): void {
    (this.listeners.get(name) ?? []).forEach(listener => listener(event));
  }
}

const installFakeBrowser = (): { restore: () => void; targetWindow: FakeWindow } => {
  const globals = globalThis as unknown as FakeBrowserGlobals;
  const originalInput = globals.HTMLInputElement;
  const originalWindow = globals.window;
  const targetWindow = new FakeWindow();
  globals.HTMLInputElement = FakeInputElement;
  globals.window = targetWindow;
  return {
    targetWindow,
    restore: () => {
      globals.HTMLInputElement = originalInput;
      globals.window = originalWindow;
    }
  };
};

const fileListFor = (files: readonly File[]): FileList => ({
  length: files.length,
  item: (index: number): File | null => files[index] ?? null
}) as FileList;

const createDirectoryInspection = (
  openDroppedItems: DirectoryInspectionController["openDroppedItems"],
  openFiles: DirectoryInspectionController["openFiles"]
): DirectoryInspectionController => ({
  cancel: () => undefined,
  hide: () => undefined,
  open: async () => undefined,
  openDroppedItems,
  openFiles,
  showRoute: async () => undefined
});

const createPreventableEvent = (type: string): Event => {
  let prevented = false;
  return {
    type,
    preventDefault: () => { prevented = true; },
    get defaultPrevented() { return prevented; }
  } as Event;
};

void test("selection inputs route dropped files through directory inspection", async () => {
  const browser = installFakeBrowser();
  const dropZone = new FakeElement();
  const input = new FakeInputElement();
  const openedSources: string[] = [];
  try {
    attachSelectionInputs({
      directoryInspection: createDirectoryInspection(async () => false, async (_, source) => {
        openedSources.push(source);
        return true;
      }),
      dropZoneElement: dropZone as unknown as HTMLElement,
      fileInputElement: input as unknown as HTMLInputElement,
      openFile: async () => undefined,
      setStatusMessage: () => undefined
    });
    const event = createPreventableEvent("drop");
    Object.defineProperty(event, "dataTransfer", {
      value: { files: fileListFor([new File(["a"], "alpha.txt")]), items: { length: 0, item: () => null } }
    });
    dropZone.dispatch("drop", event);
    await Promise.resolve();
    assert.equal(event.defaultPrevented, true);
    assert.deepEqual(openedSources, ["Drop"]);
  } finally {
    browser.restore();
  }
});

void test("selection inputs handle keyboard selection and pasted text", async () => {
  const browser = installFakeBrowser();
  const dropZone = new FakeElement();
  const input = new FakeInputElement();
  const openedFiles: File[] = [];
  try {
    attachSelectionInputs({
      directoryInspection: createDirectoryInspection(async () => false, async () => true),
      dropZoneElement: dropZone as unknown as HTMLElement,
      fileInputElement: input as unknown as HTMLInputElement,
      openFile: async file => { openedFiles.push(file); },
      setStatusMessage: () => undefined
    });
    dropZone.dispatch("keydown", { key: "Enter", preventDefault: () => undefined } as KeyboardEvent);
    browser.targetWindow.dispatch("paste", {
      clipboardData: {
        files: fileListFor([]),
        items: [{ kind: "string", getAsString: (resolve: (text: string) => void) => resolve("hello") }]
      }
    } as unknown as ClipboardEvent);
    await Promise.resolve();
    await Promise.resolve();
    assert.equal(input.clickCount, 1);
    assert.equal(openedFiles[0]?.name, "clipboard.bin");
    assert.equal(await openedFiles[0]?.text(), "hello");
  } finally {
    browser.restore();
  }
});
