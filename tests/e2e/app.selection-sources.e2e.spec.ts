import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

type PayloadKind = "one-file" | "multiple-files" | "folder" | "multiple-folders";
type SourceKind = "drop" | "paste" | "dialog";
type BrowserHandle = {
  kind: "directory" | "file";
  name: string;
  entries?: () => AsyncIterableIterator<[string, BrowserHandle]>;
  getFile?: () => Promise<File>;
};
type SelectionFixtureWindow = Window & {
  __binary101DispatchDrop?: (payload: PayloadKind) => void;
  __binary101DispatchPaste?: (payload: PayloadKind) => void;
  __binary101InstallDirectoryPicker?: (payload: PayloadKind) => void;
};

const uploadFile = (name: string, text: string) => ({
  name,
  mimeType: "text/plain",
  buffer: Buffer.from(text)
});

const uploadsFor = (payload: PayloadKind) =>
  payload === "one-file"
    ? [uploadFile("alpha.txt", "alpha")]
    : [uploadFile("alpha.txt", "alpha"), uploadFile("beta.txt", "beta")];

const installSelectionFixtures = async (page: Page): Promise<void> => {
  await page.addInitScript(() => {
    type FixtureItem = { kind: "file"; getAsFileSystemHandle: () => Promise<BrowserHandle | null> };
    const browserWindow = globalThis as unknown as SelectionFixtureWindow;
    const browserDocument = (globalThis as { document: Document }).document;
    const file = (name: string, text: string): File =>
      new File([text], name, { type: "text/plain", lastModified: Date.UTC(2024, 0, 2, 3, 4, 5) });
    const fileHandle = (name: string, text: string): BrowserHandle => ({
      kind: "file",
      name,
      getFile: async () => file(name, text)
    });
    const directoryHandle = (name: string, children: readonly BrowserHandle[]): BrowserHandle => ({
      kind: "directory",
      name,
      async *entries() {
        for (const child of children) yield [child.name, child];
      }
    });
    const handlesFor = (payload: PayloadKind): BrowserHandle[] => {
      if (payload === "folder") {
        return [directoryHandle("folder-one", [fileHandle("inside.txt", "inside")])];
      }
      if (payload === "multiple-folders") {
        return [
          directoryHandle("folder-one", [fileHandle("one.txt", "one")]),
          directoryHandle("folder-two", [fileHandle("two.txt", "two")])
        ];
      }
      return payload === "one-file"
        ? [fileHandle("alpha.txt", "alpha")]
        : [fileHandle("alpha.txt", "alpha"), fileHandle("beta.txt", "beta")];
    };
    const filesFor = (payload: PayloadKind): File[] =>
      handlesFor(payload)
        .filter(handle => handle.kind === "file")
        .map(handle => file(handle.name, handle.name));
    const fileListFor = (files: readonly File[]) => ({
      length: files.length,
      item: (index: number): File | null => files[index] ?? null
    });
    const itemListFor = (items: readonly FixtureItem[]) =>
      Object.assign([...items], { item: (index: number): FixtureItem | null => items[index] ?? null });
    const handleItemsFor = (handles: readonly BrowserHandle[]): FixtureItem[] =>
      handles.map(handle => ({ kind: "file", getAsFileSystemHandle: async () => handle }));
    const fileProbeItemsFor = (files: readonly File[]): FixtureItem[] =>
      files.map(() => ({
        kind: "file",
        getAsFileSystemHandle: async () => { throw new Error("file handle unavailable"); }
      }));
    browserWindow.__binary101DispatchDrop = payload => {
      const files = filesFor(payload);
      const items = payload.includes("file") ? fileProbeItemsFor(files) : handleItemsFor(handlesFor(payload));
      const dropEvent = new Event("drop", { bubbles: true, cancelable: true });
      Object.defineProperty(dropEvent, "dataTransfer", {
        value: { files: fileListFor(files), items: itemListFor(items) }
      });
      browserDocument.getElementById("dropZone")?.dispatchEvent(dropEvent);
      files.splice(0, files.length);
    };
    browserWindow.__binary101DispatchPaste = payload => {
      const files = filesFor(payload);
      const items = payload.includes("file") ? [] : handleItemsFor(handlesFor(payload));
      const pasteEvent = new Event("paste", { bubbles: true, cancelable: true });
      Object.defineProperty(pasteEvent, "clipboardData", {
        value: { files: fileListFor(files), items: itemListFor(items) }
      });
      browserWindow.dispatchEvent(pasteEvent);
    };
    browserWindow.__binary101InstallDirectoryPicker = payload => {
      const handles = handlesFor(payload);
      const root = payload === "folder" ? handles[0] : directoryHandle("Selected folders", handles);
      Object.defineProperty(browserWindow, "showDirectoryPicker", { configurable: true, value: async () => root });
    };
  });
};

const dispatchDrop = async (page: Page, payload: PayloadKind): Promise<void> => {
  await page.evaluate(payloadKind => {
    (globalThis as unknown as SelectionFixtureWindow).__binary101DispatchDrop?.(payloadKind);
  }, payload);
};

const dispatchPaste = async (page: Page, payload: PayloadKind): Promise<void> => {
  await page.evaluate(payloadKind => {
    (globalThis as unknown as SelectionFixtureWindow).__binary101DispatchPaste?.(payloadKind);
  }, payload);
};

const openDialog = async (page: Page, payload: PayloadKind): Promise<void> => {
  if (payload.includes("file")) {
    await page.setInputFiles("#fileInput", uploadsFor(payload));
    return;
  }
  await page.evaluate(payloadKind => {
    (globalThis as unknown as SelectionFixtureWindow).__binary101InstallDirectoryPicker?.(payloadKind);
  }, payload);
  await page.getByRole("button", { name: "Open folder" }).click();
};

const useSource = async (page: Page, source: SourceKind, payload: PayloadKind): Promise<void> => {
  if (source === "drop") await dispatchDrop(page, payload);
  else if (source === "paste") await dispatchPaste(page, payload);
  else await openDialog(page, payload);
};

const expectFileDetails = async (page: Page, fileName: string): Promise<void> => {
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toHaveText(fileName);
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText("Text file");
};

const expectPageNotStretched = async (page: Page): Promise<void> => {
  await expect.poll(async () => page.evaluate(() => {
    const viewport = globalThis as unknown as { document: Document; innerWidth: number };
    return viewport.document.documentElement.scrollWidth <= viewport.innerWidth;
  })).toBe(true);
};

const expectMultipleFiles = async (page: Page): Promise<void> => {
  await expect(page.locator("#directoryInfoCard")).toBeVisible();
  await expect(page.locator("#directoryName")).toHaveText("Selected files");
  await expect(page.locator("#directorySummary")).toHaveText("2 files, 0 folders, 2/2 files scanned");
  await expect(page.locator("#directoryFileListingBody tr")).toHaveCount(2);
  await expectPageNotStretched(page);
  await page.locator("#directoryFileListingBody tr", { hasText: "alpha.txt" }).click();
  await expectFileDetails(page, "alpha.txt");
};

const expectOneFolder = async (page: Page): Promise<void> => {
  await expect(page.locator("#directoryInfoCard")).toBeVisible();
  await expect(page.locator("#directoryName")).toHaveText("folder-one");
  await expect(page.locator("#directorySummary")).toHaveText("1 file, 0 folders, 1/1 files scanned");
  await expect(page.locator("#directoryFileListingBody tr")).toHaveCount(1);
  await expectPageNotStretched(page);
  await page.locator("#directoryFileListingBody tr", { hasText: "inside.txt" }).click();
  await expectFileDetails(page, "inside.txt");
};

const expectMultipleFolders = async (page: Page, rootName: string): Promise<void> => {
  await expect(page.locator("#directoryInfoCard")).toBeVisible();
  await expect(page.locator("#directoryName")).toHaveText(rootName);
  await expect(page.locator("#directorySummary")).toHaveText("0 files, 2 folders, 0/0 files scanned");
  await expect(page.locator("#directoryFolderListingBody tr")).toHaveCount(2);
  await page.locator("#directoryFolderListingBody tr", { hasText: "folder-one/" }).click();
  await expect(page.locator("#directoryName")).toHaveText(`${rootName}/folder-one`);
  await page.getByRole("button", { name: "Back" }).click();
  await expect(page.locator("#directoryName")).toHaveText(rootName);
  await expectPageNotStretched(page);
};

const expectPayload = async (page: Page, source: SourceKind, payload: PayloadKind): Promise<void> => {
  if (payload === "one-file") await expectFileDetails(page, "alpha.txt");
  else if (payload === "multiple-files") await expectMultipleFiles(page);
  else if (payload === "folder") await expectOneFolder(page);
  else await expectMultipleFolders(page, source === "dialog" ? "Selected folders" : "Dropped items");
};

test.describe("selection sources", () => {
  test.beforeEach(async ({ page }) => {
    await installSelectionFixtures(page);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  for (const source of ["paste", "drop", "dialog"] as const) {
    for (const payload of ["one-file", "multiple-files", "folder", "multiple-folders"] as const) {
      void test(`${source} handles ${payload}`, async ({ page }) => {
        await useSource(page, source, payload);
        await expectPayload(page, source, payload);
      });
    }
  }
});
