import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const dispatchFixtureFolderDrop = async (page: Page): Promise<void> => {
  await page.evaluate(() => {
    type PageBrowserHandle = {
      kind: "directory" | "file";
      name: string;
      entries?: () => AsyncIterableIterator<[string, PageBrowserHandle]>;
      getFile?: () => Promise<File>;
    };
    const lastModified = Date.UTC(2024, 0, 2, 3, 4, 5);
    const fileHandle = (name: string, bytes: number[], type: string): PageBrowserHandle => ({
      kind: "file",
      name,
      getFile: async () => new File([new Uint8Array(bytes)], name, { type, lastModified })
    });
    const docsHandle: PageBrowserHandle = {
      kind: "directory",
      name: "docs",
      async *entries() {
        yield ["note.txt", fileHandle("note.txt", Array.from(new TextEncoder().encode("hello")), "text/plain")];
      }
    };
    const rootHandle: PageBrowserHandle = {
      kind: "directory",
      name: "fixture-folder",
      async *entries() {
        yield ["docs", docsHandle];
        yield [
          "pixel.png",
          fileHandle("pixel.png", [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], "image/png")
        ];
      }
    };
    const dropEvent = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(dropEvent, "dataTransfer", {
      value: {
        files: [],
        items: {
          length: 1,
          item: () => ({ kind: "file", getAsFileSystemHandle: async () => rootHandle })
        }
      }
    });
    globalThis.document.getElementById("dropZone")?.dispatchEvent(dropEvent);
  });
};

const expectDirectory = async (page: Page, name: string): Promise<void> => {
  await expect(page.locator("#directoryInfoCard")).toBeVisible();
  await expect(page.locator("#directoryName")).toHaveText(name);
};

const expectPixelFile = async (page: Page): Promise<void> => {
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toHaveText("pixel.png");
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText("PNG image");
};

test("browser back and forward restore folder and file inspection routes", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  await dispatchFixtureFolderDrop(page);
  await expectDirectory(page, "fixture-folder");
  await page.locator("#directoryFolderListingBody tr").click();
  await expectDirectory(page, "fixture-folder/docs");
  await page.goBack();
  await expectDirectory(page, "fixture-folder");
  await page.goForward();
  await expectDirectory(page, "fixture-folder/docs");
  await page.goBack();
  await expectDirectory(page, "fixture-folder");
  await page.locator("#directoryFileListingBody tr", { hasText: "pixel.png" }).click();
  await expectPixelFile(page);
  await page.goBack();
  await expectDirectory(page, "fixture-folder");
  await page.goForward();
  await expectPixelFile(page);
});
