import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import type { Page } from "@playwright/test";
import { createFb2File, createPdfFile } from "../fixtures/document-sample-files.js";
import { createElfFile } from "../fixtures/elf-sample-file.js";
import {
  createBmpFile,
  createGifFile,
  createJpegFile,
  createPngFile,
  createWebpFile
} from "../fixtures/image-sample-files.js";
import { createLnkFile } from "../fixtures/lnk-sample-file.js";
import { createMp3File } from "../fixtures/audio-sample-files.js";
import { createPeFile, createPePlusFile } from "../fixtures/sample-files-pe.js";
import { createSevenZipFile } from "../fixtures/rar-sevenzip-fixtures.js";
import { createTarFile } from "../fixtures/tar-fixtures.js";
import { createZipFile } from "../fixtures/zip-fixtures.js";
import { createGzipFile } from "../fixtures/gzip-fixtures.js";
import { createMachOFile } from "../fixtures/macho-fixtures.js";
import type { MockFile } from "../helpers/mock-file.js";
const toUpload = (file: MockFile) => ({
  name: file.name,
  mimeType: file.type,
  buffer: Buffer.from(file.data)
});
const hashExpectations = [
  { label: "MD5", id: "md5", nodeDigestName: "md5" },
  { label: "SHA-1", id: "sha1", nodeDigestName: "sha1" },
  { label: "SHA-224", id: "sha224", nodeDigestName: "sha224" },
  { label: "SHA-256", id: "sha256", nodeDigestName: "sha256" },
  { label: "SHA-384", id: "sha384", nodeDigestName: "sha384" },
  { label: "SHA-512", id: "sha512", nodeDigestName: "sha512" },
  { label: "SHA-512/224", id: "sha512224", nodeDigestName: "sha512-224" },
  { label: "SHA-512/256", id: "sha512256", nodeDigestName: "sha512-256" }
] as const;
const expectBaseDetails = async (page: Page, fileName: string, expectedKind: string): Promise<void> => {
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toHaveText(fileName);
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText(expectedKind);
};
const expectEveryHashCanBeComputed = async (page: Page, file: MockFile): Promise<void> => {
  const fileBytes = Buffer.from(file.data);
  await page.locator("#hashDetails > summary").click();
  for (const { label, id, nodeDigestName } of hashExpectations) {
    const expectedDigest = createHash(nodeDigestName).update(fileBytes).digest("hex");
    await page.getByRole("button", { name: `Compute ${label}`, exact: true }).click();
    await expect(page.locator(`#${id}Value`)).toHaveText(expectedDigest);
    await expect(page.getByRole("button", { name: `Copy ${label} hash`, exact: true })).toBeVisible();
  }
};
const happyCases = [
  { name: "PNG", file: createPngFile, expectedKind: "PNG image", detailText: "Chunks" },
  { name: "GIF", file: createGifFile, expectedKind: "GIF image", detailText: "Frames" },
  { name: "JPEG", file: createJpegFile, expectedKind: "JPEG image", detailText: "JPEG structure" },
  { name: "WebP", file: createWebpFile, expectedKind: "WebP image", detailText: "Chunks" },
  { name: "BMP", file: createBmpFile, expectedKind: "BMP bitmap image", detailText: "BMP structure" },
  { name: "FictionBook (FB2)", file: createFb2File, expectedKind: "FictionBook e-book (FB2)", detailText: "Document info" },
  { name: "TAR", file: createTarFile, expectedKind: "TAR archive", detailText: "TAR overview" },
  {
    name: "gzip",
    file: () => createGzipFile({ payload: Buffer.from("hello"), extra: null, comment: null, includeHeaderCrc16: false }),
    expectedKind: "gzip compressed data",
    detailText: "gzip compressed data"
  },
  { name: "Windows shortcut (.lnk)", file: createLnkFile, expectedKind: "Windows shortcut (.lnk)", detailText: "Shell link header" },
  { name: "ZIP", file: createZipFile, expectedKind: "ZIP archive", detailText: "ZIP overview" },
  { name: "PDF", file: createPdfFile, expectedKind: "PDF document (v1.4)", detailText: "Cross-reference" },
  { name: "ELF 64-bit", file: createElfFile, expectedKind: "ELF 64-bit LSB executable, x86-64", detailText: "ELF header" },
  { name: "MP3", file: createMp3File, expectedKind: "MPEG audio stream (MP3/AAC)", detailText: "MPEG audio stream" },
  { name: "7z", file: createSevenZipFile, expectedKind: "7z archive", detailText: "7z overview" },
  {
    name: "PE32 (x86)",
    file: createPeFile,
    expectedKind: "PE32 executable for x86 (I386)",
    detailText: "PE/COFF headers",
    extraDetailText: "Instruction-set analysis"
  },
  {
    name: "PE32+ (x86-64)",
    file: createPePlusFile,
    expectedKind: "PE32+ executable for x86-64 (AMD64)",
    detailText: "PE/COFF headers",
    extraDetailText: "Instruction-set analysis"
  }
];
test.describe("file type detection", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });
  void test("drops a text file, shows its details, and hashes", async ({ page }) => {
    const fileContent = "Hello from Playwright";
    await page.evaluate(text => {
      let file: File | null = new File([text], "sample.txt", { type: "text/plain" });
      const dropEvent = new Event("drop", { bubbles: true, cancelable: true });
      Object.defineProperty(dropEvent, "dataTransfer", {
        value: {
          files: { length: 1, item: () => file },
          items: {
            length: 1,
            item: () => ({
              kind: "file",
              getAsFileSystemHandle: async () => { throw new Error("file probe rejected"); }
            })
          }
        }
      });
      globalThis.document.getElementById("dropZone")?.dispatchEvent(dropEvent);
      file = null;
    }, fileContent);
    await expectBaseDetails(page, "sample.txt", "Text file");
    await expect(page.locator("#analysisValue")).toBeHidden();
    await page.locator("#hashDetails > summary").click();
    await page.getByRole("button", { name: "Compute SHA-256" }).click();
    await expect(page.locator("#sha256Value")).toHaveText(/^[0-9a-f]{64}$/);
  });
  void test("drops a folder and fills file type rows progressively", async ({ page }) => {
    await page.evaluate(() => {
      type BrowserHandle = {
        kind: "directory" | "file";
        name: string;
        entries?: () => AsyncIterableIterator<[string, BrowserHandle]>;
        getFile?: () => Promise<File>;
      };
      const lastModified = Date.UTC(2024, 0, 2, 3, 4, 5);
      const fileHandle = (name: string, bytes: number[], type: string): BrowserHandle => ({
        kind: "file",
        name,
        getFile: async () => new File([new Uint8Array(bytes)], name, { type, lastModified })
      });
      const docsHandle: BrowserHandle = {
        kind: "directory",
        name: "docs",
        async *entries() {
          yield ["note.txt", fileHandle("note.txt", Array.from(new TextEncoder().encode("hello")), "text/plain")];
        }
      };
      const rootHandle: BrowserHandle = {
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
    await expect(page.locator("#directoryInfoCard")).toBeVisible();
    await expect(page.locator("#directoryName")).toHaveText("fixture-folder");
    await expect(page.locator("#directorySummary")).toHaveText("1 file, 1 folder, 1/1 files scanned");
    await expect(page.locator("#directoryFolderListingBody tr")).toHaveCount(1);
    await expect(page.locator("#directoryFileListingBody tr")).toHaveCount(1);
    await expect(page.locator("#directoryFileListingBody")).toContainText("2024-01-02T03:04:05.000Z");
    await expect(page.locator("#statusMessage")).toHaveText("Folder scan complete: 1 file.");
    await page.locator("#directoryFolderListingBody tr").click();
    await expect(page.locator("#directoryName")).toHaveText("docs");
    await expect(page.locator("#directorySourceDetail .opt.sel")).toHaveText("Navigation");
    await expect(page.locator("#directoryObjectDetail .opt.sel")).toHaveText("Directory");
    await expect(page.locator("#directoryRelativePathDetail")).toHaveText("fixture-folder/docs");
    await expect(page.locator("#directoryFileListingBody")).toContainText("note.txt");
    await expect(page.locator("#directoryFileListingBody")).toContainText("5 B (5 bytes)");
    await page.goBack();
    await expect(page.locator("#directoryName")).toHaveText("fixture-folder");
    await page.locator("#directoryFileListingBody tr", { hasText: "pixel.png" }).click();
    await expectBaseDetails(page, "pixel.png", "PNG image");
  });
});

test.describe("file hash actions", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("keeps hash actions in a collapsed section before analysis details", async ({ page }) => {
    const file = createPeFile();
    await page.setInputFiles("#fileInput", toUpload(file));
    await expectBaseDetails(page, "sample.exe", "PE32 executable for x86 (I386)");
    await expect(page.locator("#analysisValue")).toContainText("PE/COFF headers");
    await expect(page.locator("#analysisValue")).not.toContainText(
      "Portable Executable (PE) / COFF is the executable and object-file format"
    );
    const typeHelp = page.locator("#fileBinaryTypeDetail .accessibleTooltipButton");
    await expect(page.locator("#fileBinaryTypeDetail")).toHaveAttribute(
      "title",
      "Portable Executable (PE) / COFF is the executable and object-file format used by " +
      "Windows toolchains."
    );
    await expect(typeHelp).toBeVisible();
    await typeHelp.click();
    await expect(page.locator("#fileBinaryTypeDetail .accessibleTooltipPopup")).toHaveAttribute(
      "aria-label",
      "Portable Executable (PE) / COFF is the executable and object-file format used by " +
      "Windows toolchains."
    );
    await page.keyboard.press("Escape");
    await expect(page.locator("#fileBinaryTypeDetail .accessibleTooltipPopup")).toBeHidden();
    expect(await page.locator("#analysisValue .accessibleTooltipButton").count()).toBeGreaterThan(0);

    const hashDetails = page.locator("#hashDetails");
    const nativeHashLabels = page.locator(".nativeHashLabel");
    const nativeHashBadges = page.locator(".nativeHashBadge");
    const nativeHashTooltip = page.locator("#sha256NativeBadge ~ .accessibleTooltipPopup");
    const detailsBox = await page.locator("#analysisValue").boundingBox();
    await expect(hashDetails).not.toHaveAttribute("open", "");
    await expect(nativeHashLabels).toHaveCount(4);
    await expect(nativeHashBadges).toHaveText(["🍃", "🍃", "🍃", "🍃"]);
    await expect(page.locator("#sha256NativeBadge")).toHaveAttribute(
      "title",
      "Native crypto is tried first."
    );
    const hashSummaryBox = await hashDetails.locator("summary").boundingBox();
    expect(hashSummaryBox?.y).toBeLessThan(detailsBox?.y ?? 0);

    await expectEveryHashCanBeComputed(page, file);
    await page.locator("#sha256NativeBadge").click();
    await expect(nativeHashTooltip).toHaveAttribute(
      "aria-label",
      "Native crypto is tried first."
    );
  });
});

test.describe("file type rendering", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  for (const { name, file, expectedKind, detailText, extraDetailText } of happyCases) {
    void test(`recognises ${name} files`, async ({ page }) => {
      const mockFile = file();
      await page.setInputFiles("#fileInput", toUpload(mockFile));
      await expectBaseDetails(page, mockFile.name, expectedKind);

      const detailsValue = page.locator("#analysisValue");
      await expect(detailsValue).toBeVisible();
      await expect(detailsValue).toContainText(detailText);
      if (extraDetailText) {
        await expect(detailsValue).toContainText(extraDetailText);
        await expect(detailsValue).not.toContainText("Failed to load iced-x86 disassembler");
      }
    });
  }

  void test("shows Windows shortcut property store data", async ({ page }) => {
    const mockFile = createLnkFile();
    await page.setInputFiles("#fileInput", toUpload(mockFile));
    await expectBaseDetails(page, mockFile.name, "Windows shortcut (.lnk)");
    await expect(page.locator("#analysisValue")).toContainText("System.Link.TargetParsingPath");
    await expect(page.locator("#analysisValue")).toContainText("C:\\Program Files\\Example\\app.exe");
    await expect(page.locator("#analysisValue")).toContainText("System.VolumeId");
  });

  void test("renders Mach-O analysis", async ({ page }) => {
    const file = createMachOFile();
    await page.setInputFiles("#fileInput", toUpload(file));

    await expectBaseDetails(page, file.name, "Mach-O 64-bit");
    await expect(page.locator("#analysisValue")).toContainText("Mach-O header");
    await expect(page.locator("#analysisValue")).toContainText("Code signing");
  });

  void test("renders MP3 audio summary", async ({ page }) => {
    const file = createMp3File();
    await page.setInputFiles("#fileInput", toUpload(file));

    await expectBaseDetails(page, file.name, "MPEG audio stream (MP3/AAC)");
    await expect(page.locator("#analysisValue")).toContainText("MPEG audio stream");
    await expect(page.locator("#analysisValue")).toContainText("Summary");
    await expect(page.locator(".audioPreview audio")).toBeVisible();
  });

  void test("shows unknown binary type when no probe matches", async ({ page }) => {
    const buffer = Buffer.alloc(32, 0);
    await page.setInputFiles("#fileInput", {
      name: "unknown.bin",
      mimeType: "application/octet-stream",
      buffer
    });

    await expectBaseDetails(page, "unknown.bin", "Unknown binary type");
    await expect(page.locator("#analysisValue")).toBeHidden();
  });

});
