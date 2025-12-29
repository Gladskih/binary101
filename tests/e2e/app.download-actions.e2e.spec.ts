import { expect, test } from "@playwright/test";
import type { Locator, Page } from "@playwright/test";
import { createGzipFile } from "../fixtures/gzip-fixtures.js";
import { createIso9660PrimaryFile } from "../fixtures/iso9660-fixtures.js";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";
import { createZipWithEntries } from "../fixtures/zip-fixtures.js";
import type { MockFile } from "../helpers/mock-file.js";

const toUpload = (file: MockFile) => ({
  name: file.name,
  mimeType: file.type,
  buffer: Buffer.from(file.data)
});

const expectBaseDetails = async (page: Page, fileName: string, expectedKind: string): Promise<void> => {
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileOriginalName")).toHaveText(fileName);
  await expect(page.locator("#fileKindDisplay")).toHaveText(expectedKind);
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText(expectedKind);
};

test.describe("download actions", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("allows downloading stored and deflated ZIP entries from the UI", async ({ page }) => {
    const supportsDecompression = await page.evaluate(() => typeof DecompressionStream === "function");
    test.skip(!supportsDecompression, "DecompressionStream not supported in this browser");

    const zip = createZipWithEntries();
    await page.setInputFiles("#fileInput", toUpload(zip));

    await expectBaseDetails(page, zip.name, "ZIP archive (PK-based, e.g. Office, JAR, APK)");
    const table = page.locator("button.zipExtractButton");
    await expect(table).toHaveCount(2);

    const readDownloadText = async (locator: Locator): Promise<{ name: string; content: string }> => {
      const [download] = await Promise.all([page.waitForEvent("download"), locator.click()]);
      const stream = await download.createReadStream();
      if (!stream) throw new Error("Download stream unavailable");
      const chunks: Buffer[] = [];
      for await (const chunk of stream) chunks.push(chunk);
      const content = Buffer.concat(chunks).toString("utf8");
      return { name: download.suggestedFilename(), content };
    };

    const storedResult = await readDownloadText(page.locator('[data-zip-entry="0"]'));
    expect(storedResult.name).toBe("stored.txt");
    expect(storedResult.content).toBe("stored");

    const deflatedResult = await readDownloadText(page.locator('[data-zip-entry="1"]'));
    expect(deflatedResult.name).toBe("deflated.txt");
    expect(deflatedResult.content).toBe("deflated");
  });

  void test("allows downloading decompressed gzip data from the UI", async ({ page }) => {
    const supportsGzip = await page.evaluate(() => {
      if (typeof DecompressionStream !== "function") return false;
      try {
        const stream = new DecompressionStream("gzip");
        void stream;
        return true;
      } catch {
        return false;
      }
    });
    test.skip(!supportsGzip, "gzip DecompressionStream not supported in this browser");

    const gzip = createGzipFile({
      payload: Buffer.from("hello"),
      filename: "hello.txt",
      extra: null,
      comment: null,
      includeHeaderCrc16: false,
      name: "hello.txt.gz"
    });
    await page.setInputFiles("#fileInput", toUpload(gzip));

    await expectBaseDetails(page, gzip.name, "gzip compressed data");
    await expect(page.locator("#peDetailsTerm")).toHaveText("gzip details");

    const button = page.locator("button.gzipDecompressButton");
    await expect(button).toHaveCount(1);

    const [download] = await Promise.all([page.waitForEvent("download"), button.click()]);
    const stream = await download.createReadStream();
    if (!stream) throw new Error("Download stream unavailable");
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk);
    const content = Buffer.concat(chunks).toString("utf8");
    expect(download.suggestedFilename()).toBe("hello.txt");
    expect(content).toBe("hello");
  });

  void test("allows downloading ISO-9660 file contents from the UI", async ({ page }) => {
    const iso = createIso9660PrimaryFile();
    await page.setInputFiles("#fileInput", toUpload(iso));

    await expectBaseDetails(page, iso.name, "ISO-9660 CD/DVD image (ISO)");
    await expect(page.locator("#peDetailsTerm")).toHaveText("ISO-9660 details");

    const button = page.locator("button.isoExtractButton");
    await expect(button).toHaveCount(1);

    const [download] = await Promise.all([page.waitForEvent("download"), button.click()]);
    const stream = await download.createReadStream();
    if (!stream) throw new Error("Download stream unavailable");
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk);
    const content = Buffer.concat(chunks).toString("utf8");

    expect(download.suggestedFilename()).toBe("HELLO.TXT");
    expect(content).toBe("HELLO");
  });

  void test("expands ISO-9660 directories and downloads nested files", async ({ page }) => {
    const iso = createIso9660PrimaryFile();
    await page.setInputFiles("#fileInput", toUpload(iso));

    await expectBaseDetails(page, iso.name, "ISO-9660 CD/DVD image (ISO)");
    await expect(page.locator("#peDetailsTerm")).toHaveText("ISO-9660 details");

    const expand = page.locator("button.isoDirToggleButton");
    await expect(expand).toHaveCount(1);
    await expand.click();

    const nestedButton = page.locator('tr:has-text("INNER.TXT") button.isoExtractButton');
    await expect(nestedButton).toHaveCount(1);

    const [download] = await Promise.all([page.waitForEvent("download"), nestedButton.click()]);
    const stream = await download.createReadStream();
    if (!stream) throw new Error("Download stream unavailable");
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk);
    const content = Buffer.concat(chunks).toString("utf8");

    expect(download.suggestedFilename()).toBe("INNER.TXT");
    expect(content).toBe("INNER");
  });

  void test("runs PE instruction-set analysis on demand", async ({ page }) => {
    const mockFile = createPePlusFile();
    await page.setInputFiles("#fileInput", toUpload(mockFile));
    await expectBaseDetails(page, mockFile.name, "PE32+ executable for x86-64 (AMD64)");

    const detailsValue = page.locator("#peDetailsValue");
    await expect(detailsValue).toContainText("Instruction sets");
    await expect(detailsValue.locator("#peInstructionSetsAnalyzeButton")).toBeVisible();

    await detailsValue.locator("#peInstructionSetsAnalyzeButton").click();
    await expect(detailsValue).toContainText("Disassembly sample");
    await expect(detailsValue).not.toContainText("Failed to load iced-x86 disassembler");
    await expect(detailsValue).not.toContainText("Disassembly failed");
  });
});
