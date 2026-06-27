import { expect, test } from "@playwright/test";
import type { Locator, Page } from "@playwright/test";
import { createGzipFile } from "../fixtures/gzip-fixtures.js";
import { createIso9660PrimaryFile } from "../fixtures/iso9660-fixtures.js";
import { createLargePeCodeStringReferenceFile } from "../fixtures/pe-code-string-table-file.js";
import { createPePlusEntrypointCallFile, createPePlusFile } from "../fixtures/sample-files-pe.js";
import { createZipWithEntries } from "../fixtures/zip-fixtures.js";
import type { MockFile } from "../helpers/mock-file.js";

const toUpload = (file: MockFile) => ({
  name: file.name,
  mimeType: file.type,
  buffer: Buffer.from(file.data)
});

const expectBaseDetails = async (page: Page, fileName: string, expectedKind: string): Promise<void> => {
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toHaveText(fileName);
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText(expectedKind);
};

const toBufferChunk = (chunk: unknown): Buffer => {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (chunk instanceof Uint8Array) return Buffer.from(chunk);
  if (typeof chunk === "string") return Buffer.from(chunk);
  throw new Error("Unexpected download stream chunk type");
};

const readDownloadText = async (
  page: Page,
  locator: Locator
): Promise<{ name: string; content: string }> => {
  const [download] = await Promise.all([page.waitForEvent("download"), locator.click()]);
  const stream = await download.createReadStream();
  if (!stream) throw new Error("Download stream unavailable");
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(toBufferChunk(chunk));
  return {
    name: download.suggestedFilename(),
    content: Buffer.concat(chunks).toString("utf8")
  };
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

    await expectBaseDetails(page, zip.name, "ZIP archive");
    const table = page.locator("button.zipExtractButton");
    await expect(table).toHaveCount(2);

    const storedResult = await readDownloadText(page, page.locator('[data-zip-entry="0"]'));
    expect(storedResult.name).toBe("stored.txt");
    expect(storedResult.content).toBe("stored");

    const deflatedResult = await readDownloadText(page, page.locator('[data-zip-entry="1"]'));
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
    await expect(page.locator("#analysisValue")).toContainText("gzip compressed data");

    const button = page.locator("button.gzipDecompressButton");
    await expect(button).toHaveCount(1);

    const result = await readDownloadText(page, button);
    expect(result.name).toBe("hello.txt");
    expect(result.content).toBe("hello");
  });

  void test("allows downloading ISO-9660 file contents from the UI", async ({ page }) => {
    const iso = createIso9660PrimaryFile();
    await page.setInputFiles("#fileInput", toUpload(iso));

    await expectBaseDetails(page, iso.name, "ISO-9660 CD/DVD image (ISO)");
    await expect(page.locator("#analysisValue")).toContainText("ISO-9660 overview");

    const button = page.locator("button.isoExtractButton");
    await expect(button).toHaveCount(1);

    const result = await readDownloadText(page, button);
    expect(result.name).toBe("HELLO.TXT");
    expect(result.content).toBe("HELLO");
  });

  void test("expands ISO-9660 directories and downloads nested files", async ({ page }) => {
    const iso = createIso9660PrimaryFile();
    await page.setInputFiles("#fileInput", toUpload(iso));

    await expectBaseDetails(page, iso.name, "ISO-9660 CD/DVD image (ISO)");
    await expect(page.locator("#analysisValue")).toContainText("ISO-9660 overview");

    const expand = page.locator("button.isoDirToggleButton");
    await expect(expand).toHaveCount(1);
    await expand.click();

    const nestedButton = page.locator('tr:has-text("INNER.TXT") button.isoExtractButton');
    await expect(nestedButton).toHaveCount(1);

    const result = await readDownloadText(page, nestedButton);
    expect(result.name).toBe("INNER.TXT");
    expect(result.content).toBe("INNER");
  });
});

test.describe("PE analysis actions", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("runs PE Instruction-set, imports and strings analysis on demand", async ({ page }) => {
    const mockFile = createPePlusFile();
    await page.setInputFiles("#fileInput", toUpload(mockFile));
    await expectBaseDetails(page, mockFile.name, "PE32+ executable for x86-64 (AMD64)");

    const detailsValue = page.locator("#analysisValue");
    const instructionSection = detailsValue.locator("details.analysisPanel").filter({
      has: page.locator("summary", { hasText: /^Instruction-set, imports and strings analysis\b/ })
    }).first();
    await instructionSection.locator(":scope > summary").click();
    await expect(instructionSection).toHaveJSProperty("open", true);
    await expect(detailsValue).toContainText("Instruction-set, imports and strings analysis");
    await expect(detailsValue.locator("#peInstructionSetsAnalyzeButton")).toBeVisible();

    await detailsValue.locator("#peInstructionSetsAnalyzeButton").click();
    await expect(instructionSection).toHaveJSProperty("open", true);
    await expect(detailsValue).toContainText("Disassembly sample");
    await expect(instructionSection).toHaveJSProperty("open", true);
    await expect(detailsValue).not.toContainText("Failed to load iced-x86 disassembler");
    await expect(detailsValue).not.toContainText("Disassembly failed");
  });

  void test("runs PE entrypoint disassembly on demand", async ({ page }) => {
    const mockFile = createPePlusEntrypointCallFile();
    await page.setInputFiles("#fileInput", toUpload(mockFile));
    await expectBaseDetails(page, mockFile.name, "PE32+ executable for x86-64 (AMD64)");

    const detailsValue = page.locator("#analysisValue");
    const entrypointSection = detailsValue.locator("details.analysisPanel").filter({
      has: page.locator("summary", { hasText: /^Entrypoint disassembly\b/ })
    }).first();
    await entrypointSection.locator(":scope > summary").click();
    await expect(entrypointSection).toHaveJSProperty("open", true);
    await expect(detailsValue.locator("#peEntrypointDisassembleButton")).toBeVisible();

    await detailsValue.locator("#peEntrypointDisassembleButton").click();
    await expect(entrypointSection).toHaveJSProperty("open", true);
    await expect(detailsValue).toContainText("Entrypoint preview:");
    await expect(detailsValue).toContainText("Followed call target");
    await expect(detailsValue.locator('[data-pe-entrypoint-jump="4102"]').first()).toBeVisible();
    await expect(detailsValue.locator('[data-pe-entrypoint-jump="4106"]').first()).toBeVisible();
    await expect(detailsValue.locator('[data-pe-entrypoint-jump="4104"]').first()).toBeVisible();
    await detailsValue.locator('[data-pe-entrypoint-jump="4102"]').first().click();
    const callTargetRow = detailsValue.locator(
      '.peEntrypointInstructionRow[data-pe-entrypoint-rva="4102"]'
    ).first();
    await expect(callTargetRow).toBeFocused();
    await expect(callTargetRow).toHaveClass(/peEntrypointTargetFlash/);
    await expect(detailsValue).toContainText("Followed conditional branch target");
    await expect(detailsValue).toContainText("Followed conditional fallthrough");
    await expect(detailsValue).toContainText("Instruction");
    await expect(detailsValue).not.toContainText("Failed to load iced-x86 disassembler");
    await expect(detailsValue).not.toContainText("Entrypoint disassembly failed");
    await expect(detailsValue).not.toContainText("unexpected module shape");
  });

  void test("keeps instruction-set table sorting when entrypoint disassembly completes", async ({ page }) => {
    const mockFile = createPePlusEntrypointCallFile();
    await page.setInputFiles("#fileInput", toUpload(mockFile));

    const detailsValue = page.locator("#analysisValue");
    const instructionSection = detailsValue.locator("details.analysisPanel").filter({
      has: page.locator("summary", { hasText: /^Instruction-set, imports and strings analysis\b/ })
    }).first();
    const entrypointSection = detailsValue.locator("details.analysisPanel").filter({
      has: page.locator("summary", { hasText: /^Entrypoint disassembly\b/ })
    }).first();
    await instructionSection.locator(":scope > summary").click();
    await detailsValue.locator("#peInstructionSetsAnalyzeButton").click();
    await expect(instructionSection).toContainText("Disassembly sample");

    const sortSetButton = instructionSection.getByRole("button", { name: "Sort by Set" }).first();
    await sortSetButton.click();
    await expect(sortSetButton.locator("..")).toHaveAttribute("aria-sort", "ascending");

    await entrypointSection.locator(":scope > summary").click();
    await detailsValue.locator("#peEntrypointDisassembleButton").click();
    await expect(entrypointSection).toContainText("Entrypoint preview:");
    await expect(sortSetButton.locator("..")).toHaveAttribute("aria-sort", "ascending");
  });
});

test.describe("large PE string tables", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("pages and sorts large PE code string tables", async ({ page }) => {
    const mockFile = createLargePeCodeStringReferenceFile();
    await page.setInputFiles("#fileInput", toUpload(mockFile));
    await expectBaseDetails(page, mockFile.name, "PE32+ executable for x86-64 (AMD64)");

    const detailsValue = page.locator("#analysisValue");
    const instructionSection = detailsValue.locator("details.analysisPanel").filter({
      has: page.locator("summary", { hasText: /^Instruction-set, imports and strings analysis\b/ })
    }).first();
    await instructionSection.locator(":scope > summary").click();
    await detailsValue.locator("#peInstructionSetsAnalyzeButton").click();
    await expect(instructionSection).toContainText("Code-referenced strings (1005)");

    const stringDetails = instructionSection.locator("details").filter({
      has: page.locator("summary", { hasText: /^Code-referenced strings \(1005\)/ })
    }).first();
    await stringDetails.locator(":scope > summary").click();
    const pagedTable = stringDetails.locator("[data-paged-sortable-table-root]").first();
    await expect(pagedTable.getByText("Showing 1-500 of 1005")).toBeVisible();
    await expect(pagedTable.locator("tbody tr")).toHaveCount(500);
    await expect(pagedTable).toContainText("value-1005");
    await expect(pagedTable).not.toContainText("value-0001");

    const textSortButton = pagedTable.getByRole("button", { name: "Sort by Text" });
    await textSortButton.click();
    await expect(textSortButton.locator("..")).toHaveAttribute("aria-sort", "ascending");
    await expect(pagedTable.locator("tbody tr").first()).toContainText("value-0001");

    await pagedTable.getByRole("button", { name: "Last" }).click();
    await expect(pagedTable.getByText("Showing 1001-1005 of 1005")).toBeVisible();
    await expect(pagedTable.locator("tbody tr")).toHaveCount(5);
  });
});
