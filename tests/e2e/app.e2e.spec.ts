import { expect, test } from "@playwright/test";
import {
  createElfFile,
  createFb2File,
  createGifFile,
  createJpegFile,
  createMp3File,
  createPdfFile,
  createPeFile,
  createPePlusFile,
  createPngFile,
  createSevenZipFile,
  createTarFile,
  createWebpFile,
  createZipFile,
  createZipWithEntries,
  createLnkFile
} from "../fixtures/sample-files.js";

const toUpload = file => ({
  name: file.name,
  mimeType: file.type,
  buffer: Buffer.from(file.bytes)
});

const expectBaseDetails = async (page, fileName, expectedKind) => {
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileOriginalName")).toHaveText(fileName);
  await expect(page.locator("#fileKindDisplay")).toHaveText(expectedKind);
  await expect(page.locator("#fileBinaryTypeDetail")).toHaveText(expectedKind);
};

test.describe("file type detection", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("uploads a text file, shows its details, and hashes", async ({ page }) => {
    const fileContent = "Hello from Playwright";
    await page.setInputFiles("#fileInput", {
      name: "sample.txt",
      mimeType: "text/plain",
      buffer: Buffer.from(fileContent)
    });

    await expectBaseDetails(page, "sample.txt", "Text file");
    await expect(page.locator("#peDetailsTerm")).toBeHidden();

    await page.getByRole("button", { name: "Compute SHA-256" }).click();
    await expect(page.locator("#sha256Value")).toHaveText(/^[0-9a-f]{64}$/);
  });

  const happyCases = [
    {
      name: "PNG",
      file: createPngFile,
      expectedKind: "PNG image (1x1, Grayscale + alpha, alpha)",
      term: "PNG details",
      detailText: "Chunks"
    },
    {
      name: "GIF",
      file: createGifFile,
      expectedKind: "GIF image",
      term: "GIF details",
      detailText: "Frames"
    },
    {
      name: "JPEG",
      file: createJpegFile,
      expectedKind: "JPEG image",
      term: "JPEG details",
      detailText: "JPEG structure"
    },
    {
      name: "WebP",
      file: createWebpFile,
      expectedKind: "WebP image",
      term: "WebP details",
      detailText: "Chunks"
    },
    {
      name: "FictionBook (FB2)",
      file: createFb2File,
      expectedKind: "FictionBook e-book (FB2)",
      term: "FB2 details",
      detailText: "Document info"
    },
    {
      name: "TAR",
      file: createTarFile,
      expectedKind: "TAR archive",
      term: "TAR details",
      detailText: "TAR overview"
    },
    {
      name: "Windows shortcut (.lnk)",
      file: createLnkFile,
      expectedKind: "Windows shortcut (.lnk)",
      term: "Windows shortcut details",
      detailText: "Shell link header"
    },
    {
      name: "ZIP",
      file: createZipFile,
      expectedKind: "ZIP archive",
      term: "ZIP details",
      detailText: "ZIP overview"
    },
    {
      name: "PDF",
      file: createPdfFile,
      expectedKind: "PDF document (v1.4)",
      term: "PDF details",
      detailText: "Cross-reference"
    },
    {
      name: "ELF 64-bit",
      file: createElfFile,
      expectedKind: "ELF 64-bit LSB executable, x86-64",
      term: "ELF details",
      detailText: "ELF header"
    },
    {
      name: "MP3",
      file: createMp3File,
      expectedKind: "MPEG Version 1, Layer III, 128 kbps, 44100 Hz, Stereo",
      term: "MP3 details",
      detailText: "MPEG audio stream"
    },
    {
      name: "7z",
      file: createSevenZipFile,
      expectedKind: "7z archive v0.4",
      term: "7z details",
      detailText: "7z overview"
    },
    {
      name: "PE32 (x86)",
      file: createPeFile,
      expectedKind: "PE32 executable for x86 (I386)",
      term: "PE/COFF details",
      detailText: "PE signature"
    },
    {
      name: "PE32+ (x86-64)",
      file: createPePlusFile,
      expectedKind: "PE32+ executable for x86-64 (AMD64)",
      term: "PE/COFF details",
      detailText: "PE signature"
    }
  ];

  for (const { name, file, expectedKind, term, detailText } of happyCases) {
    void test(`recognises ${name} files`, async ({ page }) => {
      const mockFile = file();
      await page.setInputFiles("#fileInput", toUpload(mockFile));
      await expectBaseDetails(page, mockFile.name, expectedKind);

      const detailsTerm = page.locator("#peDetailsTerm");
      const detailsValue = page.locator("#peDetailsValue");
      if (term) {
        await expect(detailsTerm).toHaveText(term);
        await expect(detailsValue).toBeVisible();
        await expect(detailsValue).toContainText(detailText);
      } else {
        await expect(detailsTerm).toBeHidden();
      }
    });
  }

  void test("shows Windows shortcut property store data", async ({ page }) => {
    const mockFile = createLnkFile();
    await page.setInputFiles("#fileInput", toUpload(mockFile));
    await expectBaseDetails(page, mockFile.name, "Windows shortcut (.lnk)");
    await expect(page.locator("#peDetailsTerm")).toHaveText("Windows shortcut details");
    await expect(page.locator("#peDetailsValue")).toContainText("System.Link.TargetParsingPath");
    await expect(page.locator("#peDetailsValue")).toContainText("C:\\Program Files\\Example\\app.exe");
    await expect(page.locator("#peDetailsValue")).toContainText("System.VolumeId");
  });

  void test("detects Mach-O binaries without renderer detail", async ({ page }) => {
    await page.setInputFiles("#fileInput", {
      name: "macho.bin",
      mimeType: "application/octet-stream",
      buffer: Buffer.from([0xfe, 0xed, 0xfa, 0xcf])
    });

    await expectBaseDetails(page, "macho.bin", "Mach-O 64-bit");
    await expect(page.locator("#peDetailsTerm")).toBeHidden();
  });

  void test("renders MP3 audio summary", async ({ page }) => {
    const file = createMp3File();
    await page.setInputFiles("#fileInput", toUpload(file));

    await expectBaseDetails(page, file.name, "MPEG Version 1, Layer III, 128 kbps, 44100 Hz, Stereo");
    await expect(page.locator("#peDetailsTerm")).toHaveText("MP3 details");
    await expect(page.locator("#peDetailsValue")).toContainText("MPEG audio stream");
    await expect(page.locator("#peDetailsValue")).toContainText("Summary");
  });

  void test("shows unknown binary type when no probe matches", async ({ page }) => {
    const buffer = Buffer.alloc(32, 0);
    await page.setInputFiles("#fileInput", {
      name: "unknown.bin",
      mimeType: "application/octet-stream",
      buffer
    });

    await expectBaseDetails(page, "unknown.bin", "Unknown binary type");
    await expect(page.locator("#peDetailsTerm")).toBeHidden();
  });

  void test("allows downloading stored and deflated ZIP entries from the UI", async ({ page }) => {
    const supportsDecompression = await page.evaluate(() => typeof DecompressionStream === "function");
    test.skip(!supportsDecompression, "DecompressionStream not supported in this browser");

    const zip = createZipWithEntries();
    await page.setInputFiles("#fileInput", toUpload(zip));

    await expectBaseDetails(page, zip.name, "ZIP archive (PK-based, e.g. Office, JAR, APK)");
    const table = page.locator("button.zipExtractButton");
    await expect(table).toHaveCount(2);

    const readDownloadText = async locator => {
      const [download] = await Promise.all([page.waitForEvent("download"), locator.click()]);
      const stream = await download.createReadStream();
      if (!stream) throw new Error("Download stream unavailable");
      const chunks = [];
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
});