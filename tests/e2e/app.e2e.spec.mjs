import { expect, test } from "@playwright/test";

test("uploads a text file and shows its details", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();

  const fileContent = "Hello from Playwright";
  await page.setInputFiles("#fileInput", {
    name: "sample.txt",
    mimeType: "text/plain",
    buffer: Buffer.from(fileContent)
  });

  const infoCard = page.locator("#fileInfoCard");
  await expect(infoCard).toBeVisible();
  await expect(page.locator("#fileOriginalName")).toHaveText("sample.txt");
  await expect(page.locator("#fileKindDisplay")).toHaveText("Text file");

  await page.getByRole("button", { name: "Compute SHA-256" }).click();
  await expect(page.locator("#sha256Value")).toHaveText(/^[0-9a-f]{64}$/);
});

test("uploads an empty zip file and identifies it", async ({ page }) => {
  await page.goto("/");

  // A minimal ZIP file (end of central directory record with no entries)
  const emptyZipBytes = Buffer.from([
    0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);

  await page.setInputFiles("#fileInput", {
    name: "empty.zip",
    mimeType: "application/zip",
    buffer: emptyZipBytes
  });

  const infoCard = page.locator("#fileInfoCard");
  await expect(infoCard).toBeVisible();
  await expect(page.locator("#fileOriginalName")).toHaveText("empty.zip");
  await expect(page.locator("#fileKindDisplay")).toHaveText("ZIP archive");
});
