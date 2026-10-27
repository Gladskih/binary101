import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { lzmaZipFile } from "../fixtures/lzma-zip-file.js";

const archive = () => ({ name: "lzma.zip", mimeType: "application/zip",
  buffer: Buffer.from(lzmaZipFile()) });

test("ZIP downloads real LZMA entries with one lazy same-origin WASM load", async ({ page }) => {
  const assets: string[] = [];
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("request", request => {
    if (/lzma-sdk-decode.*\.wasm$/.test(request.url())) assets.push(request.url());
  });
  await page.goto("/");
  await page.setInputFiles("#fileInput", archive());
  await expect(page.locator("[data-zip-entry='0']")).toBeEnabled();
  expect(assets).toHaveLength(0);
  const payloadDownload = page.waitForEvent("download");
  await page.locator("[data-zip-entry='0']").click();
  const payload = await payloadDownload;
  expect(payload.suggestedFilename()).toBe("payload.bin");
  expect(await readFile((await payload.path())!)).toEqual(Buffer.from("DATA"));
  const emptyDownload = page.waitForEvent("download");
  await page.locator("[data-zip-entry='1']").click();
  expect(await readFile((await (await emptyDownload).path())!)).toHaveLength(0);
  expect(assets).toHaveLength(1);
  expect(new URL(assets[0]!).origin).toBe(new URL(page.url()).origin);
  expect(errors).toEqual([]);
});

test("ZIP reports LZMA integrity errors and restores the extract button", async ({ page }) => {
  const fixture = archive();
  // ZIP local header (30) plus filename payload.bin (11), then the 9-byte LZMA header.
  fixture.buffer[50] = 255; // Range-coded LZMA input must begin with zero.
  await page.goto("/");
  await page.setInputFiles("#fileInput", fixture);
  const button = page.locator("[data-zip-entry='0']");
  await button.click();
  await expect(page.locator("body")).toContainText("Extract failed:");
  await expect(button).toBeEnabled();
});

test("ZIP retries LZMA initialization after a failed local WASM load", async ({ page }) => {
  await page.route("**/*lzma-sdk-decode*.wasm", route => route.abort());
  await page.goto("/");
  await page.setInputFiles("#fileInput", archive());
  const button = page.locator("[data-zip-entry='0']");
  await button.click();
  await expect(page.locator("body")).toContainText("Extract failed:");
  await expect(button).toBeEnabled();
  await page.unroute("**/*lzma-sdk-decode*.wasm");
  const downloadEvent = page.waitForEvent("download");
  await button.click();
  expect(await readFile((await (await downloadEvent).path())!)).toEqual(Buffer.from("DATA"));
});
