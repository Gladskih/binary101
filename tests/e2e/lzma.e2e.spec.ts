import { expect, test } from "@playwright/test";
import { createLzmaSevenZipFile } from "../fixtures/lzma-sevenzip-file.js";
import { readFile } from "node:fs/promises";
import {
  lzma2SevenZipEncoded, lzma2SevenZipPlain, lzma2SevenZipPayload
} from "../fixtures/lzma2-sevenzip-file.js";

const encodedArchive = () => ({ name: "compressed-header.7z",
  mimeType: "application/x-7z-compressed", buffer: Buffer.from(createLzmaSevenZipFile()) });

for (const [name, fixture] of [["plain", lzma2SevenZipPlain],
  ["LZMA2 encoded", lzma2SevenZipEncoded]] as const) {
  test(`extracts a real LZMA2 archive with ${name} header`, async ({ page }) => {
    const errors: string[] = [];
    const assets: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("request", request => {
      if (/lzma-sdk-decode.*\.wasm$/.test(request.url())) assets.push(request.url());
    });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: "lzma2.7z",
      mimeType: "application/x-7z-compressed", buffer: Buffer.from(fixture()) });
    await expect(page.locator("body")).toContainText("payload.bin");
    const downloadEvent = page.waitForEvent("download");
    await page.getByRole("button", { name: "Extract", exact: true }).click();
    const download = await downloadEvent;
    expect(download.suggestedFilename()).toBe("payload.bin");
    expect(await readFile((await download.path())!)).toEqual(Buffer.from(lzma2SevenZipPayload()));
    expect(assets).toHaveLength(1);
    expect(new URL(assets[0]!).origin).toBe(new URL(page.url()).origin);
    expect(errors).toEqual([]);
  });
}

test("7z decodes using one lazy same-origin LZMA WASM load", async ({ page }) => {
  const assets: string[] = [];
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("request", request => {
    if (/lzma-sdk-decode.*\.wasm$/.test(request.url())) assets.push(request.url());
  });
  await page.goto("/");
  expect(assets).toHaveLength(0);
  await page.setInputFiles("#fileInput", encodedArchive());
  await expect(page.locator("body")).toContainText("7z overview");
  await expect(page.locator("body")).not.toContainText("Encoded 7z header decode failed");
  expect(assets).toHaveLength(1);
  expect(new URL(assets[0]!).origin).toBe(new URL(page.url()).origin);
  await page.setInputFiles("#fileInput", encodedArchive());
  await expect(page.locator("body")).toContainText("7z overview");
  expect(assets).toHaveLength(1);
  expect(errors).toEqual([]);
});

test("7z reports a failed local WASM load and retries for the next file", async ({ page }) => {
  await page.route("**/*lzma-sdk-decode*.wasm", route => route.abort());
  await page.goto("/");
  await page.setInputFiles("#fileInput", encodedArchive());
  await expect(page.locator("body")).toContainText("Encoded 7z header decode failed");
  await page.unroute("**/*lzma-sdk-decode*.wasm");
  await page.setInputFiles("#fileInput", encodedArchive());
  await expect(page.locator("body")).toContainText("7z overview");
  await expect(page.locator("body")).not.toContainText("Encoded 7z header decode failed");
});
