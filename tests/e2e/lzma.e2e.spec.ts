import { expect, test } from "@playwright/test";
import { createLzmaSevenZipFile } from "../fixtures/lzma-sevenzip-file.js";

const encodedArchive = () => ({ name: "compressed-header.7z",
  mimeType: "application/x-7z-compressed", buffer: Buffer.from(createLzmaSevenZipFile()) });

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
