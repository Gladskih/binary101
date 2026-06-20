import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";

const hashAlgorithms = [
  ["MD5", "md5", "md5"],
  ["SHA-1", "sha1", "sha1"],
  ["SHA-224", "sha224", "sha224"],
  ["SHA-256", "sha256", "sha256"],
  ["SHA-384", "sha384", "sha384"],
  ["SHA-512", "sha512", "sha512"],
  ["SHA-512/224", "sha512224", "sha512-224"],
  ["SHA-512/256", "sha512256", "sha512-256"]
] as const;

void test("hashes every algorithm for a real empty file", async ({ page }) => {
  const emptyBuffer = Buffer.alloc(0);
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "empty.bin",
    mimeType: "application/octet-stream",
    buffer: emptyBuffer
  });
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toHaveText("empty.bin");
  await expect(page.locator("#fileSizeDetail")).toHaveText("0 B (0 bytes)");
  await expect(page.locator("#fileSourceDetail .opt")).toHaveText([
    "Selection", "Paste", "Drop", "Navigation"
  ]);
  await expect(page.locator("#fileSourceDetail .opt.sel")).toHaveText("Selection");
  await expect(page.locator("#fileObjectDetail .opt.sel")).toHaveText("File");
  await page.locator("#hashDetails > summary").click();
  for (const [label, id, nodeName] of hashAlgorithms) {
    await page.getByRole("button", { name: `Compute ${label}`, exact: true }).click();
    await expect(page.locator(`#${id}Value`)).toHaveText(
      createHash(nodeName).update(emptyBuffer).digest("hex")
    );
  }
});
