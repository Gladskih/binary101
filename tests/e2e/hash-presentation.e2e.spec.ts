import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";

const ids = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512224", "sha512256"];

for (const width of [320, 768, 1440, 2530]) {
  test(`complete digests fit without individual scrollbars at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: "hashes.bin", mimeType: "application/octet-stream",
      buffer: Buffer.alloc(128 * 1024, 37) });
    await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
    await page.locator("#fileHashesButton").click();
    await page.locator("#sha512ComputeButton").click();
    await expect(page.locator("#sha512Value")).toHaveText(/^[a-f0-9]{128}$/);

    const bounds = await page.locator("#sha512Value").evaluate(value => ({
      client: value.clientWidth, scroll: value.scrollWidth,
      table: value.closest("table")?.getBoundingClientRect().width,
      right: value.getBoundingClientRect().right, viewport: value.ownerDocument.defaultView!.innerWidth
    }));
    expect(bounds.table).toBeDefined();
    expect(bounds.scroll).toBeLessThanOrEqual(bounds.client);
    expect(bounds.right).toBeLessThanOrEqual(bounds.viewport);
    expect(await page.locator("html").evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(width);
  });
}

test("small files compute all algorithms automatically without opening the hash tool", async ({ page }) => {
  await page.goto("/");
  const bytes = Buffer.from("small file with known hashes");

  await page.setInputFiles("#fileInput", { name: "small.txt", mimeType: "text/plain", buffer: bytes });

  await expect(page.locator("#sha256Value")).toHaveText(createHash("sha256").update(bytes).digest("hex"));
  await expect(page.locator("#sha512Value")).toHaveText(createHash("sha512").update(bytes).digest("hex"));
  await page.locator("#fileHashesButton").click();
  await expect(page.locator("#hashDetails tbody tr")).toHaveCount(ids.length);
  await expect(page.locator("#sha512ComputeButton")).toBeHidden();
  await expect(page.locator("#sha512CopyButton")).toBeVisible();
});

test("a wide viewport shows the complete SHA-512 on one line when it fits", async ({ page }) => {
  await page.setViewportSize({ width: 2530, height: 900 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "small.txt", mimeType: "text/plain", buffer: Buffer.from("abc") });
  await expect(page.locator("#sha512Value")).toHaveText(/^[a-f0-9]{128}$/);
  await page.locator("#fileHashesButton").click();

  const dimensions = await page.locator("#sha512Value").evaluate(element => ({
    height: element.getBoundingClientRect().height,
    lineHeight: Number.parseFloat(element.ownerDocument.defaultView!.getComputedStyle(element).lineHeight)
  }));

  expect(dimensions.height).toBe(dimensions.lineHeight);
});

test("a hashes-only report has no empty navigation column", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "small.txt", mimeType: "text/plain", buffer: Buffer.from("abc") });
  await expect(page.locator("#sha512Value")).toHaveText(/^[a-f0-9]{128}$/);

  await expect(page.locator(".workspaceSidebar")).toBeHidden();
  expect((await page.locator("#workspaceContent").boundingBox())!.x).toBe(0);
});

test("copying a wrapped digest preserves every character and does not add a page status bar", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 900 });
  await page.goto("/");
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", { value: { writeText: async (value: string) => {
      Reflect.set(globalThis, "copiedHash", value);
    } } });
  });
  const bytes = Buffer.from("copy an entire wrapped hash");
  await page.setInputFiles("#fileInput", { name: "small.txt", mimeType: "text/plain", buffer: bytes });
  await expect(page.locator("#sha512Value")).toHaveText(/^[a-f0-9]{128}$/);
  await page.locator("#fileHashesButton").click();

  await page.locator("#sha512CopyButton").click();

  await expect(page.locator("#sha512CopyButton")).toHaveAttribute("data-copy-state", "copied");
  expect(await page.evaluate(() => {
    const value: unknown = Reflect.get(globalThis, "copiedHash");
    return typeof value === "string" ? value : null;
  }))
    .toBe(createHash("sha512").update(bytes).digest("hex"));
  await expect(page.locator("#statusMessage")).toBeEmpty();
});
