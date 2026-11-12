import { expect, test } from "@playwright/test";

const algorithms = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512224", "sha512256"];

for (const width of [320, 768, 1440]) {
test(`hash computation keeps every row in place at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 900 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "hash.txt", mimeType: "text/plain",
    buffer: Buffer.alloc(128 * 1024, 37) });
  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
  await page.locator("#fileHashesButton").click();
  const before = await page.locator("#hashDetails tbody tr").evaluateAll(elements =>
    elements.map(element => ({ y: element.getBoundingClientRect().y - elements[0]!.getBoundingClientRect().y,
      height: element.getBoundingClientRect().height })));
  expect(before).toHaveLength(8);

  for (const id of algorithms) {
    await page.locator(`#${id}ComputeButton`).click();
    await expect(page.locator(`#${id}Value`)).not.toHaveText("");
  }

  const after = await page.locator("#hashDetails tbody tr").evaluateAll(elements =>
    elements.map(element => ({ y: element.getBoundingClientRect().y - elements[0]!.getBoundingClientRect().y,
      height: element.getBoundingClientRect().height })));
  expect(after.map(box => box.y)).toEqual(before.map(box => box.y));
  expect(after.map(box => box.height)).toEqual(before.map(box => box.height));
  await expect(page.locator(".hashTable")).toHaveCSS("border-top-width", "1px");
});
}
