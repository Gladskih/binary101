import { expect, test } from "@playwright/test";

const algorithms = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512224", "sha512256"];

test("hash computation keeps every row and following element in place", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "hash.txt", mimeType: "text/plain",
    buffer: Buffer.from("stable hash geometry") });
  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
  await page.locator("#fileHashesButton").click();
  const before = await page.locator("#hashDetails dt, #hashDetails dd").evaluateAll(elements =>
    elements.map(element => ({ y: element.getBoundingClientRect().y,
      height: element.getBoundingClientRect().height })));

  for (const id of algorithms) {
    await page.locator(`#${id}ComputeButton`).click();
    await expect(page.locator(`#${id}Value`)).not.toHaveText("");
  }

  const after = await page.locator("#hashDetails dt, #hashDetails dd").evaluateAll(elements =>
    elements.map(element => ({ y: element.getBoundingClientRect().y,
      height: element.getBoundingClientRect().height })));
  expect(after.map(box => box.y)).toEqual(before.map(box => box.y));
  expect(after.map(box => box.height)).toEqual(before.map(box => box.height));
  await expect(page.locator("#hashDetails")).toHaveCSS("border-top-width", "0px");
});
