import { expect, test } from "@playwright/test";

for (const colorScheme of ["dark", "light"] as const) {
  for (const width of [320, 1640, 2560]) {
    test(`file selection stays together at ${width}px in ${colorScheme}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme });
      await page.setViewportSize({ width, height: 720 });
      await page.goto("/");
      const drop = (await page.locator("#dropZone").boundingBox())!;
      const privacy = (await page.locator(".selectionPrivacy").boundingBox())!;
      const header = (await page.locator(".appHeader").boundingBox())!;

      expect(privacy.x + privacy.width / 2).toBeCloseTo(drop.x + drop.width / 2, 0);
      expect(drop.x + drop.width / 2).toBeCloseTo(width / 2, 0);
      expect(header.x + header.width / 2).toBeCloseTo(width / 2, 0);
      expect(privacy.y - drop.y - drop.height).toBeCloseTo(12, 0);
      expect(privacy.x).toBeGreaterThanOrEqual(drop.x);
      expect(privacy.x + privacy.width).toBeLessThanOrEqual(drop.x + drop.width);
      expect(await page.locator("html").evaluate(element => element.scrollWidth))
        .toBeLessThanOrEqual(width);
      await page.locator("#statusMessage").evaluate(element => {
        element.textContent = "Unable to open folder: access denied.";
      });
      const status = (await page.locator("#statusMessage").boundingBox())!;
      expect(status.x + status.width / 2).toBeCloseTo(width / 2, 0);
      await page.locator("#fileInput").setInputFiles({ name: "sample.txt", mimeType: "text/plain",
        buffer: Buffer.from("sample") });
      await expect(page.locator("#dropZone")).toBeHidden();
      await expect(page.locator(".selectionPrivacy")).toBeHidden();
      await page.locator("body").evaluate(element => element.classList.add("draggingFiles"));
      await expect(page.locator("#dropZone")).toBeVisible();
      await expect(page.locator(".selectionPrivacy")).toBeHidden();
    });
  }
}
