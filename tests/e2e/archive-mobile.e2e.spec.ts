import { expect, test, type Locator } from "@playwright/test";
import { createZipWithEntries } from "../fixtures/zip-fixtures.js";
import { openInspectionSection } from "./inspection-navigation.js";

const scrollToArchiveAction = (action: Locator): Promise<boolean> => action.evaluate(element => {
  for (let parent = element.parentElement; parent; parent = parent.parentElement) {
    if (parent.scrollWidth > parent.clientWidth &&
      /auto|scroll/.test(parent.ownerDocument.defaultView!.getComputedStyle(parent).overflowX)) {
      parent.scrollLeft = parent.scrollWidth;
      return parent.scrollLeft > 0;
    }
  }
  return false;
});

for (const width of [320, 390]) {
  test(`archive actions remain reachable by horizontal scrolling at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await page.goto("/");
    const zip = createZipWithEntries();
    await page.setInputFiles("#fileInput", { name: zip.name, mimeType: zip.type,
      buffer: Buffer.from(zip.data) });
    await openInspectionSection(page, "Central directory entries");
    const action = page.locator(".zipExtractButton").first();
    await page.locator(".workspaceViewport").scrollIntoViewIfNeeded();
    expect(await scrollToArchiveAction(action)).toBe(true);
    await expect(action).toBeInViewport();
    const download = page.waitForEvent("download");
    await action.click();
    expect((await download).suggestedFilename()).toBe("stored.txt");
    expect(await page.locator("html").evaluate(element => element.scrollWidth))
      .toBeLessThanOrEqual(width);
  });
}
