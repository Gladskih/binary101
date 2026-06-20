import { expect, test } from "@playwright/test";

void test("marks a native hash fallback with a tooltip", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => {
    const file = new File(["abc"], "fallback.bin");
    Object.defineProperty(file, "arrayBuffer", {
      value: async () => { throw new DOMException("too large", "NotReadableError"); }
    });
    Object.defineProperty(file, "stream", { value: () => new Blob(["abc"]).stream() });
    const event = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(event, "dataTransfer", {
      value: {
        files: { length: 1, item: () => file },
        items: { length: 0, item: () => null }
      }
    });
    globalThis.document.getElementById("dropZone")?.dispatchEvent(event);
  });
  await expect(page.locator("#fileNameDetail")).toHaveText("fallback.bin");
  await page.locator("#hashDetails > summary").click();
  await page.getByRole("button", { name: "Compute SHA-256" }).click();
  await expect(page.locator("#sha256NativeBadge")).toHaveText("🍂");
  await page.locator("#sha256NativeBadge").click();
  await expect(page.locator("#sha256NativeBadge ~ .accessibleTooltipPopup")).toHaveAttribute(
    "aria-label",
    "Native crypto failed; fallback used."
  );
});
