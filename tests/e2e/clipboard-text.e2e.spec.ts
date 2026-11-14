import { expect, test } from "@playwright/test";

test("paste lists all representations and waits for the selected content", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => {
    const clipboardData = new DataTransfer();
    clipboardData.setData("text/html", "<b>clipboard text</b>");
    clipboardData.setData("text/uri-list", "https://example.test/");
    clipboardData.setData("text/plain", "clipboard text");
    globalThis.dispatchEvent(new ClipboardEvent("paste", { clipboardData }));
  });
  const chooser = page.getByRole("dialog", { name: "Clipboard contents" });
  await expect(chooser).toBeVisible();
  await expect(chooser.locator("tbody tr")).toHaveCount(3);
  await expect(page.locator("#fileInfoCard")).toBeHidden();
  await chooser.getByRole("button", { name: /^Analyze text\/plain:/ }).click();
  await expect(chooser).toHaveCount(0);
  await expect(page.locator("#fileInfoCard")).toBeVisible();
  await expect(page.locator("#fileNameDetail")).toHaveText("clipboard.bin");
  await expect(page.locator("#fileSizeDetail")).toContainText("14");
});

test("mixed file and text clipboard data lets the user choose the actual file", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => {
    const clipboardData = new DataTransfer();
    clipboardData.items.add(new File(["file bytes"], "sample.bin"));
    clipboardData.setData("text/plain", "file name or description");
    globalThis.dispatchEvent(new ClipboardEvent("paste", { clipboardData }));
  });
  const chooser = page.getByRole("dialog", { name: "Clipboard contents" });
  await expect(chooser.locator("tbody tr")).toHaveCount(2);
  await chooser.locator("tr").filter({ hasText: "sample.bin" }).getByRole("button").click();
  await expect(page.locator("#fileNameDetail")).toHaveText("sample.bin");
  await expect(page.locator("#fileSizeDetail")).toContainText("10");
});

test("keyboard selection can analyze the HTML representation", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => {
    const clipboardData = new DataTransfer();
    clipboardData.setData("text/plain", "hello");
    clipboardData.setData("text/html", "<b>hello</b>");
    globalThis.dispatchEvent(new ClipboardEvent("paste", { clipboardData }));
  });
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await expect(page.locator("#fileSizeDetail")).toContainText("12");
});

test("unreadable clipboard entries remain visible and cancellation opens nothing", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => {
    const event = new Event("paste");
    Object.defineProperty(event, "clipboardData", { value: { items: [
      { kind: "string", type: "text/plain",
        getAsString: (callback: (text: string) => void) => { callback("readable"); } },
      { kind: "file", type: "application/private" }
    ] } });
    globalThis.dispatchEvent(event);
  });
  const chooser = page.getByRole("dialog", { name: "Clipboard contents" });
  await expect(chooser.locator("tbody tr")).toHaveCount(2);
  await expect(chooser.getByRole("button", { name: /Analyze application\/private/ })).toBeDisabled();
  await chooser.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(chooser).toHaveCount(0);
  await expect(page.locator("#fileInfoCard")).toBeHidden();
});

for (const width of [390, 1280]) {
  for (const colorScheme of ["light", "dark"] as const) {
    test(`clipboard choice is safe and accessible at ${width}px in ${colorScheme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme });
      await page.goto("/");
      await page.evaluate(() => {
        const clipboardData = new DataTransfer();
        clipboardData.setData("text/plain", "Ordinary text");
        clipboardData.setData("text/html", '<img src="invalid" onerror="alert(1)">');
        globalThis.dispatchEvent(new ClipboardEvent("paste", { clipboardData }));
      });
      const chooser = page.getByRole("dialog", { name: "Clipboard contents" });
      await expect(chooser).toBeVisible();
      await expect(chooser.locator("img")).toHaveCount(0);
      await expect(chooser).toContainText('<img src="invalid"');
      await page.locator("html").evaluate(element => { element.style.zoom = "2"; });
      expect(await chooser.evaluate(element => {
        const bounds = element.getBoundingClientRect();
        const viewport = element.ownerDocument.defaultView!;
        return bounds.left >= 0 && bounds.right <= viewport.innerWidth &&
          bounds.top >= 0 && bounds.bottom <= viewport.innerHeight;
      })).toBe(true);
      await page.locator("html").evaluate(element => { element.style.zoom = "1"; });
      await page.screenshot({ path: `test-results/clipboard-${width}-${colorScheme}.png` });
      await page.keyboard.press("Escape");
      await expect(chooser).toHaveCount(0);
      await expect(page.locator("#fileInfoCard")).toBeHidden();
    });
  }
}

test("a newer paste replaces the pending choice", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => {
    const clipboardData = new DataTransfer();
    clipboardData.setData("text/html", "<b>older</b>");
    clipboardData.setData("text/plain", "older");
    globalThis.dispatchEvent(new ClipboardEvent("paste", { clipboardData }));
  });
  await expect(page.getByRole("dialog", { name: "Clipboard contents" })).toBeVisible();
  await page.evaluate(() => {
    const clipboardData = new DataTransfer();
    clipboardData.setData("text/plain", "new");
    globalThis.dispatchEvent(new ClipboardEvent("paste", { clipboardData }));
  });
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("#fileNameDetail")).toHaveText("clipboard.bin");
  await expect(page.locator("#fileSizeDetail")).toContainText("3");
});

test("late clipboard reads cannot replace a newer paste", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => {
    const event = new Event("paste");
    Object.defineProperty(event, "clipboardData", { value: { items: [{ kind: "string",
      getAsString: (callback: (text: string) => void) => {
        globalThis.addEventListener("completeClipboardRead",
          () => callback("older and longer"), { once: true });
      } }] } });
    globalThis.dispatchEvent(event);
    const clipboardData = new DataTransfer();
    clipboardData.setData("text/plain", "new");
    globalThis.dispatchEvent(new ClipboardEvent("paste", { clipboardData }));
  });
  await expect(page.locator("#fileSizeDetail")).toContainText("3");
  await page.evaluate(() => { globalThis.dispatchEvent(new Event("completeClipboardRead")); });
  await expect(page.locator("#fileSizeDetail")).toContainText("3");
});
