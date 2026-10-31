import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { embeddedResourceFixture } from "../fixtures/embedded-resource-builders.js";

for (const [name, width] of [["qt-glib.dll", 1280], ["qt-glib.so", 1280],
  ["qt-glib.dll", 390], ["qt-glib.so", 390]] as const) {
  test(`previews and extracts Qt and GLib resources in ${name} at ${width}px`, async ({ page }, info) => {
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await page.locator("#fileInput").setInputFiles({ name, mimeType: "application/octet-stream",
      buffer: Buffer.from(embeddedResourceFixture(name)) });
    const section = page.locator("section.peSection").filter({ has:
      page.locator("summary", { hasText: /^Qt \/ GLib embedded resources$/ }) });
    await section.locator(":scope > details > summary").click();
    await expect(section.getByRole("heading", { name: /^Qt RCC/ })).toHaveCount(2);
    await expect(section.getByRole("heading", { name: /^GLib GResource/ })).toHaveCount(2);
    await expect(section).toContainText("Binary101 resource oracle");
    await expect(section).toContainText("zstd");
    await expect(section).toContainText("zlib");
    await section.screenshot({ path: info.outputPath("resource-section.png") });
    const pending = page.waitForEvent("download");
    await section.locator('button[data-embedded-resource-entry="3"]').first().click();
    const download = await pending;
    expect(download.suggestedFilename()).toBe("message.txt");
    expect(await readFile((await download.path())!, "utf8")).toBe("Binary101 resource oracle ".repeat(50));
    expect(errors).toEqual([]);
  });
}
