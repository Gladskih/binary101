import { expect, test } from "@playwright/test";
import { createPeItaniumFixture } from "../fixtures/pe-itanium-rtti.js";

test("PE Itanium RTTI opens and survives lazy section remount", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "itanium.exe",
    mimeType: "application/octet-stream", buffer: Buffer.from(createPeItaniumFixture().bytes) });
  const section = page.locator("section.peSection").filter({
    has: page.locator("summary", { hasText: "Itanium C++ RTTI" })
  });
  await section.locator("summary").click();
  await expect(section).toContainText("7Derived");
  await expect(section).toContainText("Virtual: vtable slot");
  await expect(section.locator("table")).toHaveCount(2);
  await section.locator("summary").click();
  await section.locator("summary").click();
  await expect(section).toContainText("8Multiple");
});
