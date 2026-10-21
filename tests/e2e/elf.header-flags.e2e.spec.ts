import { expect, test } from "@playwright/test";
import { createElfFile } from "../fixtures/elf-sample-file.js";

for (const width of [390, 1280]) {
  test(`ELF flags expose all choices and keyboard help at width ${width}`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    const bytes = createElfFile().data;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // RISC-V psABI e_machine=243, e_flags=RVC|FLOAT_ABI_QUAD|TSO plus unknown bit 31.
    // https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#-file-header
    view.setUint16(18, 243, true);
    view.setUint32(48, 0x80000017, true);
    await page.setViewportSize({ width, height: 720 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", {
      name: "riscv-flags.elf", mimeType: "application/x-elf", buffer: Buffer.from(bytes)
    });
    await page.locator("summary").filter({ hasText: /^ELF header$/ }).click();
    const term = page.locator("dt").filter({ hasText: /^Flags \(e_flags\)/ });
    await expect(term).toBeVisible();
    const flags = term.locator("+ dd");
    await expect(flags.locator("code")).toHaveText("0x80000017");
    await expect(flags.locator(".opt")).toHaveCount(8);
    await expect(flags.locator(".opt.sel")).toHaveCount(4);
    await expect(flags.locator(".opt.dim")).toHaveCount(4);
    const quad = flags.locator(".opt").filter({ hasText: /^EF_RISCV_FLOAT_ABI_QUAD/ });
    await expect(quad).toHaveClass("opt sel");
    const help = quad.getByRole("button");
    await expect(help).toBeVisible();
    expect(await help.evaluate(element =>
      element.ownerDocument.defaultView!.getComputedStyle(element, "::before").content)).toBe('"?"');
    await help.focus();
    await page.keyboard.press("Enter");
    await expect(help).toHaveAttribute("aria-expanded", "true");
    await expect(quad.getByRole("tooltip")).toBeVisible();
    await expect(quad.getByRole("tooltip")).toHaveAttribute("aria-label", /quad-precision/);
    await page.keyboard.press("Escape");
    await expect(help).toHaveAttribute("aria-expanded", "false");
    const unknown = flags.locator(".opt").filter({ hasText: /^UNKNOWN_BITS_/ });
    await expect(unknown).toContainText("0x80000000");
    await unknown.getByRole("button").click();
    await expect(unknown.getByRole("tooltip")).toBeVisible();
    await expect(unknown.getByRole("tooltip")).toHaveAttribute("aria-label", /no known meaning/);
    expect(await page.locator("html").evaluate(element =>
      element.scrollWidth <= element.ownerDocument.defaultView!.innerWidth)).toBe(true);
    expect(errors).toEqual([]);
  });
}
