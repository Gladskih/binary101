import { openInspectionSection } from "./inspection-navigation.js";
"use strict";

import { expect, test } from "@playwright/test";
import { createPePlusWithSection } from "../fixtures/sample-files-pe.js";
import { NARROW_LAYOUT_VIEWPORT } from "./viewports.js";

const createVersionedPe = (subsystem: number): Uint8Array => {
  const bytes = createPePlusWithSection();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // Microsoft PE format: e_lfanew, PE signature (4), COFF header (20),
  // then OS version at optional-header +40, subsystem version +48, subsystem +68.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const optionalOffset = view.getUint32(0x3c, true) + 4 + 20;
  view.setUint16(optionalOffset + 40, 10, true);
  view.setUint16(optionalOffset + 42, 0, true);
  view.setUint16(optionalOffset + 48, 5, true);
  view.setUint16(optionalOffset + 50, 2, true);
  view.setUint16(optionalOffset + 68, subsystem, true);
  return bytes;
};

void test("explains PE versions as wrapping text on a narrow screen", async ({ page }) => {
  await page.setViewportSize(NARROW_LAYOUT_VIEWPORT);
  await page.goto("/");
  // Microsoft PE format: 3 = Windows CUI.
  await page.setInputFiles("#fileInput", {
    name: "versions.exe", mimeType: "application/octet-stream",
    buffer: Buffer.from(createVersionedPe(3))
  });
  await openInspectionSection(page, "PE/COFF headers");
  await expect(page.locator("dt").filter({ hasText: /^LinkerVersion$/ }).locator("+ dd"))
    .toHaveText(
      "14.0 (possible: Microsoft LINK (Visual Studio 2015 toolset) / " +
      "LLVM lld-link (compatibility value))"
    );
  const osVersion = page.locator("dt").filter({ hasText: /^OperatingSystemVersion$/ })
    .locator("+ dd");
  const subsystemVersion = page.locator("dt").filter({ hasText: /^SubsystemVersion$/ })
    .locator("+ dd");
  await expect(osVersion).toHaveText(
    "10.0 (Windows 10 / Windows 11 / Windows Server 2016 / Windows Server 2019 / " +
    "Windows Server 2022 / Windows Server 2025)"
  );
  await expect(subsystemVersion).toHaveText(
    "5.2 (Windows CUI subsystem; Windows XP Professional x64 Edition / " +
    "Windows XP 64-Bit Edition Version 2003 (Itanium) / Windows Server 2003 / " +
    "Windows Server 2003 R2 / Windows Home Server)"
  );
  await expect(subsystemVersion.locator(".opt")).toHaveCount(0);
  expect(await osVersion.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
  expect(await subsystemVersion.evaluate(element =>
    element.scrollWidth <= element.clientWidth)).toBe(true);
});

void test("uses the selected EFI subsystem without desktop Windows labels", async ({ page }) => {
  await page.goto("/");
  // Microsoft PE format: 10 = EFI Application.
  await page.setInputFiles("#fileInput", {
    name: "versions.efi", mimeType: "application/octet-stream",
    buffer: Buffer.from(createVersionedPe(10))
  });
  await openInspectionSection(page, "PE/COFF headers");
  await expect(page.locator("dt").filter({ hasText: /^OperatingSystemVersion$/ })
    .locator("+ dd")).toHaveText("10.0");
  await expect(page.locator("dt").filter({ hasText: /^SubsystemVersion$/ })
    .locator("+ dd")).toHaveText(
    "5.2 (EFI Application subsystem; not a UEFI specification revision)"
  );
});
