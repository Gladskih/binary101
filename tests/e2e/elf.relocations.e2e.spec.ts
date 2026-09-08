import { expect, test } from "@playwright/test";
import { createElfNativeAotFixture } from "../helpers/elf-native-aot-fixture.js";

const pagedRelocations = (): Buffer => {
  const fixture = createElfNativeAotFixture();
  const bytes = Buffer.alloc(fixture.bytes.length + 201 * 24);
  bytes.set(fixture.bytes);
  const tableOffset = fixture.bytes.length;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // gABI Elf64_Phdr.p_filesz/p_memsz and Elf64_Shdr.sh_offset/sh_size.
  view.setBigUint64(64 + 32, BigInt(bytes.length), true);
  view.setBigUint64(64 + 40, BigInt(bytes.length), true);
  view.setBigUint64(fixture.sectionHeaderOffset + 64 + 24, BigInt(tableOffset), true);
  view.setBigUint64(fixture.sectionHeaderOffset + 64 + 32, 201n * 24n, true);
  for (let index = 0; index < 201; index += 1) {
    view.setBigUint64(tableOffset + index * 24, BigInt(fixture.modulePointerAddress), true);
    view.setBigUint64(tableOffset + index * 24 + 8, 8n, true); // R_X86_64_RELATIVE.
    view.setBigInt64(tableOffset + index * 24 + 16, BigInt(index), true);
  }
  return bytes;
};

test("ELF relocation rows paginate and sort in the browser", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "relocations.elf", mimeType: "application/x-elf", buffer: pagedRelocations()
  });
  const table = page.locator('[data-paged-sortable-table-id="elf-relocations"]');

  await expect(table).toContainText("R_X86_64_RELATIVE");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await table.getByRole("button", { name: "Next", exact: true }).click();
  await expect(table).toContainText("Showing 101-200 of 201");
  await table.getByRole("button", { name: "Sort by Addend", exact: true }).click();
  await table.getByRole("button", { name: "Sort by Addend", exact: true }).click();
  await expect(table.locator("tbody tr").first().locator("td").nth(5)).toHaveText("200");
});
