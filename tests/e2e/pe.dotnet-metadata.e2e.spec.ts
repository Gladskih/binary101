"use strict";

import { expect, test } from "@playwright/test";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

const findAssembly = (): string | null => {
  const requested = process.env["BINARY101_DOTNET_ASSEMBLY"];
  if (requested) return existsSync(requested) ? requested : null;
  const root = join(process.env["ProgramFiles"] ?? "C:\\Program Files", "dotnet", "shared", "Microsoft.NETCore.App");
  if (!existsSync(root)) return null;
  const version = readdirSync(root).sort((left, right) => right.localeCompare(left, "en", { numeric: true }))[0];
  if (!version) return null;
  return existsSync(join(root, version, "System.Collections.dll"))
    ? join(root, version, "System.Collections.dll") : null;
};

test("shows additional CLR metadata from an installed assembly in the browser", async ({ page }) => {
  const assembly = findAssembly();
  test.skip(!assembly, "Requires an installed .NET assembly or BINARY101_DOTNET_ASSEMBLY.");
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/");
  await page.setInputFiles("#fileInput", assembly!);
  const clr = page.locator("section.peSection").filter({
    has: page.locator("summary", { hasText: /^CLR\b/ })
  });
  await clr.locator(":scope > details > summary").click();
  const properties = clr.locator("details").filter({
    has: page.locator(":scope > summary", { hasText: /^Property \(/ })
  });
  await properties.locator(":scope > summary").click();
  await expect(properties.getByRole("button", { name: "Sort by Name", exact: true })).toBeVisible();
  await expect(properties.getByRole("button", { name: "Sort by Type", exact: true })).toBeVisible();
  await expect(properties.locator("tbody tr").first()).toContainText("ResourceManager");
  await expect(clr.locator("summary").filter({ hasText: /^GenericParam \(/ })).toBeVisible();
  await expect(clr.locator("summary").filter({ hasText: /^TypeSpec \(/ })).toBeVisible();
  const specifications = clr.locator("details").filter({
    has: page.locator(":scope > summary", { hasText: /^TypeSpec \(/ })
  });
  await specifications.locator(":scope > summary").click();
  await expect(specifications.locator("tbody tr").first().locator("td").first()).toHaveText("1");
  await specifications.getByRole("button", { name: "Next", exact: true }).click();
  await expect(specifications.locator("tbody tr").first().locator("td").first()).toHaveText("81");
  expect(errors).toEqual([]);
});

test("resolves external enum values from a locally selected dependency assembly", async ({ page }) => {
  const framework = join(process.env["WINDIR"] ?? "C:\\Windows", "Microsoft.NET", "Framework64", "v4.0.30319");
  const application = join(framework, "Microsoft.Build.Framework.dll");
  const dependency = join(framework, "mscorlib.dll");
  test.skip(!existsSync(application) || !existsSync(dependency), "Requires installed .NET Framework assemblies.");
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/");
  await page.setInputFiles("#fileInput", application);
  const clr = page.locator("section.peSection").filter({
    has: page.locator("summary", { hasText: /^CLR\b/ })
  });
  await clr.locator(":scope > details > summary").click();
  const security = clr.locator("details").filter({
    has: page.locator(":scope > summary", { hasText: /^DeclSecurity \(/ })
  });
  await security.locator(":scope > summary").click();
  await expect(security).toContainText("underlying type is unresolved");
  await page.getByLabel("Load assembly dependencies").setInputFiles(dependency);
  await expect(page.locator("#statusMessage")).toHaveText("Loaded 1 local assembly dependencies.");
  await expect(security).not.toContainText("underlying type is unresolved");
  await expect(security).toContainText("Flags");
  await expect(security).toContainText("8");
  await expect(security).toHaveAttribute("open", "");
  expect(errors).toEqual([]);
});
