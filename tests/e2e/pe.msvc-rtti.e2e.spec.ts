import { expect, test } from "@playwright/test";
import { MsvcRttiPeFixtureBuilder } from "../fixtures/pe-msvc-rtti-fixture.js";

const fixtureBytes = () => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const base = builder.addHierarchy(builder.addType(".?AUBase@demo@@"));
  const derived = builder.addHierarchy(builder.addType(".?AV?$Box@H@demo@@"), [{ hierarchy: base }]);
  builder.addVftable(derived, [builder.allocateFunctionTarget()]);
  return Buffer.from(builder.build().bytes);
};

test("MSVC RTTI loads local LLVM WASM and keeps type names through remount", async ({ page }) => {
  const wasmUrls: string[] = [];
  page.on("request", request => {
    if (request.url().includes("llvm-msvc-demangle") && request.url().endsWith(".wasm")) {
      wasmUrls.push(request.url());
    }
  });
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "msvc-rtti.exe", mimeType: "application/octet-stream", buffer: fixtureBytes()
  });
  const section = page.locator("section.peSection").filter({
    has: page.locator("summary", { hasText: "Microsoft C++ RTTI" })
  });
  await section.locator("summary").first().click();
  await expect(section).toContainText("class demo::Box<int>");
  await expect(section).toContainText(".?AV?$Box@H@demo@@");
  await section.getByText("Show inheritance and 1 vftable slot(s)", { exact: true }).click();
  await expect(section).toContainText("struct demo::Base");
  await section.locator("summary").first().click();
  await section.locator("summary").first().click();
  await expect(section).toContainText("class demo::Box<int>");
  expect(wasmUrls).toHaveLength(1);
  expect(new URL(wasmUrls[0]!).origin).toBe(new URL(page.url()).origin);
});

test("MSVC RTTI reports a failed WASM load and recovers on the next file", async ({ page }) => {
  await page.route("**/*llvm-msvc-demangle*.wasm", route => route.abort());
  await page.goto("/");
  const file = { name: "msvc-rtti.exe", mimeType: "application/octet-stream", buffer: fixtureBytes() };
  await page.setInputFiles("#fileInput", file);
  const section = page.locator("section.peSection").filter({
    has: page.locator("summary", { hasText: "Microsoft C++ RTTI" })
  });
  await section.locator("summary").first().click();
  await expect(section).toContainText("MSVC RTTI name analysis failed:");
  await page.unroute("**/*llvm-msvc-demangle*.wasm");
  await page.setInputFiles("#fileInput", file);
  await section.locator("summary").first().click();
  await expect(section).toContainText("class demo::Box<int>");
});
