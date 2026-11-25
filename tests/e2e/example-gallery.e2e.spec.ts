import { existsSync } from "node:fs";
import { expect, test } from "@playwright/test";

test.skip(!process.env["CI"] && !existsSync("generated/gallery/hello-samples.zip"),
  "Build the gallery assets before running these tests locally.");

const examples = [
  ["PE · C / MSVC", "hello-msvc-x64.exe", /PE/],
  ["PE · x86 assembly", "hello-masm-x86.exe", /PE/],
  ["PE · Go", "hello-go-x64.exe", /PE/],
  ["PE · C#", "HelloCSharp.dll", /PE/],
  ["ELF · C / GCC", "hello-gcc-x64.elf", /ELF/],
  ["ELF · Go", "hello-go-arm64.elf", /ELF/],
  ["WebAssembly", "hello.wasm", /WebAssembly/i],
  ["ZIP", "hello-samples.zip", /ZIP/i],
  ["SQLite", "hello.sqlite", /SQLite/i],
  ["PNG", "test-pattern.png", /PNG/],
  ["JPEG", "test-pattern.jpg", /JPEG/],
  ["GIF", "test-pattern.gif", /GIF/],
  ["PDF", "hello.pdf", /PDF/],
  ["WebM", "test-pattern.webm", /WebM/]
] as const;

test("opens every generated example directly from the welcome screen", async ({ page }) => {
  const binaryRequests: string[] = [];
  page.on("request", request => {
    if (request.headers()["accept"] === "application/octet-stream") {
      binaryRequests.push(request.url());
    }
  });
  for (const [label, name, type] of examples) {
    await page.goto("/");
    const examplesOnWelcome = page.getByRole("region", { name: "Examples" });
    await expect(examplesOnWelcome.getByRole("button")).toHaveCount(examples.length);
    await expect(page.getByRole("button", { name: "Browse examples" })).toBeHidden();
    await examplesOnWelcome.getByRole("button", { name: label, exact: true }).click();
    await expect(page.locator("#fileNameDetail")).toHaveText(name);
    await expect(page.locator("#fileBinaryTypeDetail")).toHaveText(type);
    await expect(page.locator("#fileSourceDetail .opt.sel")).toHaveText("Example");
    await expect(page.locator("#analysisValue > :not([hidden])").first()).toBeAttached();
  }
  expect(binaryRequests).toHaveLength(examples.length);
});

test("browses examples while inspecting a file", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "PNG", exact: true }).click();
  await expect(page.locator("#fileNameDetail")).toHaveText("test-pattern.png");
  const browse = page.getByRole("button", { name: "Browse examples" });
  const gallery = page.getByRole("dialog", { name: "Examples" });
  await browse.click();
  await expect(gallery.getByRole("button", { name: "Close" })).toBeFocused();
  await expect(gallery.locator("tbody tr")).toHaveCount(examples.length);
  await page.keyboard.press("Escape");
  await expect(browse).toBeFocused();
  await browse.click();
  await gallery.getByRole("button", { name: "JPEG", exact: true }).click();
  await expect(page.locator("#fileNameDetail")).toHaveText("test-pattern.jpg");
});

const failedResponses = {
  "a missing asset": { status: 404, body: "Missing", contentType: "text/plain" },
  "an HTML fallback": { status: 200, body: "<title>Missing</title>", contentType: "text/html" },
  "an empty asset": { status: 200, body: "", contentType: "application/octet-stream" }
};

for (const [failure, response] of Object.entries(failedResponses)) {
  test(`reports ${failure} and allows retry`, async ({ page }) => {
    await page.route("**/hello-*.wasm", route => route.fulfill(response));
    await page.goto("/");
    const gallery = page.getByRole("region", { name: "Examples" });
    const sample = gallery.getByRole("button", { name: "WebAssembly", exact: true });
    await sample.click();
    await expect(gallery.getByRole("status")).toHaveText("Unable to open hello.wasm. Try again.");
    await expect(page.locator("#fileInfoCard")).toBeHidden();
    await page.unroute("**/hello-*.wasm");
    await sample.click();
    await expect(page.locator("#analysisValue")).toContainText("WebAssembly");
  });
}

test("closing the gallery cancels the pending selection", async ({ page }) => {
  const request = Promise.withResolvers<void>();
  const response = Promise.withResolvers<void>();
  await page.route("**/hello-*.wasm", async route => {
    request.resolve();
    await response.promise;
    await route.continue();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "PNG", exact: true }).click();
  await expect(page.locator("#fileNameDetail")).toHaveText("test-pattern.png");
  const browse = page.getByRole("button", { name: "Browse examples" });
  await browse.click();
  const gallery = page.getByRole("dialog", { name: "Examples" });
  await gallery.getByRole("button", { name: "WebAssembly", exact: true }).click();
  await request.promise;
  await expect(gallery.getByRole("status")).toHaveText("Loading hello.wasm…");
  const cancelled = page.waitForEvent("requestfailed", {
    predicate: request => request.url().includes(".wasm"), timeout: 5000
  });
  await page.keyboard.press("Escape");
  await cancelled;
  response.resolve();
  await expect(page.locator("#fileNameDetail")).toHaveText("test-pattern.png");
  await browse.click();
  await expect(gallery.getByRole("status")).toBeEmpty();
});

test("opening a local file cancels a pending welcome example", async ({ page }) => {
  const response = Promise.withResolvers<void>();
  await page.route("**/hello-*.wasm", async route => {
    await response.promise;
    await route.continue();
  });
  await page.goto("/");
  const sample = page.getByRole("button", { name: "WebAssembly", exact: true });
  await sample.click();
  await expect(sample).toHaveAttribute("aria-disabled", "true");
  const cancelled = page.waitForEvent("requestfailed", {
    predicate: request => request.url().includes(".wasm"), timeout: 5000
  });
  await page.setInputFiles("#fileInput", {
    name: "local.txt", mimeType: "text/plain", buffer: Buffer.from("local file")
  });
  await cancelled;
  response.resolve();
  await expect(page.locator("#fileNameDetail")).toHaveText("local.txt");
  await expect(page.locator("#fileSourceDetail .opt.sel")).toHaveText("Selection");
});

for (const colorScheme of ["light", "dark"] as const) {
  test(`keyboard scrolls the gallery in a narrow ${colorScheme} viewport`, async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 425 });
    await page.emulateMedia({ colorScheme });
    await page.goto("/");
    const gallery = page.getByRole("region", { name: "Examples" });
    await gallery.getByRole("button", { name: examples[0][0], exact: true }).focus();
    for (const [label] of examples.slice(1)) {
      await page.keyboard.press("Tab");
      await expect(gallery.getByRole("button", { name: label, exact: true })).toBeFocused();
    }
    const list = gallery.getByRole("list");
    expect(await list.evaluate(element => element.scrollWidth - element.clientWidth)).toBe(0);
    await expect(gallery.getByRole("button", { name: "WebM" })).toBeInViewport();
    await page.keyboard.press("Enter");
    await expect(page.locator("#fileNameDetail")).toHaveText("test-pattern.webm");
    await expect(page.locator("#analysisValue")).toContainText(/VP8/);
    await expect(page.locator("#analysisValue")).toContainText(/Opus/i);
  });
}
