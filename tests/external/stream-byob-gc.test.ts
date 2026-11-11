import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { chromium, type Page } from "@playwright/test";
import { ModuleKind, ScriptTarget, transpileModule } from "typescript";
import type { readByobChunk } from "../../analyzers/stream-byob.js";

// Playwright callbacks execute in the page realm. The fixture installs readByobTest
// there, and each probe initializes its fields before the test reads them back.
type GcTestScope = typeof globalThis & {
  readByobTest: typeof readByobChunk;
  completed: boolean;
  bytesRead: number;
  readError?: string;
  observedReader: WeakRef<ReadableStreamBYOBReader>;
};

const withGcPage = async (check: (page: Page) => Promise<void>): Promise<void> => {
  const browser = await chromium.launch({
    ...process.env["CHROMIUM_CHANNEL"] && { channel: process.env["CHROMIUM_CHANNEL"] },
    args: ["--js-flags=--expose-gc"]
  });
  try {
    const page = await browser.newPage();
    await page.goto("about:blank");
    await page.addScriptTag({ type: "module", content: transpileModule(
      await readFile(new URL("../../analyzers/stream-byob.ts", import.meta.url), "utf8"),
      { compilerOptions: { module: ModuleKind.ESNext, target: ScriptTarget.ES2022 } }
    ).outputText + "\nglobalThis.readByobTest = readByobChunk;" });
    await check(page);
  } finally { await browser.close(); }
};

const collectGarbage = async (): Promise<void> => {
  if (!globalThis.gc) throw new Error("Run Chromium with --js-flags=--expose-gc");
  await globalThis.gc({ type: "major", execution: "async" });
};

const startReadProbe = async (): Promise<void> => {
  const target = globalThis as GcTestScope;
  target.completed = false;
  target.bytesRead = 0;
  void (async () => {
    // A five-byte Blob already reproduces crbug.com/574627778.
    const reader = new Blob([new Uint8Array([1, 2, 3, 4, 5])])
      .stream().getReader({ mode: "byob" });
    target.observedReader = new WeakRef(reader);
    try {
      for (;;) {
        const result = await target.readByobTest(reader, new Uint8Array(64 * 1024));
        if (result.done) break;
        target.bytesRead += result.value.byteLength;
      }
      target.completed = true;
    } catch (error) { target.readError = String(error); }
    finally { reader.releaseLock(); }
  })();
  // Async major GC avoids retaining the reader via conservative stack scanning.
  // See crbug.com/574627778 and its regression test in CL 8612396.
  if (!globalThis.gc) throw new Error("Run Chromium with --js-flags=--expose-gc");
  await globalThis.gc({ type: "major", execution: "async" });
};

void test("native BYOB reading survives GC and releases its reader afterwards", () =>
  withGcPage(async page => {
    await page.evaluate(startReadProbe);
    await page.waitForFunction(() => (globalThis as GcTestScope).completed, null, { timeout: 5000 });
    assert.deepEqual(await page.evaluate(() => {
      const target = globalThis as GcTestScope;
      return { bytes: target.bytesRead, error: target.readError };
    }), { bytes: 5, error: undefined });
    await page.evaluate(collectGarbage);
    assert.equal(await page.evaluate(() =>
      (globalThis as GcTestScope).observedReader.deref() === undefined), true);
  }));

void test("a rejected BYOB read releases the retained reader", () =>
  withGcPage(async page => {
    await page.evaluate(async () => {
      const target = globalThis as GcTestScope;
      const reader = new Blob([]).stream().getReader({ mode: "byob" });
      target.observedReader = new WeakRef(reader);
      try { await target.readByobTest(reader, new Uint8Array(0)); }
      catch (error) { target.readError = error instanceof Error ? error.name : String(error); }
      finally { reader.releaseLock(); }
    });
    assert.equal(await page.evaluate(() => (globalThis as GcTestScope).readError), "TypeError");
    await page.evaluate(collectGarbage);
    assert.equal(await page.evaluate(() =>
      (globalThis as GcTestScope).observedReader.deref() === undefined), true);
  }));

void test("cancelling a pending BYOB read releases the retained reader", () =>
  withGcPage(async page => {
    await page.evaluate(async () => {
      const target = globalThis as GcTestScope;
      const reader = new Blob([new Uint8Array([1])]).stream().getReader({ mode: "byob" });
      target.observedReader = new WeakRef(reader);
      const pending = target.readByobTest(reader, new Uint8Array(8));
      await reader.cancel();
      target.completed = (await pending).done;
      reader.releaseLock();
    });
    assert.equal(await page.evaluate(() => (globalThis as GcTestScope).completed), true);
    await page.evaluate(collectGarbage);
    assert.equal(await page.evaluate(() =>
      (globalThis as GcTestScope).observedReader.deref() === undefined), true);
  }));
