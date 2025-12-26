"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../analyzers/index.js";
import { createGzipClickHandler } from "../../ui/gzip-actions.js";
import { createGzipFile } from "../fixtures/gzip-fixtures.js";
import { encoder } from "../fixtures/archive-fixture-helpers.js";
import { installGzipActionsDomStubs } from "../helpers/gzip-actions-dom-stubs.js";

void test("gzip click handler ignores unrelated clicks", async () => {
  const stubs = installGzipActionsDomStubs();
  try {
    const handler = createGzipClickHandler({
      getParseResult: () => ({ analyzer: "gzip", parsed: {} } as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    await handler({ target: {} } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), []);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});

void test("gzip click handler reports non-gzip selections", async () => {
  const stubs = installGzipActionsDomStubs();
  try {
    const handler = createGzipClickHandler({
      getParseResult: () => ({ analyzer: "zip", parsed: {} } as unknown as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["Not a gzip file."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});

void test("gzip click handler reports missing file selection", async () => {
  const stubs = installGzipActionsDomStubs();
  try {
    const handler = createGzipClickHandler({
      getParseResult: () => ({ analyzer: "gzip", parsed: {} } as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["No file selected."]);
  } finally {
    stubs.restore();
  }
});

void test("gzip click handler hides decompression when DecompressionStream is unavailable", async () => {
  const stubs = installGzipActionsDomStubs();
  const globals = globalThis as unknown as Record<string, unknown>;
  try {
    globals["DecompressionStream"] = undefined;

    const payload = encoder.encode("hello");
    const file = createGzipFile({ payload });

    const handler = createGzipClickHandler({
      getParseResult: () => ({ analyzer: "gzip", parsed: {} } as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    const button = stubs.getButton();
    button.textContent = "Decompress";

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["Browser does not support DecompressionStream; cannot decompress gzip."]);
    assert.equal(button.disabled, false);
    assert.equal(button.textContent, "Decompress");
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});

void test("gzip click handler downloads decompressed blob using header filename", async () => {
  const stubs = installGzipActionsDomStubs();
  try {
    const payload = encoder.encode("hello");
    const file = createGzipFile({ payload, name: "ignored.gz", filename: null, comment: null, extra: null, includeHeaderCrc16: false });

    const parseResult: ParseForUiResult = {
      analyzer: "gzip",
      parsed: { header: { fileName: "folder/hello.txt" } }
    } as unknown as ParseForUiResult;

    const handler = createGzipClickHandler({
      getParseResult: () => parseResult,
      getFile: () => file as unknown as File,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    await handler({ target: stubs.getChild() } as unknown as Event);

    const anchor = stubs.getAnchor();
    assert.ok(anchor);
    assert.equal(anchor.download, "hello.txt");
    assert.equal(anchor.href, "blob:unit-test");
    assert.equal(anchor.clicked, 1);

    const created = stubs.getCreatedBlob();
    assert.ok(created);
    assert.equal(await created.text(), "hello");

    assert.deepEqual(stubs.getMessages(), [null]);
  } finally {
    stubs.restore();
  }
});

void test("gzip click handler strips .tgz and .gz extensions when suggesting output names", async () => {
  const stubs = installGzipActionsDomStubs();
  try {
    const payload = encoder.encode("hello");

    const handler = createGzipClickHandler({
      getParseResult: () => ({ analyzer: "gzip", parsed: { header: {} } } as unknown as ParseForUiResult),
      getFile: () => createGzipFile({ payload, name: "archive.tgz", filename: null, comment: null, extra: null, includeHeaderCrc16: false }) as unknown as File,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.equal(stubs.getAnchor()?.download, "archive.tar");

    const handlerGz = createGzipClickHandler({
      getParseResult: () => ({ analyzer: "gzip", parsed: { header: {} } } as unknown as ParseForUiResult),
      getFile: () => createGzipFile({ payload, name: "hello.txt.gz", filename: null, comment: null, extra: null, includeHeaderCrc16: false }) as unknown as File,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    await handlerGz({ target: stubs.getChild() } as unknown as Event);
    assert.equal(stubs.getAnchor()?.download, "hello.txt");
  } finally {
    stubs.restore();
  }
});

void test("gzip click handler falls back to decompressed.bin for empty output names", async () => {
  const stubs = installGzipActionsDomStubs();
  try {
    const payload = encoder.encode("hello");
    const file = createGzipFile({ payload, name: ".gz", filename: null, comment: null, extra: null, includeHeaderCrc16: false });

    const handler = createGzipClickHandler({
      getParseResult: () => ({ analyzer: "gzip", parsed: { header: {} } } as unknown as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.equal(stubs.getAnchor()?.download, "decompressed.bin");
  } finally {
    stubs.restore();
  }
});

void test("gzip click handler reports decompression errors and restores button state", async () => {
  const stubs = installGzipActionsDomStubs();
  const globals = globalThis as unknown as Record<string, unknown>;
  try {
    const originalText = stubs.getButton().textContent;
    stubs.getButton().textContent = "";

    globals["DecompressionStream"] = class {
      constructor() {
        throw "boom";
      }
    };

    const payload = encoder.encode("hello");
    const file = createGzipFile({ payload });

    const handler = createGzipClickHandler({
      getParseResult: () => ({ analyzer: "gzip", parsed: {} } as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.equal(stubs.getMessages().length, 1);
    assert.equal(stubs.getMessages()[0], "Decompression failed: boom");
    assert.equal(stubs.getButton().disabled, false);
    assert.equal(stubs.getButton().textContent, "Decompress");
    stubs.getButton().textContent = originalText;
  } finally {
    stubs.restore();
  }
});

void test("gzip click handler handles DecompressionStream disappearing mid-flight", async () => {
  const stubs = installGzipActionsDomStubs();
  const globals = globalThis as unknown as Record<string, unknown>;
  try {
    const payload = encoder.encode("hello");
    const file = createGzipFile({ payload });

    let reads = 0;
    const constructor = globals["DecompressionStream"];
    Object.defineProperty(globalThis, "DecompressionStream", {
      configurable: true,
      get() {
        reads += 1;
        return reads === 1 ? constructor : undefined;
      }
    });

    const handler = createGzipClickHandler({
      getParseResult: () => ({ analyzer: "gzip", parsed: {} } as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => {
        stubs.getMessages().push(message);
      }
    });

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.equal(stubs.getMessages()[0], "Decompression failed: Browser does not support DecompressionStream for gzip.");
  } finally {
    stubs.restore();
  }
});
