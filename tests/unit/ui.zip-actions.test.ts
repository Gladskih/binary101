"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createZipEntryClickHandler } from "../../ui/zip-actions.js";
import { createZipEntry, createZipParseResult, installZipEnvironment } from "../fixtures/ui-zip-actions-fixtures.js";

void test("zip entry click handler ignores unrelated targets and invalid indices", async () => {
  const environment = installZipEnvironment();
  const messages: Array<string | null | undefined> = [];
  const globals = globalThis as unknown as Record<string, unknown>;
  const handler = createZipEntryClickHandler({
    getParseResult: () => createZipParseResult([]),
    getFile: () => null,
    setStatusMessage: message => {
      messages.push(message);
    }
  });

  try {
    assert.ok(new (globals["HTMLElement"] as new () => object)());
    assert.ok(new (globals["HTMLButtonElement"] as new () => object)());
    await handler({ target: {} } as Event);

    const malformedTarget = Object.assign(
      Object.create((globalThis as unknown as Record<string, unknown>)["HTMLElement"] as object),
      { attributes: new Map([["data-zip-entry", "not-a-number"]]) }
    );
    await handler({ target: malformedTarget } as Event);

    assert.deepEqual(messages, []);
  } finally {
    environment.restore();
  }
});

void test("zip entry click handler reports missing entries and stored extraction errors", async () => {
  const environment = installZipEnvironment();
  const messages: Array<string | null | undefined> = [];
  const erroredEntry = createZipEntry({
    extractError: "Entry spans beyond the file."
  });

  try {
    const missingEntryHandler = createZipEntryClickHandler({
      getParseResult: () => createZipParseResult([]),
      getFile: () => null,
      setStatusMessage: message => {
        messages.push(message);
      }
    });
    await missingEntryHandler({ target: environment.button } as unknown as Event);

    const erroredEntryHandler = createZipEntryClickHandler({
      getParseResult: () => createZipParseResult([erroredEntry]),
      getFile: () => null,
      setStatusMessage: message => {
        messages.push(message);
      }
    });
    await erroredEntryHandler({ target: environment.button } as unknown as Event);

    assert.deepEqual(messages, ["ZIP entry not found.", "Entry spans beyond the file."]);
  } finally {
    environment.restore();
  }
});

void test("zip entry click handler extracts stored entries and sanitizes the download name", async () => {
  const environment = installZipEnvironment();
  const messages: Array<string | null | undefined> = [];
  const file = new File([new TextEncoder().encode("__DATA__")], "archive.zip");
  const entry = createZipEntry({
    fileName: "folder/result.bin",
    compressedSize: 4,
    uncompressedSize: 4,
    dataOffset: 2,
    dataLength: 4,
    dataEnd: 6
  });

  try {
    const handler = createZipEntryClickHandler({
      getParseResult: () => createZipParseResult([entry]),
      getFile: () => file,
      setStatusMessage: message => {
        messages.push(message);
      }
    });

    await handler({ target: environment.button } as unknown as Event);

    const anchor = environment.anchorRef();
    assert.ok(anchor);
    assert.equal(anchor.download, "result.bin");
    assert.equal(anchor.clicked, 1);
    assert.equal(await environment.createdBlobRef()?.text(), "DATA");
    assert.deepEqual(messages, [null]);
    assert.equal(environment.button.disabled, false);
    assert.equal(environment.button.textContent, "Extract");
  } finally {
    environment.restore();
  }
});

void test("zip entry click handler decompresses deflated entries and falls back to entry.bin", async () => {
  const environment = installZipEnvironment();
  const globals = globalThis as unknown as Record<string, unknown>;
  const messages: Array<string | null | undefined> = [];
  const file = new File([new TextEncoder().encode("COMP")], "archive.zip");
  const entry = createZipEntry({
    fileName: "folder/ ",
    compressionMethod: 8,
    compressionName: "deflate",
    compressedSize: 4,
    uncompressedSize: 4,
    dataOffset: 0,
    dataLength: 4,
    dataEnd: 4
  });
  // The handler owns the piping and download flow; browser-native inflation is outside this unit,
  // so a pass-through TransformStream is sufficient to cover the supported DecompressionStream path.
  globals["DecompressionStream"] = class {
    constructor(format: string) {
      assert.equal(format, "deflate-raw");
      return new TransformStream();
    }
  };

  try {
    const handler = createZipEntryClickHandler({
      getParseResult: () => createZipParseResult([entry]),
      getFile: () => file,
      setStatusMessage: message => {
        messages.push(message);
      }
    });

    await handler({ target: environment.button } as unknown as Event);

    const anchor = environment.anchorRef();
    assert.ok(anchor);
    assert.equal(anchor.download, "entry.bin");
    assert.equal(await environment.createdBlobRef()?.text(), "COMP");
    assert.deepEqual(messages, [null]);
  } finally {
    environment.restore();
  }
});

void test("zip entry click handler reports unsupported deflate and missing file errors", async () => {
  const environment = installZipEnvironment();
  const messages: Array<string | null | undefined> = [];
  const entry = createZipEntry({
    fileName: "clip.deflate",
    compressionMethod: 8,
    compressionName: "deflate",
    compressedSize: 4,
    uncompressedSize: 4,
    dataOffset: 0,
    dataLength: 4,
    dataEnd: 4
  });

  try {
    const missingFileHandler = createZipEntryClickHandler({
      getParseResult: () => createZipParseResult([entry]),
      getFile: () => null,
      setStatusMessage: message => {
        messages.push(message);
      }
    });
    await missingFileHandler({ target: environment.button } as unknown as Event);

    (globalThis as unknown as Record<string, unknown>)["DecompressionStream"] = undefined;

    const unsupportedHandler = createZipEntryClickHandler({
      getParseResult: () => createZipParseResult([entry]),
      getFile: () => new File([new TextEncoder().encode("COMP")], "archive.zip"),
      setStatusMessage: message => {
        messages.push(message);
      }
    });
    await unsupportedHandler({ target: environment.button } as unknown as Event);

    assert.deepEqual(messages, [
      "No file selected.",
      "Browser does not support DecompressionStream; cannot decompress this entry."
    ]);
  } finally {
    environment.restore();
  }
});

void test("zip entry click handler restores the button after extraction failures", async () => {
  const environment = installZipEnvironment();
  const messages: Array<string | null | undefined> = [];
  const file = new File([new TextEncoder().encode("COMP")], "archive.zip");
  const entry = createZipEntry({
    fileName: "broken.bin",
    compressedSize: 4,
    uncompressedSize: 4
  });

  try {
    const handler = createZipEntryClickHandler({
      getParseResult: () => createZipParseResult([entry]),
      getFile: () => file,
      setStatusMessage: message => {
        messages.push(message);
      }
    });

    await handler({ target: environment.button } as unknown as Event);

    assert.deepEqual(messages, ["Extract failed: Entry is missing data bounds."]);
    assert.equal(environment.button.disabled, false);
    assert.equal(environment.button.textContent, "Extract");
  } finally {
    environment.restore();
  }
});
