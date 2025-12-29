"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { Iso9660ParseResult } from "../../analyzers/iso9660/types.js";
import { parseIso9660 } from "../../analyzers/iso9660/index.js";
import { createIso9660EntryClickHandler } from "../../ui/iso9660-actions.js";
import { createIso9660PrimaryFile } from "../fixtures/iso9660-fixtures.js";
import { installIso9660ActionsDomStubs } from "../helpers/iso9660-actions-dom-stubs.js";
import { MockFile } from "../helpers/mock-file.js";

void test("iso9660 click handler ignores unrelated clicks", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: {} } as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    await handler({ target: {} } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), []);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports non-iso selections", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "zip", parsed: {} } as unknown as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["Not an ISO-9660 file."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports missing root directory", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const iso = { selectedBlockSize: 2048, rootDirectory: null } as unknown as Iso9660ParseResult;
    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["ISO-9660 root directory was not parsed."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports missing file selection", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const iso = {
      selectedBlockSize: 2048,
      rootDirectory: { entries: [{ name: "FILE.BIN", kind: "file", extentLocationLba: 1, dataLength: 1, fileFlags: 0 }] }
    } as unknown as Iso9660ParseResult;
    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    const button = stubs.getButton();
    button.setAttribute("data-iso-entry", "0");

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["No file selected."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler rejects multi-extent entries", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const iso = {
      selectedBlockSize: 2048,
      rootDirectory: { entries: [{ name: "BIG.BIN", kind: "file", extentLocationLba: 1, dataLength: 1, fileFlags: 0x80 }] }
    } as unknown as Iso9660ParseResult;
    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    const button = stubs.getButton();
    button.setAttribute("data-iso-entry", "0");

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["Multi-extent ISO-9660 files are not supported for extraction yet."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports entries outside the file bounds", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const iso = {
      selectedBlockSize: 2048,
      rootDirectory: { entries: [{ name: "TOO-FAR.BIN", kind: "file", extentLocationLba: 999, dataLength: 1, fileFlags: 0 }] }
    } as unknown as Iso9660ParseResult;
    const file = new MockFile(new Uint8Array(2048), "small.iso", "application/x-iso9660-image");

    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    const button = stubs.getButton();
    button.setAttribute("data-iso-entry", "0");

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["ISO-9660 entry starts past end of file."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler downloads the selected root file extent", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const file = createIso9660PrimaryFile();
    const iso = await parseIso9660(file as unknown as File);
    assert.ok(iso);
    const result: ParseForUiResult = { analyzer: "iso9660", parsed: iso };

    const helloIndex = iso.rootDirectory?.entries.findIndex(entry => entry.name === "HELLO.TXT") ?? -1;
    assert.ok(helloIndex >= 0);
    stubs.getButton().setAttribute("data-iso-entry", String(helloIndex));

    const handler = createIso9660EntryClickHandler({
      getParseResult: () => result,
      getFile: () => file as unknown as File,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    await handler({ target: stubs.getChild() } as unknown as Event);

    const anchor = stubs.getAnchor();
    assert.ok(anchor);
    assert.equal(anchor.download, "HELLO.TXT");
    assert.equal(anchor.href, "blob:unit-test");
    assert.equal(anchor.clicked, 1);

    const created = stubs.getCreatedBlob();
    assert.ok(created);
    assert.equal(await created.text(), "HELLO");
    assert.deepEqual(stubs.getMessages(), [null]);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports missing entries", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const iso = { selectedBlockSize: 2048, rootDirectory: { entries: [] } } as unknown as Iso9660ParseResult;
    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    stubs.getButton().setAttribute("data-iso-entry", "0");
    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["ISO-9660 entry not found."]);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports non-file entries", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const iso = {
      selectedBlockSize: 2048,
      rootDirectory: { entries: [{ name: "DIR", kind: "directory", extentLocationLba: 1, dataLength: 1, fileFlags: 0 }] }
    } as unknown as Iso9660ParseResult;
    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    stubs.getButton().setAttribute("data-iso-entry", "0");
    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["Selected ISO-9660 entry is not a file."]);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports missing entry bounds", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const iso = {
      selectedBlockSize: 2048,
      rootDirectory: { entries: [{ name: "FILE", kind: "file", extentLocationLba: null, dataLength: 1, fileFlags: 0 }] }
    } as unknown as Iso9660ParseResult;
    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => null,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    stubs.getButton().setAttribute("data-iso-entry", "0");
    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["ISO-9660 entry data bounds are missing."]);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports invalid entry offsets", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const iso = {
      selectedBlockSize: 2048,
      rootDirectory: { entries: [{ name: "FILE", kind: "file", extentLocationLba: Number.NaN, dataLength: 1, fileFlags: 0 }] }
    } as unknown as Iso9660ParseResult;
    const file = new MockFile(new Uint8Array(4096), "sample.iso", "application/x-iso9660-image");

    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    stubs.getButton().setAttribute("data-iso-entry", "0");
    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["ISO-9660 entry offset is invalid."]);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports invalid entry lengths", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const iso = {
      selectedBlockSize: 2048,
      rootDirectory: { entries: [{ name: "FILE", kind: "file", extentLocationLba: 1, dataLength: -1, fileFlags: 0 }] }
    } as unknown as Iso9660ParseResult;
    const file = new MockFile(new Uint8Array(4096), "sample.iso", "application/x-iso9660-image");

    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    stubs.getButton().setAttribute("data-iso-entry", "0");
    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["ISO-9660 entry length is invalid."]);
  } finally {
    stubs.restore();
  }
});
void test("iso9660 click handler reports extraction errors and restores button state", async () => {
  const stubs = installIso9660ActionsDomStubs();
  const originalCreateObjectURL = URL.createObjectURL;
  try {
    URL.createObjectURL = () => {
      throw new Error("boom");
    };

    const iso = {
      selectedBlockSize: 2048,
      rootDirectory: { entries: [{ name: "FILE", kind: "file", extentLocationLba: 0, dataLength: 1, fileFlags: 0 }] }
    } as unknown as Iso9660ParseResult;
    const file = new MockFile(new Uint8Array([0x41]), "sample.iso", "application/x-iso9660-image");
    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    const button = stubs.getButton();
    button.textContent = "Download";
    button.setAttribute("data-iso-entry", "0");

    await handler({ target: stubs.getChild() } as unknown as Event);
    assert.deepEqual(stubs.getMessages(), ["Extract failed: boom"]);
    assert.equal(button.disabled, false);
    assert.equal(button.textContent, "Download");
    assert.equal(stubs.getAnchor(), null);
  } finally {
    URL.createObjectURL = originalCreateObjectURL;
    stubs.restore();
  }
});
