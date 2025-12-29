"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../analyzers/index.js";
import { parseIso9660 } from "../../analyzers/iso9660/index.js";
import { createIso9660EntryClickHandler } from "../../ui/iso9660-actions.js";
import { createIso9660PrimaryFile } from "../fixtures/iso9660-fixtures.js";
import { installIso9660ActionsDomStubs } from "../helpers/iso9660-actions-dom-stubs.js";
import { encoder } from "../fixtures/archive-fixture-helpers.js";
import { MockFile } from "../helpers/mock-file.js";

void test("iso9660 click handler expands directories and renders nested entries", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const file = createIso9660PrimaryFile();
    const iso = await parseIso9660(file as unknown as File);
    assert.ok(iso);
    const root = iso.rootDirectory;
    assert.ok(root);
    const subdir = root.entries.find(entry => entry.name === "SUBDIR");
    assert.ok(subdir);
    assert.equal(subdir.kind, "directory");
    assert.ok(subdir.extentLocationLba != null);

    const dirButton = stubs.getDirButton();
    dirButton.setAttribute("data-iso-lba", String(subdir.extentLocationLba));
    if (subdir.dataLength != null) dirButton.setAttribute("data-iso-size", String(subdir.dataLength));
    dirButton.setAttribute("data-iso-path", "/SUBDIR");
    dirButton.setAttribute("data-iso-depth", "0");
    dirButton.textContent = "Expand";

    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    stubs.getDirRow().hidden = true;
    await handler({ target: stubs.getDirChild() } as unknown as Event);

    const container = stubs.getDirContainer() as unknown as {
      innerHTML: string;
      getAttribute: (name: string) => string | null;
    };
    assert.equal(stubs.getDirRow().hidden, false);
    assert.equal(container.getAttribute("data-iso-loaded"), "1");
    assert.ok(container.innerHTML.includes("INNER.TXT"));
    assert.equal(dirButton.textContent, "Collapse");
    assert.deepEqual(stubs.getMessages().slice(-1), [null]);

    await handler({ target: stubs.getDirChild() } as unknown as Event);
    assert.equal(stubs.getDirRow().hidden, true);
    assert.equal(dirButton.textContent, "Expand");
  } finally {
    stubs.restore();
  }
});

void test("iso9660 click handler supports direct offset/length extraction", async () => {
  const stubs = installIso9660ActionsDomStubs();
  try {
    const payload = encoder.encode("HELLO");
    const file = new MockFile(payload, "payload.iso", "application/x-iso9660-image");
    const iso = await parseIso9660(createIso9660PrimaryFile() as unknown as File);
    assert.ok(iso);

    const button = stubs.getButton();
    button.setAttribute("data-iso-offset", "0");
    button.setAttribute("data-iso-length", "5");
    button.setAttribute("data-iso-name", "folder/hello.txt");
    button.setAttribute("data-iso-flags", "0");

    const handler = createIso9660EntryClickHandler({
      getParseResult: () => ({ analyzer: "iso9660", parsed: iso } as ParseForUiResult),
      getFile: () => file as unknown as File,
      setStatusMessage: message => stubs.getMessages().push(message)
    });

    await handler({ target: stubs.getChild() } as unknown as Event);

    const anchor = stubs.getAnchor();
    assert.ok(anchor);
    assert.equal(anchor.download, "hello.txt");
    assert.equal(anchor.clicked, 1);

    const created = stubs.getCreatedBlob();
    assert.ok(created);
    assert.equal(await created.text(), "HELLO");
    assert.deepEqual(stubs.getMessages(), [null]);
  } finally {
    stubs.restore();
  }
});

