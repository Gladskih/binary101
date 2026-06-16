"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createSevenZipEntryClickHandler } from "../../../ui/sevenz-actions.js";
import type { ParseForUiResult } from "../../../analyzers/index.js";

type AnchorStub = {
  href: string;
  download: string;
  clicked: number;
  click: () => void;
};

const installSevenZipDom = () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originalElement = globals["HTMLElement"];
  const originalButton = globals["HTMLButtonElement"];
  const originalDocument = globals["document"];
  const originalCreateObjectUrl = URL.createObjectURL;
  const originalRevokeObjectUrl = URL.revokeObjectURL;
  class FakeElement {
    parent: FakeElement | null;

    constructor(parent: FakeElement | null = null) {
      this.parent = parent;
    }

    closest(selector: string): FakeElement | null {
      return selector === "button.sevenZipExtractButton" ? this.parent || this : null;
    }
  }
  class FakeButton extends FakeElement {
    disabled = false;
    textContent: string | null = "Extract";
    readonly attributes = new Map<string, string>([["data-sevenzip-entry", "1"]]);

    getAttribute(name: string): string | null {
      return this.attributes.get(name) ?? null;
    }
  }
  globals["HTMLElement"] = FakeElement;
  globals["HTMLButtonElement"] = FakeButton;
  let anchor: AnchorStub | null = null;
  let createdBlob: Blob | null = null;
  globals["document"] = {
    body: { appendChild: (node: unknown) => node, removeChild: (node: unknown) => node },
    createElement: () => {
      anchor = { href: "", download: "", clicked: 0, click: () => { if (anchor) anchor.clicked += 1; } };
      return anchor;
    }
  };
  URL.createObjectURL = (blob: Blob): string => {
    createdBlob = blob;
    return "blob:sevenzip-test";
  };
  URL.revokeObjectURL = () => {};
  const button = new FakeButton();
  return {
    anchor: () => anchor,
    blob: () => createdBlob,
    button: button as unknown as HTMLButtonElement,
    setEntryIndex: (value: string) => button.attributes.set("data-sevenzip-entry", value),
    restore: () => {
      globals["HTMLElement"] = originalElement;
      globals["HTMLButtonElement"] = originalButton;
      globals["document"] = originalDocument;
      URL.createObjectURL = originalCreateObjectUrl;
      URL.revokeObjectURL = originalRevokeObjectUrl;
    }
  };
};

const createParseResult = (uncompressedSize = 4n): ParseForUiResult => ({
  analyzer: "sevenZip",
  parsed: {
    is7z: true,
    issues: [],
    structure: {
      archiveFlags: { isSolid: false, isHeaderEncrypted: false, hasEncryptedContent: false },
      folders: [{
        index: 0,
        packedOffset: 0n,
        packedSize: 14n,
        unpackSize: 4n,
        coders: [{
          id: "LZMA",
          methodId: "030101",
          numInStreams: 1,
          numOutStreams: 1,
          propertyBytes: [0x5d, 0x00, 0x00, 0x01, 0x00],
          properties: null,
          isEncryption: false
        }],
        numUnpackStreams: 1,
        substreams: [{ size: 4n, crc: null }],
        isEncrypted: false
      }],
      files: [{
        index: 1,
        name: "folder/data.bin",
        folderIndex: 0,
        folderStreamIndex: 0,
        uncompressedSize,
        packedSize: 14n,
        compressionRatio: null,
        crc32: null,
        modifiedTime: null,
        attributes: null,
        hasStream: true,
        isDirectory: false,
        isEncrypted: false
      }]
    }
  }
});

void test("7z entry click handler reports entries that are not in the parse result", async () => {
  const dom = installSevenZipDom();
  const messages: Array<string | null | undefined> = [];
  dom.setEntryIndex("99");
  const handler = createSevenZipEntryClickHandler({
    getParseResult: createParseResult,
    getFile: () => new File([], "archive.7z"),
    setStatusMessage: message => messages.push(message)
  });

  try {
    await handler({ target: dom.button } as unknown as Event);

    assert.deepEqual(messages, ["7z entry not found."]);
  } finally {
    dom.restore();
  }
});

void test("7z entry click handler reports analyzer-side extraction errors", async () => {
  const dom = installSevenZipDom();
  const messages: Array<string | null | undefined> = [];
  const parseResult = createParseResult();
  if (parseResult.analyzer === "sevenZip") {
    parseResult.parsed.structure!.files[0]!.extractError = "Unsupported 7z coder.";
  }
  const handler = createSevenZipEntryClickHandler({
    getParseResult: () => parseResult,
    getFile: () => new File([], "archive.7z"),
    setStatusMessage: message => messages.push(message)
  });

  try {
    await handler({ target: dom.button } as unknown as Event);

    assert.deepEqual(messages, ["Unsupported 7z coder."]);
  } finally {
    dom.restore();
  }
});

void test("7z entry click handler reports missing source files", async () => {
  const dom = installSevenZipDom();
  const messages: Array<string | null | undefined> = [];
  const handler = createSevenZipEntryClickHandler({
    getParseResult: createParseResult,
    getFile: () => null,
    setStatusMessage: message => messages.push(message)
  });

  try {
    await handler({ target: dom.button } as unknown as Event);

    assert.deepEqual(messages, ["No file selected."]);
  } finally {
    dom.restore();
  }
});

void test("7z entry click handler extracts single LZMA folders", async () => {
  const dom = installSevenZipDom();
  const messages: Array<string | null | undefined> = [];
  const packed = Uint8Array.from([
    0x00, 0x22, 0x10, 0x46, 0xcd, 0x69, 0xa5, 0x3c, 0x7f, 0xff, 0xfa, 0x6f, 0xe0, 0x00
  ]);
  const handler = createSevenZipEntryClickHandler({
    getParseResult: createParseResult,
    getFile: () => new File([packed], "archive.7z"),
    setStatusMessage: message => messages.push(message)
  });

  try {
    await handler({ target: dom.button } as unknown as Event);

    assert.equal(dom.anchor()?.download, "data.bin");
    assert.equal(dom.anchor()?.clicked, 1);
    assert.equal(await dom.blob()?.text(), "DATA");
    assert.deepEqual(messages, [null]);
  } finally {
    dom.restore();
  }
});

void test("7z entry click handler reports decoded range overflow", async () => {
  const dom = installSevenZipDom();
  const messages: Array<string | null | undefined> = [];
  const packed = Uint8Array.from([
    0x00, 0x22, 0x10, 0x46, 0xcd, 0x69, 0xa5, 0x3c, 0x7f, 0xff, 0xfa, 0x6f, 0xe0, 0x00
  ]);
  const handler = createSevenZipEntryClickHandler({
    getParseResult: () => createParseResult(8n),
    getFile: () => new File([packed], "archive.7z"),
    setStatusMessage: message => messages.push(message)
  });

  try {
    await handler({ target: dom.button } as unknown as Event);

    assert.equal(dom.anchor(), null);
    assert.match(messages[0] || "", /decoded range exceeds folder data/);
  } finally {
    dom.restore();
  }
});
