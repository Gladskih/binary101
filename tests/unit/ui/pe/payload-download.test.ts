"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../../../analyzers/index.js";
import type { PeParseResult } from "../../../../analyzers/pe/index.js";
import { createPePayloadDownloadClickHandler } from "../../../../ui/pe-payload-download.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { MockFile } from "../../../helpers/mock-file.js";

const installDownloadDom = () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originals = {
    Element: globals["Element"],
    HTMLElement: globals["HTMLElement"],
    document: globals["document"],
    createObjectURL: URL.createObjectURL,
    revokeObjectURL: URL.revokeObjectURL
  };
  class FakeElement {
    readonly attributes = new Map<string, string>();
    closest(selector: string): FakeElement | null {
      return selector === "[data-pe-payload-download]" ? this : null;
    }
    getAttribute(name: string): string | null {
      return this.attributes.get(name) ?? null;
    }
    setAttribute(name: string, value: string): void {
      this.attributes.set(name, value);
    }
  }
  globals["Element"] = FakeElement;
  globals["HTMLElement"] = FakeElement;
  let anchor: { download: string; href: string; clicked: number; click: () => void } | null = null;
  let blob: Blob | null = null;
  globals["document"] = {
    body: { appendChild: () => {}, removeChild: () => {} },
    createElement: () => {
      anchor = { download: "", href: "", clicked: 0, click() { this.clicked += 1; } };
      return anchor;
    }
  };
  URL.createObjectURL = created => {
    if (created instanceof Blob) blob = created;
    return "blob:payload";
  };
  URL.revokeObjectURL = () => {};
  return {
    button: new FakeElement(),
    getAnchor: () => anchor,
    getBlob: () => blob,
    restore: () => {
      globals["Element"] = originals.Element;
      globals["HTMLElement"] = originals.HTMLElement;
      globals["document"] = originals.document;
      URL.createObjectURL = originals.createObjectURL;
      URL.revokeObjectURL = originals.revokeObjectURL;
    }
  };
};

const createParseResult = (): ParseForUiResult => ({
  analyzer: "pe",
  parsed: {
    opt: { Magic: 0x10b },
    payloads: {
      entries: [{
        start: 1,
        end: 4,
        format: "sevenzip",
        provenance: {
          location: "overlay",
          discovery: "archive-scan",
          association: "nsis-installer-data",
          validation: "sevenzip-next-header"
        }
      }]
    }
  } as PeParseResult
});

const setPayloadAttributes = (
  button: ReturnType<typeof installDownloadDom>["button"],
  end = 4,
  format = "sevenzip"
): void => {
  button.setAttribute("data-pe-payload-download", "");
  button.setAttribute("data-payload-start", "1");
  button.setAttribute("data-payload-end", String(end));
  button.setAttribute("data-payload-format", format);
};

void test("PE payload download slices the exact validated archive", async () => {
  const dom = installDownloadDom();
  const messages: Array<string | null | undefined> = [];
  try {
    setPayloadAttributes(dom.button);
    const handler = createPePayloadDownloadClickHandler({
      getFile: () => new MockFile(Uint8Array.of(0, 1, 2, 3, 4), "setup.exe"),
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: dom.button } as unknown as Event);

    const blob = expectDefined(dom.getBlob());
    assert.equal(blob.type, "application/x-7z-compressed");
    assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), Uint8Array.of(1, 2, 3));
    assert.equal(expectDefined(dom.getAnchor()).download, "setup.exe.payload-1.7z");
    assert.equal(expectDefined(dom.getAnchor()).clicked, 1);
    assert.deepEqual(messages, [null]);
  } finally {
    dom.restore();
  }
});

void test("PE payload download rejects tampered bounds and formats", () => {
  const dom = installDownloadDom();
  const messages: Array<string | null | undefined> = [];
  try {
    setPayloadAttributes(dom.button, 5, "rar");
    const handler = createPePayloadDownloadClickHandler({
      getFile: () => new MockFile(new Uint8Array(8), "setup.exe"),
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: dom.button } as unknown as Event);

    assert.deepEqual(messages, ["PE payload is not available."]);
    assert.equal(dom.getAnchor(), null);
  } finally {
    dom.restore();
  }
});

void test("PE-signature resource object download stays a neutral binary", () => {
  const dom = installDownloadDom();
  const messages: Array<string | null | undefined> = [];
  try {
    setPayloadAttributes(dom.button, 4, "pe");
    const handler = createPePayloadDownloadClickHandler({
      getFile: () => new MockFile(new Uint8Array(8), "bootstrap.exe"),
      getParseResult: () => ({
        analyzer: "pe",
        parsed: {
          opt: { Magic: 0x10b },
          payloads: { entries: [{
            start: 1,
            end: 4,
            format: "pe" as const,
            provenance: {
              location: "resource" as const,
              discovery: "resource-leaf" as const,
              resourcePath: [],
              validation: "pe-signatures" as const
            }
          }] }
        } as unknown as PeParseResult
      }),
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: dom.button } as unknown as Event);

    assert.equal(expectDefined(dom.getAnchor()).download, "bootstrap.exe.payload-1.bin");
    assert.equal(expectDefined(dom.getBlob()).type, "application/octet-stream");
    assert.deepEqual(messages, [null]);
  } finally {
    dom.restore();
  }
});

void test("PE payload download reports a missing selected file", () => {
  const dom = installDownloadDom();
  const messages: Array<string | null | undefined> = [];
  try {
    setPayloadAttributes(dom.button);
    const handler = createPePayloadDownloadClickHandler({
      getFile: () => null,
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: dom.button } as unknown as Event);

    assert.deepEqual(messages, ["No file selected."]);
  } finally {
    dom.restore();
  }
});
