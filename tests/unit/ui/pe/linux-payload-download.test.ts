"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../../../analyzers/index.js";
import type { PeParseResult } from "../../../../analyzers/pe/index.js";
import { createPeLinuxPayloadDownloadClickHandler } from "../../../../ui/pe-linux-payload-download.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const installDownloadStubs = () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originals = {
    Element: globals["Element"],
    HTMLElement: globals["HTMLElement"],
    document: globals["document"],
    createObjectURL: URL.createObjectURL,
    revokeObjectURL: URL.revokeObjectURL
  };
  const hadElement = Object.prototype.hasOwnProperty.call(globals, "Element");
  const hadHtmlElement = Object.prototype.hasOwnProperty.call(globals, "HTMLElement");
  const hadDocument = Object.prototype.hasOwnProperty.call(globals, "document");
  class FakeElement {
    readonly attributes = new Map<string, string>();
    closest(selector: string): FakeElement | null {
      return selector === "[data-pe-linux-payload-download]" ? this : null;
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
  let anchor: { href: string; download: string; clicked: number; click: () => void } | null = null;
  let createdBlob: Blob | null = null;
  globals["document"] = {
    body: {
      appendChild: (node: unknown) => node,
      removeChild: (node: unknown) => node
    },
    createElement: () => {
      anchor = { href: "", download: "", clicked: 0, click() { this.clicked += 1; } };
      return anchor;
    }
  };
  URL.createObjectURL = (blob: Blob): string => {
    createdBlob = blob;
    return "blob:linux-payload";
  };
  URL.revokeObjectURL = () => {};
  return {
    button: new FakeElement(),
    getAnchor: () => anchor,
    getCreatedBlob: () => createdBlob,
    restore: () => {
      if (hadElement) globals["Element"] = originals.Element;
      else Reflect.deleteProperty(globals, "Element");
      if (hadHtmlElement) globals["HTMLElement"] = originals.HTMLElement;
      else Reflect.deleteProperty(globals, "HTMLElement");
      if (hadDocument) globals["document"] = originals.document;
      else Reflect.deleteProperty(globals, "document");
      URL.createObjectURL = originals.createObjectURL;
      URL.revokeObjectURL = originals.revokeObjectURL;
    }
  };
};

const createParseResult = (): ParseForUiResult => ({
  analyzer: "pe",
  parsed: {
    opt: { Magic: 0x20b },
    linuxBoot: {
      setupSectorsRaw: 1,
      setupSectors: 1,
      bootFlag: 0xaa55,
      protocolVersion: 0x020f,
      kernelVersionOffset: 0,
      loadFlags: 0,
      payload: {
        offset: 0x20,
        length: 4,
        fileOffset: 64,
        endOffset: 68,
        format: "gzip"
      }
    }
  } as unknown as PeParseResult
});

const createHeaderOnlyParseResult = (): ParseForUiResult => ({
  analyzer: "pe",
  parsed: {
    opt: null,
    linuxBoot: {
      payload: {
        offset: 0x20,
        length: 4,
        fileOffset: 64,
        endOffset: 68,
        format: "gzip"
      }
    }
  } as unknown as PeParseResult
});

void test("PE Linux payload download handler slices the validated payload range", async () => {
  const stubs = installDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  try {
    stubs.button.setAttribute("data-pe-linux-payload-download", "");
    stubs.button.setAttribute("data-linux-payload-start", "64");
    stubs.button.setAttribute("data-linux-payload-end", "68");
    const bytes = Uint8Array.from({ length: 80 }, (_, index) => index);
    const handler = createPeLinuxPayloadDownloadClickHandler({
      getFile: () => new MockFile(bytes, "kernel"),
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.equal(expectDefined(stubs.getAnchor()).download, "kernel.linux-payload-40-44.gz");
    assert.deepEqual(new Uint8Array(await expectDefined(stubs.getCreatedBlob()).arrayBuffer()), bytes.subarray(64, 68));
    assert.deepEqual(messages, [null]);
  } finally {
    stubs.restore();
  }
});

void test("PE Linux payload download handler reports when no file is selected", () => {
  const stubs = installDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  try {
    stubs.button.setAttribute("data-pe-linux-payload-download", "");
    const handler = createPeLinuxPayloadDownloadClickHandler({
      getFile: () => null,
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.deepEqual(messages, ["No file selected."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});

void test("PE Linux payload download handler rejects tampered ranges", () => {
  const stubs = installDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  try {
    stubs.button.setAttribute("data-pe-linux-payload-download", "");
    stubs.button.setAttribute("data-linux-payload-start", "64");
    stubs.button.setAttribute("data-linux-payload-end", "69");
    const handler = createPeLinuxPayloadDownloadClickHandler({
      getFile: () => new MockFile(new Uint8Array(80), "kernel"),
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.deepEqual(messages, ["Linux payload range is not available."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});

void test("PE Linux payload download handler rejects header-only PE parse results", () => {
  const stubs = installDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  try {
    stubs.button.setAttribute("data-pe-linux-payload-download", "");
    stubs.button.setAttribute("data-linux-payload-start", "64");
    stubs.button.setAttribute("data-linux-payload-end", "68");
    const handler = createPeLinuxPayloadDownloadClickHandler({
      getFile: () => new MockFile(new Uint8Array(80), "kernel"),
      getParseResult: createHeaderOnlyParseResult,
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.deepEqual(messages, ["Linux payload range is not available."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
