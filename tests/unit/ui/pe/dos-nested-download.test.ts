"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../../../analyzers/index.js";
import type { PeParseResult } from "../../../../analyzers/pe/index.js";
import { createPeDosNestedDownloadClickHandler } from "../../../../ui/pe-dos-nested-download.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const installNestedDownloadStubs = () => {
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
      return selector === "[data-pe-dos-nested-download]" ? this : null;
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
    return "blob:nested";
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
    dos: {
      stub: {
        code: {
          kind: "custom-or-unrecognized",
          instructions: [],
          nestedPe: {
            offset: 0,
            endOffset: 4,
            peHeaderOffset: 2,
            machine: 0x014c,
            optionalMagic: 0x10b,
            entrypointRva: 0,
            subsystem: 16,
            sizeOfImage: 4,
            sizeOfHeaders: 4,
            sections: []
          }
        }
      }
    }
  } as unknown as PeParseResult
});

void test("PE DOS nested download handler slices the validated nested PE range", async () => {
  const stubs = installNestedDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  try {
    stubs.button.setAttribute("data-pe-dos-nested-download", "");
    stubs.button.setAttribute("data-nested-start", "64");
    stubs.button.setAttribute("data-nested-end", "68");
    const bytes = Uint8Array.from({ length: 80 }, (_, index) => index);
    const handler = createPeDosNestedDownloadClickHandler({
      getFile: () => new MockFile(bytes, "boot.exe"),
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.equal(expectDefined(stubs.getAnchor()).download, "boot.exe.dos-nested-40-44.exe");
    assert.deepEqual(new Uint8Array(await expectDefined(stubs.getCreatedBlob()).arrayBuffer()), bytes.subarray(64, 68));
    assert.deepEqual(messages, [null]);
  } finally {
    stubs.restore();
  }
});

void test("PE DOS nested download handler rejects tampered ranges", () => {
  const stubs = installNestedDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  try {
    stubs.button.setAttribute("data-pe-dos-nested-download", "");
    stubs.button.setAttribute("data-nested-start", "64");
    stubs.button.setAttribute("data-nested-end", "69");
    const handler = createPeDosNestedDownloadClickHandler({
      getFile: () => new MockFile(Uint8Array.from({ length: 80 }, (_, index) => index), "boot.exe"),
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.deepEqual(messages, ["Nested PE range is not available."]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
