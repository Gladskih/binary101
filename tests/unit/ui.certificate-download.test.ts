"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createCertificateDownloadClickHandler } from "../../ui/certificate-download.js";

const installCertificateDownloadStubs = () => {
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
      return selector === "[data-certificate-download]" ? this : null;
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
      anchor = {
        href: "",
        download: "",
        clicked: 0,
        click() {
          this.clicked += 1;
        }
      };
      return anchor;
    }
  };
  URL.createObjectURL = (blob: Blob): string => {
    createdBlob = blob;
    return "blob:certificate";
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

void test("certificate download handler downloads DER bytes from button data", async () => {
  const stubs = installCertificateDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  try {
    stubs.button.setAttribute("data-certificate-download", "");
    stubs.button.setAttribute("data-certificate-der-base64", "AQID");
    stubs.button.setAttribute("data-certificate-filename", "../leaf certificate");
    const handler = createCertificateDownloadClickHandler({
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.strictEqual(stubs.getAnchor()?.download, "leaf_certificate.cer");
    assert.strictEqual(stubs.getAnchor()?.clicked, 1);
    const createdBlob = stubs.getCreatedBlob();
    assert.ok(createdBlob);
    assert.deepStrictEqual(new Uint8Array(await createdBlob.arrayBuffer()), Uint8Array.of(1, 2, 3));
    assert.deepStrictEqual(messages, [null]);
  } finally {
    stubs.restore();
  }
});

void test("certificate download handler reports missing DER data", () => {
  const stubs = installCertificateDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  try {
    stubs.button.setAttribute("data-certificate-download", "");
    const handler = createCertificateDownloadClickHandler({
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.deepStrictEqual(messages, ["Certificate DER data is not available."]);
    assert.strictEqual(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
