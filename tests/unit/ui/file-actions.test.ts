"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileActionClickHandler } from "../../../ui/file-actions.js";

type AnchorStub = {
  href: string;
  download: string;
  clicked: number;
  click: () => void;
};

const installCertificateDom = () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originalDocument = globals["document"];
  const originalElement = globals["Element"];
  const originalHTMLElement = globals["HTMLElement"];
  const originalHTMLButtonElement = globals["HTMLButtonElement"];
  const originalCreateObjectUrl = URL.createObjectURL;
  const originalRevokeObjectUrl = URL.revokeObjectURL;
  class FakeElement {
    readonly id = "";
    private readonly attributes = new Map<string, string>([
      ["data-certificate-der-base64", "AQID"],
      ["data-certificate-filename", "test.der"]
    ]);
    closest(selector: string): FakeElement | null {
      return selector === "[data-certificate-download]" ? this : null;
    }
    getAttribute(name: string): string | null {
      return this.attributes.get(name) ?? null;
    }
  }
  let anchor: AnchorStub | null = null;
  let blob: Blob | null = null;
  globals["Element"] = FakeElement;
  globals["HTMLElement"] = FakeElement;
  globals["HTMLButtonElement"] = FakeElement;
  globals["document"] = {
    body: { appendChild: (node: unknown) => node, removeChild: (node: unknown) => node },
    createElement: () => {
      anchor = { href: "", download: "", clicked: 0, click: () => { if (anchor) anchor.clicked += 1; } };
      return anchor;
    },
    getElementById: () => null
  };
  URL.createObjectURL = (value: Blob): string => {
    blob = value;
    return "blob:file-action-test";
  };
  URL.revokeObjectURL = () => {};
  return {
    anchor: () => anchor,
    blob: () => blob,
    target: new FakeElement(),
    restore: () => {
      globals["document"] = originalDocument;
      globals["Element"] = originalElement;
      globals["HTMLElement"] = originalHTMLElement;
      globals["HTMLButtonElement"] = originalHTMLButtonElement;
      URL.createObjectURL = originalCreateObjectUrl;
      URL.revokeObjectURL = originalRevokeObjectUrl;
    }
  };
};

void test("createFileActionClickHandler dispatches certificate download clicks", async () => {
  const dom = installCertificateDom();
  const messages: Array<string | null | undefined> = [];
  const handler = createFileActionClickHandler({
    getParseResult: () => ({ analyzer: null, parsed: null }),
    getFile: () => null,
    setStatusMessage: message => messages.push(message)
  });
  try {
    handler({ target: dom.target } as unknown as Event);
    assert.equal(dom.anchor()?.download, "test.der.cer");
    assert.equal(dom.anchor()?.clicked, 1);
    const blob = dom.blob();
    assert.ok(blob);
    assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), Uint8Array.of(1, 2, 3));
    assert.deepEqual(messages, [null]);
  } finally {
    dom.restore();
  }
});

void test("createFileActionClickHandler ignores non-element targets", () => {
  const dom = installCertificateDom();
  const messages: Array<string | null | undefined> = [];
  const handler = createFileActionClickHandler({
    getParseResult: () => ({ analyzer: null, parsed: null }),
    getFile: () => null,
    setStatusMessage: message => messages.push(message)
  });
  try {
    handler({ target: null } as unknown as Event);
    assert.deepEqual(messages, []);
  } finally {
    dom.restore();
  }
});
