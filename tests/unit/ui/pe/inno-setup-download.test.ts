"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../../../analyzers/index.js";
import type { PeParseResult } from "../../../../analyzers/pe/index.js";
import { createPeInnoSetupDownloadClickHandler } from "../../../../ui/pe-inno-setup-download.js";
import { createInnoFinding, createInnoSetupFixture } from "../../../fixtures/inno-setup-fixture.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const installDownloadDom = () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originals = {
    Element: globals["Element"],
    HTMLButtonElement: globals["HTMLButtonElement"],
    document: globals["document"],
    createObjectURL: URL.createObjectURL,
    revokeObjectURL: URL.revokeObjectURL
  };
  class FakeButton {
    readonly attributes = new Map<string, string>();
    disabled = false;
    textContent: string | null = "Download";
    closest(selector: string): FakeButton | null {
      return selector === "[data-pe-inno-engine-download]" ? this : null;
    }
    getAttribute(name: string): string | null {
      return this.attributes.get(name) ?? null;
    }
    setAttribute(name: string, value: string): void {
      this.attributes.set(name, value);
    }
    removeAttribute(name: string): void {
      this.attributes.delete(name);
    }
  }
  globals["Element"] = FakeButton;
  globals["HTMLButtonElement"] = FakeButton;
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
    return "blob:inno";
  };
  URL.revokeObjectURL = () => {};
  return {
    button: new FakeButton(),
    getAnchor: () => anchor,
    getBlob: () => blob,
    restore: () => {
      globals["Element"] = originals.Element;
      globals["HTMLButtonElement"] = originals.HTMLButtonElement;
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
    packers: {
      reports: [{ id: "inno-setup", findings: [createInnoFinding()], warnings: [] }]
    }
  } as unknown as PeParseResult
});

void test("Inno Setup download decodes the validated embedded PE engine", async () => {
  const dom = installDownloadDom();
  const fixture = createInnoSetupFixture();
  const messages: Array<string | null | undefined> = [];
  try {
    dom.button.setAttribute("data-inno-table-offset", "16");
    const handler = createPeInnoSetupDownloadClickHandler({
      getFile: () => fixture.file,
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    await handler({ target: dom.button } as unknown as Event);

    const blob = expectDefined(dom.getBlob());
    assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), fixture.decodedEngine);
    assert.equal(expectDefined(dom.getAnchor()).download, "inno.exe.inno-setup-engine.exe");
    assert.equal(expectDefined(dom.getAnchor()).clicked, 1);
    assert.equal(dom.button.disabled, false);
    assert.equal(dom.button.textContent, "Download");
    assert.equal(dom.button.getAttribute("aria-busy"), null);
    assert.deepEqual(messages, [null]);
  } finally {
    dom.restore();
  }
});

void test("Inno Setup download rejects a stale table offset", async () => {
  const dom = installDownloadDom();
  const messages: Array<string | null | undefined> = [];
  try {
    dom.button.setAttribute("data-inno-table-offset", "17");
    const handler = createPeInnoSetupDownloadClickHandler({
      getFile: () => createInnoSetupFixture().file,
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    await handler({ target: dom.button } as unknown as Event);

    assert.deepEqual(messages, ["Inno Setup engine is not available."]);
    assert.equal(dom.getAnchor(), null);
  } finally {
    dom.restore();
  }
});

void test("Inno Setup download reports a missing file", async () => {
  const dom = installDownloadDom();
  const messages: Array<string | null | undefined> = [];
  try {
    const handler = createPeInnoSetupDownloadClickHandler({
      getFile: () => null,
      getParseResult: createParseResult,
      setStatusMessage: message => messages.push(message)
    });

    await handler({ target: dom.button } as unknown as Event);

    assert.deepEqual(messages, ["No file selected."]);
  } finally {
    dom.restore();
  }
});
