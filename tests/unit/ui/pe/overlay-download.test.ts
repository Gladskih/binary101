"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../../../analyzers/index.js";
import type { PeParseResult } from "../../../../analyzers/pe/index.js";
import { createPeOverlayDownloadClickHandler } from "../../../../ui/pe-overlay-download.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const createOverlayDownloadFixture = () => {
  const fileName = "app.exe";
  const fileBytes = Uint8Array.of(0, 1, 2, 3, 4, 5);
  const range = { start: 2, end: 5 };
  return {
    fileName,
    fileBytes,
    range,
    finding: { start: range.start + 1, end: range.end },
    rangeSize: range.end - range.start,
    tamperedEnd: range.end + 1,
    expectedBytes: fileBytes.subarray(range.start, range.end),
    expectedDownloadName: `${fileName}.overlay-${range.start}-${range.end}.bin`,
    rangeUnavailableMessage: "PE overlay range is not available."
  };
};
type OverlayDownloadFixture = ReturnType<typeof createOverlayDownloadFixture>;

const installOverlayDownloadStubs = () => {
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
      return selector === "[data-pe-overlay-download]" ? this : null;
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
    return "blob:overlay";
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

const createPeOverlayParseResult = (fixture: OverlayDownloadFixture): ParseForUiResult => ({
  analyzer: "pe",
  parsed: {
    overlay: {
      ranges: [{
        start: fixture.range.start,
        end: fixture.range.end,
        size: fixture.rangeSize,
        findings: [{
          start: fixture.finding.start,
          end: fixture.finding.end,
          size: fixture.finding.end - fixture.finding.start,
          detectedType: "Synthetic payload",
          endDescription: "Synthetic test payload."
        }]
      }]
    }
  } as PeParseResult
});

const createPeNsisParseResult = (fixture: OverlayDownloadFixture): ParseForUiResult => ({
  analyzer: "pe",
  parsed: {
    opt: { Magic: 0x10b },
    packers: {
      reports: [{ id: "upx", findings: [], warnings: [] }, {
        id: "nsis-installer",
        findings: [{
          id: "nsis-installer",
          name: "Other NSIS installer",
          kind: "installer",
          confidence: "high",
          evidence: ["Other NSIS range"],
          compressedHeaderSize: 1,
          firstHeaderOffset: 0,
          flags: 0,
          followingDataSize: 1
        }, {
          id: "nsis-installer",
          name: "NSIS installer",
          kind: "installer",
          confidence: "high",
          evidence: ["NSIS verified"],
          compressedHeaderSize: 1,
          firstHeaderOffset: fixture.range.start,
          flags: 0,
          followingDataSize: fixture.rangeSize
        }],
        warnings: []
      }]
    }
  } as unknown as PeParseResult
});

const createHandler = (
  fixture: OverlayDownloadFixture,
  messages: Array<string | null | undefined>
) =>
  createPeOverlayDownloadClickHandler({
    getFile: () => new MockFile(fixture.fileBytes, fixture.fileName),
    getParseResult: () => createPeOverlayParseResult(fixture),
    setStatusMessage: message => messages.push(message)
  });

const setOverlayButtonRange = (
  button: ReturnType<typeof installOverlayDownloadStubs>["button"],
  fixture: OverlayDownloadFixture,
  end: number
): void => {
  button.setAttribute("data-pe-overlay-download", "");
  button.setAttribute("data-overlay-start", String(fixture.range.start));
  button.setAttribute("data-overlay-end", String(end));
};

void test("PE overlay download handler slices the selected validated range", async () => {
  const stubs = installOverlayDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  const fixture = createOverlayDownloadFixture();
  try {
    setOverlayButtonRange(stubs.button, fixture, fixture.range.end);
    const handler = createHandler(fixture, messages);

    handler({ target: stubs.button } as unknown as Event);

    const anchor = expectDefined(stubs.getAnchor());
    assert.equal(anchor.download, fixture.expectedDownloadName);
    assert.equal(anchor.clicked, 1);
    assert.deepEqual(new Uint8Array(await expectDefined(stubs.getCreatedBlob()).arrayBuffer()), fixture.expectedBytes);
  assert.deepEqual(messages, [null]);
  } finally {
    stubs.restore();
  }
});

void test("PE overlay download handler slices a validated detected payload range", async () => {
  const stubs = installOverlayDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  const fixture = createOverlayDownloadFixture();
  try {
    stubs.button.setAttribute("data-pe-overlay-download", "");
    stubs.button.setAttribute("data-overlay-start", String(fixture.finding.start));
    stubs.button.setAttribute("data-overlay-end", String(fixture.finding.end));
    const handler = createHandler(fixture, messages);

    handler({ target: stubs.button } as unknown as Event);

    assert.deepEqual(
      new Uint8Array(await expectDefined(stubs.getCreatedBlob()).arrayBuffer()),
      fixture.fileBytes.subarray(fixture.finding.start, fixture.finding.end)
    );
    assert.deepEqual(messages, [null]);
  } finally {
    stubs.restore();
  }
});

void test("PE overlay download handler accepts a validated NSIS installer range", async () => {
  const stubs = installOverlayDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  const fixture = createOverlayDownloadFixture();
  try {
    setOverlayButtonRange(stubs.button, fixture, fixture.range.end);
    const handler = createPeOverlayDownloadClickHandler({
      getFile: () => new MockFile(fixture.fileBytes, fixture.fileName),
      getParseResult: () => createPeNsisParseResult(fixture),
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.deepEqual(
      new Uint8Array(await expectDefined(stubs.getCreatedBlob()).arrayBuffer()),
      fixture.expectedBytes
    );
    assert.deepEqual(messages, [null]);
  } finally {
    stubs.restore();
  }
});

void test("PE overlay download handler rejects a tampered NSIS installer range", () => {
  const stubs = installOverlayDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  const fixture = createOverlayDownloadFixture();
  try {
    setOverlayButtonRange(stubs.button, fixture, fixture.tamperedEnd);
    const handler = createPeOverlayDownloadClickHandler({
      getFile: () => new MockFile(fixture.fileBytes, fixture.fileName),
      getParseResult: () => createPeNsisParseResult(fixture),
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.deepEqual(messages, [fixture.rangeUnavailableMessage]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});

void test("PE overlay download handler rejects a wrong NSIS start with a matching end", () => {
  const stubs = installOverlayDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  const fixture = createOverlayDownloadFixture();
  try {
    stubs.button.setAttribute("data-pe-overlay-download", "");
    stubs.button.setAttribute("data-overlay-start", String(fixture.range.start + 1));
    stubs.button.setAttribute("data-overlay-end", String(fixture.range.end));
    const handler = createPeOverlayDownloadClickHandler({
      getFile: () => new MockFile(fixture.fileBytes, fixture.fileName),
      getParseResult: () => createPeNsisParseResult(fixture),
      setStatusMessage: message => messages.push(message)
    });

    handler({ target: stubs.button } as unknown as Event);

    assert.deepEqual(messages, [fixture.rangeUnavailableMessage]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});

void test("PE overlay download handler rejects stale or tampered ranges", () => {
  const stubs = installOverlayDownloadStubs();
  const messages: Array<string | null | undefined> = [];
  const fixture = createOverlayDownloadFixture();
  try {
    setOverlayButtonRange(stubs.button, fixture, fixture.tamperedEnd);
    const handler = createHandler(fixture, messages);

    handler({ target: stubs.button } as unknown as Event);

    assert.deepEqual(messages, [fixture.rangeUnavailableMessage]);
    assert.equal(stubs.getAnchor(), null);
  } finally {
    stubs.restore();
  }
});
