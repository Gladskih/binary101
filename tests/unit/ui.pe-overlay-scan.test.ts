import assert from "node:assert/strict";
import { test } from "node:test";
import type { FileRangeReader } from "../../analyzers/file-range-reader.js";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeOverlayRange, PeOverlayScanOptions } from "../../analyzers/pe/overlay.js";
import {
  createPeOverlayScanActions,
  createPeOverlayScanController,
  readPeOverlayScanButtonRange
} from "../../ui/pe-overlay-scan.js";
import { FakeHTMLElement, FakeHTMLProgressElement, flushTimers, installFakeDom } from "../helpers/fake-dom.js";
import { MockFile } from "../helpers/mock-file.js";

// IDs are part of the renderer/controller DOM contract for one concrete overlay range.
const OVERLAY_START = 4;
const OVERLAY_END = 12;
const OVERLAY_SIZE = OVERLAY_END - OVERLAY_START;

class FakeClosestElement {
  constructor(private readonly attrs: Record<string, string>) {}
  closest(selector: string): FakeClosestElement | null {
    return selector === "[data-pe-overlay-scan]" ? this : null;
  }
  getAttribute(name: string): string | null {
    return this.attrs[name] ?? null;
  }
}

const installFakeElementGlobal = (): (() => void) => {
  const globals = globalThis as unknown as { Element?: unknown };
  const originalElement = globals.Element;
  globals.Element = FakeClosestElement;
  return () => {
    globals.Element = originalElement;
  };
};

const overlayScanElementId = (suffix: string): string =>
  `peOverlayScan_${OVERLAY_START}_${OVERLAY_END}_${suffix}`;

const createOverlayRange = (): PeOverlayRange => ({
  start: OVERLAY_START,
  end: OVERLAY_END,
  size: OVERLAY_SIZE,
  findings: []
});

const createParseResult = (range: PeOverlayRange): ParseForUiResult => ({
  analyzer: "pe",
  parsed: { overlay: { ranges: [range] } } as unknown as PeParseResult
});

const installOverlayScanDom = () => {
  const button = new FakeHTMLElement();
  const cancelButton = new FakeHTMLElement();
  const progress = new FakeHTMLProgressElement();
  const text = new FakeHTMLElement();
  const dom = installFakeDom({
    [overlayScanElementId("button")]: button,
    [overlayScanElementId("cancel")]: cancelButton,
    [overlayScanElementId("progress")]: progress,
    [overlayScanElementId("text")]: text
  });
  return { ...dom, button, cancelButton, progress, text };
};

void test("pe overlay scan controller updates progress and renders when complete", async () => {
  const dom = installOverlayScanDom();
  const range = createOverlayRange();
  const file = new MockFile(new Uint8Array(OVERLAY_END), "pe.bin");
  const parseResult = createParseResult(range);
  const scannedRange: PeOverlayRange = {
    ...range,
    findings: [{
      start: OVERLAY_START,
      end: OVERLAY_END,
      size: OVERLAY_SIZE,
      detectedType: "ZIP archive",
      endDescription: "End is estimated."
    }],
    embeddedScan: { status: "complete", scannedBytes: OVERLAY_SIZE }
  };
  const renders: ParseForUiResult[] = [];
  const statuses: string[] = [];
  const scan = async (
    _file: File,
    _reader: FileRangeReader,
    _range: PeOverlayRange,
    opts: PeOverlayScanOptions
  ): Promise<PeOverlayRange> => {
    opts.onProgress?.({ stage: "scanning", bytesScanned: 4, totalBytes: OVERLAY_SIZE, findingsFound: 0 });
    opts.onProgress?.({ stage: "done", bytesScanned: OVERLAY_SIZE, totalBytes: OVERLAY_SIZE, findingsFound: 1 });
    return scannedRange;
  };
  const controller = createPeOverlayScanController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    setStatusMessage: message => {
      statuses.push(message ?? "");
    },
    scan
  });
  controller.start(file, range);
  await flushTimers();
  assert.equal(renders.length, 1);
  assert.equal((parseResult.parsed as PeParseResult).overlay?.ranges[0], scannedRange);
  assert.equal(dom.progress.max, OVERLAY_SIZE);
  assert.equal(dom.progress.value, OVERLAY_SIZE);
  assert.ok(dom.text.textContent?.includes("Done."));
  assert.equal(dom.button.disabled, false);
  assert.equal(dom.cancelButton.hidden, true);
  assert.deepEqual(statuses, ["PE overlay scan complete: 1 finding(s)."]);
  dom.restore();
});

void test("pe overlay scan controller does not render after cancel", async () => {
  const dom = installOverlayScanDom();
  const range = createOverlayRange();
  const file = new MockFile(new Uint8Array(OVERLAY_END), "pe.bin");
  const parseResult = createParseResult(range);
  const renders: ParseForUiResult[] = [];
  const statuses: string[] = [];
  const controller = createPeOverlayScanController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    setStatusMessage: message => {
      statuses.push(message ?? "");
    },
    scan: async () => {
      await flushTimers();
      return { ...range, embeddedScan: { status: "complete", scannedBytes: OVERLAY_SIZE } };
    }
  });
  controller.start(file, range);
  controller.cancel();
  await flushTimers();
  await flushTimers();
  assert.equal(renders.length, 0);
  assert.equal((parseResult.parsed as PeParseResult).overlay?.ranges[0], range);
  assert.deepEqual(statuses, ["PE overlay scan cancelled."]);
  assert.equal(dom.button.disabled, false);
  assert.equal(dom.cancelButton.hidden, true);
  dom.restore();
});

void test("pe overlay scan controller ignores results when file changes", async () => {
  const dom = installOverlayScanDom();
  const range = createOverlayRange();
  const file = new MockFile(new Uint8Array(OVERLAY_END), "pe.bin");
  const otherFile = new MockFile(new Uint8Array(OVERLAY_END), "other.bin");
  const parseResult = createParseResult(range);
  const renders: ParseForUiResult[] = [];
  const controller = createPeOverlayScanController({
    getCurrentFile: () => otherFile,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    setStatusMessage: () => {},
    scan: async () => ({ ...range, embeddedScan: { status: "complete", scannedBytes: OVERLAY_SIZE } })
  });
  controller.start(file, range);
  await flushTimers();
  assert.equal(renders.length, 0);
  assert.equal((parseResult.parsed as PeParseResult).overlay?.ranges[0], range);
  dom.restore();
});

void test("readPeOverlayScanButtonRange reads valid offsets and rejects invalid ranges", () => {
  const restoreElement = installFakeElementGlobal();
  try {
    const valid = readPeOverlayScanButtonRange(new FakeClosestElement({
      "data-overlay-start": String(OVERLAY_START),
      "data-overlay-end": String(OVERLAY_END)
    }) as unknown as Element);
    const invalid = readPeOverlayScanButtonRange(new FakeClosestElement({
      "data-overlay-start": String(OVERLAY_END),
      "data-overlay-end": String(OVERLAY_START)
    }) as unknown as Element);
    assert.deepEqual(valid, { start: OVERLAY_START, end: OVERLAY_END, size: OVERLAY_SIZE, findings: [] });
    assert.equal(invalid, null);
  } finally {
    restoreElement();
  }
});

void test("pe overlay scan actions start scans from button clicks", async () => {
  const dom = installOverlayScanDom();
  const restoreElement = installFakeElementGlobal();
  try {
    const range = createOverlayRange();
    const file = new MockFile(new Uint8Array(OVERLAY_END), "pe.bin");
    const parseResult = createParseResult(range);
    let scannedRange: PeOverlayRange | null = null;
    const actions = createPeOverlayScanActions({
      getCurrentFile: () => file,
      getCurrentParseResult: () => parseResult,
      renderResult: () => {},
      setStatusMessage: () => {},
      scan: async (_file, _reader, candidate) => {
        scannedRange = candidate;
        return { ...candidate, embeddedScan: { status: "complete", scannedBytes: candidate.size } };
      }
    });
    const handled = actions.handleClick(new FakeClosestElement({
      "data-overlay-start": String(OVERLAY_START),
      "data-overlay-end": String(OVERLAY_END)
    }) as unknown as Element);
    await flushTimers();
    assert.equal(handled, true);
    assert.equal(scannedRange, range);
  } finally {
    restoreElement();
    dom.restore();
  }
});
