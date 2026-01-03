"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import { hex } from "../../binary-utils.js";
import { computePeChecksum, createPeChecksumClickHandler } from "../../ui/pe-checksum-controls.js";
import { FakeHTMLElement, installFakeDom } from "../helpers/fake-dom.js";
import { MockFile } from "../helpers/mock-file.js";

const createMinimalPe = (checksum: number, e_lfanew = 0, hasCert = false): PeParseResult =>
  ({
    dos: { e_lfanew },
    opt: { CheckSum: checksum },
    hasCert
  }) as unknown as PeParseResult;

void test("computePeChecksum skips checksum dword and folds the sum", async () => {
  const bytes = new Uint8Array([
    0x04, 0x03, 0x02, 0x01,
    0x10, 0x20, 0x30, 0x40,
    0xaa, 0xbb, 0xcc, 0xdd
  ]);
  const file = new MockFile(bytes, "sample.bin");

  const result = await computePeChecksum(file as unknown as File, 4);
  assert.equal(result.checksum, 0x9d89);
  assert.deepEqual(result.warnings, []);
});

void test("computePeChecksum pads trailing bytes when needed", async () => {
  const bytes = new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x02, 0x00]);
  const file = new MockFile(bytes, "short.bin");

  const result = await computePeChecksum(file as unknown as File, 0);
  assert.equal(result.checksum, 8);
  assert.deepEqual(result.warnings, []);
});

void test("computePeChecksum uses 16-bit folding for large sums", async () => {
  const bytes = new Uint8Array(65536).fill(0xff);
  const file = new MockFile(bytes, "large.bin");

  const result = await computePeChecksum(file as unknown as File, 0);
  assert.equal(result.checksum, 0x1ffff);
  assert.deepEqual(result.warnings, []);
});

void test("computePeChecksum reports invalid offsets", async () => {
  const bytes = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
  const file = new MockFile(bytes, "bad.bin");

  const misaligned = await computePeChecksum(file as unknown as File, 2);
  assert.equal(misaligned.checksum, null);
  assert.ok(misaligned.warnings[0]?.includes("dword"));

  const outOfBounds = await computePeChecksum(file as unknown as File, 12);
  assert.equal(outOfBounds.checksum, null);
  assert.ok(outOfBounds.warnings[0]?.includes("outside"));
});

void test("pe checksum handler updates status on match", async () => {
  const status = new FakeHTMLElement();
  const computed = new FakeHTMLElement();
  const button = new FakeHTMLElement();
  (button as FakeHTMLElement & { id: string }).id = "peChecksumValidateButton";
  button.textContent = "Validate CheckSum";

  const dom = installFakeDom({
    peChecksumStatus: status,
    peChecksumComputed: computed
  });

  try {
    const file = new MockFile(new Uint8Array(100), "pe.bin");
    const pe = createMinimalPe(100);
    const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
    const messages: Array<string | null | undefined> = [];

    const handler = createPeChecksumClickHandler({
      getParseResult: () => parseResult,
      getFile: () => file as unknown as File,
      setStatusMessage: message => messages.push(message)
    });

    await handler({ target: button } as unknown as Event);

    assert.equal(status.textContent, "Matches stored value.");
    assert.equal(computed.textContent, hex(100, 8));
    assert.equal(button.disabled, false);
    assert.equal(button.textContent, "Re-validate CheckSum");
    assert.deepEqual(messages, []);
  } finally {
    dom.restore();
  }
});

void test("pe checksum handler reports missing file selection", async () => {
  const status = new FakeHTMLElement();
  const computed = new FakeHTMLElement();
  const button = new FakeHTMLElement();
  (button as FakeHTMLElement & { id: string }).id = "peChecksumValidateButton";

  const dom = installFakeDom({
    peChecksumStatus: status,
    peChecksumComputed: computed
  });

  try {
    const pe = createMinimalPe(0);
    const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
    const messages: Array<string | null | undefined> = [];

    const handler = createPeChecksumClickHandler({
      getParseResult: () => parseResult,
      getFile: () => null,
      setStatusMessage: message => messages.push(message)
    });

    await handler({ target: button } as unknown as Event);

    assert.deepEqual(messages, ["No file selected."]);
  } finally {
    dom.restore();
  }
});

void test("pe checksum handler reports checksum offset errors", async () => {
  const status = new FakeHTMLElement();
  const computed = new FakeHTMLElement();
  const button = new FakeHTMLElement();
  (button as FakeHTMLElement & { id: string }).id = "peChecksumValidateButton";
  button.textContent = "Validate CheckSum";

  const dom = installFakeDom({
    peChecksumStatus: status,
    peChecksumComputed: computed
  });

  try {
    const file = new MockFile(new Uint8Array(32), "tiny.bin");
    const pe = createMinimalPe(0);
    const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };

    const handler = createPeChecksumClickHandler({
      getParseResult: () => parseResult,
      getFile: () => file as unknown as File,
      setStatusMessage: () => {}
    });

    await handler({ target: button } as unknown as Event);

    assert.ok(status.textContent?.includes("outside"));
    assert.equal(computed.textContent, "-");
    assert.equal(button.textContent, "Retry CheckSum");
  } finally {
    dom.restore();
  }
});

void test("pe checksum handler adds note for zero stored checksum", async () => {
  const status = new FakeHTMLElement();
  const computed = new FakeHTMLElement();
  const button = new FakeHTMLElement();
  (button as FakeHTMLElement & { id: string }).id = "peChecksumValidateButton";
  button.textContent = "Validate CheckSum";

  const dom = installFakeDom({
    peChecksumStatus: status,
    peChecksumComputed: computed
  });

  try {
    const file = new MockFile(new Uint8Array(100), "pe.bin");
    const pe = createMinimalPe(0);
    const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };

    const handler = createPeChecksumClickHandler({
      getParseResult: () => parseResult,
      getFile: () => file as unknown as File,
      setStatusMessage: () => {}
    });

    await handler({ target: button } as unknown as Event);

    assert.ok(status.textContent?.includes("Does not match stored value."));
    assert.ok(status.textContent?.includes("stored CheckSum is 0"));
  } finally {
    dom.restore();
  }
});

void test("pe checksum handler notes Authenticode when mismatch", async () => {
  const status = new FakeHTMLElement();
  const computed = new FakeHTMLElement();
  const button = new FakeHTMLElement();
  (button as FakeHTMLElement & { id: string }).id = "peChecksumValidateButton";
  button.textContent = "Validate CheckSum";

  const dom = installFakeDom({
    peChecksumStatus: status,
    peChecksumComputed: computed
  });

  try {
    const file = new MockFile(new Uint8Array(100), "pe.bin");
    const pe = createMinimalPe(99, 0, true);
    const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };

    const handler = createPeChecksumClickHandler({
      getParseResult: () => parseResult,
      getFile: () => file as unknown as File,
      setStatusMessage: () => {}
    });

    await handler({ target: button } as unknown as Event);

    assert.ok(status.textContent?.includes("Does not match stored value."));
    assert.ok(status.textContent?.includes("Authenticode"));
  } finally {
    dom.restore();
  }
});
