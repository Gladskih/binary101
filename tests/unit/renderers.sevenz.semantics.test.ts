"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  KNOWN_METHODS,
  describeCoders,
  describeFileType,
  describeHeaderKind
} from "../../renderers/sevenz/semantics.js";
import type { SevenZipFileSummary } from "../../analyzers/sevenz/types.js";

void test("describeCoders describes empty and populated coder chains", () => {
  assert.strictEqual(describeCoders(undefined), "-");
  assert.strictEqual(describeCoders([]), "-");

  const withArch = describeCoders([
    {
      id: "LZMA",
      methodId: "030101",
      numInStreams: 1,
      numOutStreams: 1,
      properties: null,
      archHint: "x86",
      isEncryption: false
    }
  ]);
  assert.strictEqual(withArch, "LZMA (x86, id 030101)");

  const withoutArchOrId = describeCoders([
    {
      id: "CUSTOM",
      methodId: "",
      numInStreams: 1,
      numOutStreams: 1,
      properties: null,
      isEncryption: false
    }
  ]);
  assert.strictEqual(withoutArchOrId, "CUSTOM");

  const twoCoders = describeCoders([
    {
      id: "A",
      methodId: "01",
      numInStreams: 1,
      numOutStreams: 1,
      properties: null,
      isEncryption: false
    },
    {
      id: "B",
      methodId: "02",
      numInStreams: 1,
      numOutStreams: 1,
      properties: null,
      isEncryption: false
    }
  ]);
  assert.match(twoCoders, /^A/);
  assert.match(twoCoders, /B/);
  assert.match(twoCoders, /\+/);
});

void test("describeHeaderKind covers all branches including unknown and custom", () => {
  assert.strictEqual(describeHeaderKind(undefined), "Unknown (next header not parsed)");

  assert.match(describeHeaderKind({ kind: "header" }), /Plain Header structure/);
  assert.match(describeHeaderKind({ kind: "encoded" }), /Encoded Header/);
  assert.match(describeHeaderKind({ kind: "empty" }), /Empty Header/);

  const unknownText = describeHeaderKind({ kind: "unknown", type: 0x99 });
  assert.match(unknownText, /0x99/);

  // Unexpected kinds are passed through as generic strings.
  assert.strictEqual(describeHeaderKind({ kind: "custom" }), "custom");
});

void test("describeFileType gives priority to anti and directory flags", () => {
  assert.strictEqual(describeFileType({ isAnti: true } as unknown as SevenZipFileSummary), "Anti-item");
  assert.strictEqual(
    describeFileType({ isDirectory: true } as unknown as SevenZipFileSummary),
    "Directory"
  );

  // Directory takes precedence over other flags.
  assert.strictEqual(
    describeFileType(
      {
        isDirectory: true,
        isEmptyStream: true,
        hasStream: false
      } as unknown as SevenZipFileSummary
    ),
    "Directory"
  );

  assert.strictEqual(
    describeFileType({ isEmptyStream: true, isEmptyFile: true } as unknown as SevenZipFileSummary),
    "Empty file"
  );
  assert.strictEqual(
    describeFileType({ isEmptyStream: true } as unknown as SevenZipFileSummary),
    "Metadata only"
  );
  assert.strictEqual(
    describeFileType({ hasStream: false } as unknown as SevenZipFileSummary),
    "No stream"
  );
  assert.strictEqual(describeFileType({} as unknown as SevenZipFileSummary), "File");
});

void test("KNOWN_METHODS catalog includes common compression and encryption methods", () => {
  const hasLzma2 = KNOWN_METHODS.some(([id, name]) => id === "21" && name === "LZMA2");
  const hasAes = KNOWN_METHODS.some(([id, name]) => id === "06f10701" && name === "AES-256");
  assert.ok(hasLzma2);
  assert.ok(hasAes);
});
