"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isWinapiMetadataChunk,
  isWinapiMetadataEntrypointIndex,
  isWinapiMetadataManifest,
  type WinapiMetadataChunk,
  type WinapiMetadataEntrypointIndex,
  type WinapiMetadataManifest
} from "../../winapi-metadata-schema.js";

const source = {
  packageName: "Microsoft.Windows.SDK.Win32Metadata",
  packageVersion: "71.0.14-preview",
  fileName: "Windows.Win32.winmd"
};

const manifest: WinapiMetadataManifest = {
  formatVersion: 1,
  generatedAt: "2026-06-26T00:00:00.000Z",
  source,
  entryCounts: { dlls: 1, entries: 1 },
  entrypointIndex: { path: "entrypoint-index.json", entries: 1, references: 1 },
  chunks: [{ dll: "KERNEL32.dll", moduleKey: "kernel32.dll", path: "kernel32.dll.json", entries: 1 }]
};

const entrypointIndex: WinapiMetadataEntrypointIndex = {
  formatVersion: 1,
  generatedAt: manifest.generatedAt,
  source,
  entryCount: 1,
  referenceCount: 1,
  entries: { Sleep: ["kernel32.dll"] }
};

const chunk: WinapiMetadataChunk = {
  formatVersion: 1,
  generatedAt: manifest.generatedAt,
  source,
  dll: "KERNEL32.dll",
  moduleKey: "kernel32.dll",
  entryCount: 1,
  entries: {
    Sleep: {
      sourceKind: "winapi",
      id: "MethodDef:0x06000001;ImplMap:1",
      module: "KERNEL32.dll",
      entrypoint: "Sleep",
      namespace: "Windows.Win32.System.Threading",
      api: "Sleep",
      signature: "void Sleep(u4 dwMilliseconds)",
      returnType: "void",
      rawReturnType: "void",
      parameters: [{ name: "dwMilliseconds", type: "u4", rawType: "u4", x86StackBytes: 4 }],
      callingConvention: "winapi",
      x86StackBytes: 4,
      variadic: false,
      setLastError: false,
      characterSet: null,
      architecture: [],
      platform: ["windows5.1.2600"]
    }
  }
};

void test("WinAPI metadata schema accepts valid manifest and chunk shapes", () => {
  assert.equal(isWinapiMetadataManifest(manifest), true);
  assert.equal(isWinapiMetadataChunk(chunk), true);
  assert.equal(isWinapiMetadataEntrypointIndex(entrypointIndex), true);
});

void test("WinAPI metadata schema rejects wrong versions and malformed entries", () => {
  assert.equal(isWinapiMetadataManifest({ ...manifest, formatVersion: 2 }), false);
  assert.equal(isWinapiMetadataChunk({
    ...chunk,
    entries: { Sleep: { ...chunk.entries["Sleep"], parameters: [{ name: "bad" }] } }
  }), false);
  assert.equal(isWinapiMetadataEntrypointIndex({
    ...entrypointIndex,
    entries: { Sleep: [42] }
  }), false);
});
