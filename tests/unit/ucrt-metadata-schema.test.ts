"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isUcrtMetadataChunk,
  isUcrtMetadataManifest,
  type UcrtMetadataChunk,
  type UcrtMetadataManifest
} from "../../ucrt-metadata-schema.js";

const source = {
  headerPackageName: "Microsoft.Windows.SDK.CPP",
  importLibraryPackageName: "Microsoft.Windows.SDK.CPP.x64",
  packageVersion: "10.0.28000.1839",
  headerRoot: "c/Include/10.0.28000.0/ucrt",
  importLibraryPath: "c/ucrt/x64/ucrt.lib",
  architecture: "x64"
};

const manifest: UcrtMetadataManifest = {
  formatVersion: 1,
  generatedAt: "2026-06-26T00:00:00.000Z",
  source,
  entryCounts: { dlls: 1, entries: 1 },
  chunks: [{ dll: "ucrtbase.dll", moduleKey: "ucrtbase.dll", path: "ucrtbase.dll.json", entries: 1 }]
};

const chunk: UcrtMetadataChunk = {
  formatVersion: 1,
  generatedAt: manifest.generatedAt,
  source,
  dll: "ucrtbase.dll",
  moduleKey: "ucrtbase.dll",
  entryCount: 1,
  entries: {
    printf: {
      sourceKind: "ucrt",
      id: "UCRT:ucrtbase.dll:printf",
      module: "ucrtbase.dll",
      entrypoint: "printf",
      namespace: "UCRT",
      api: "printf",
      signature: "int printf(const char * param1, ...)",
      returnType: "int",
      rawReturnType: "int",
      parameters: [{
        name: null,
        type: "const char *",
        rawType: "const char *",
        direction: "in",
        x86StackBytes: 4
      }],
      callingConvention: "cdecl",
      x86StackBytes: 0,
      variadic: true,
      setLastError: false,
      characterSet: null,
      architecture: [],
      platform: []
    }
  }
};

const printfEntry = chunk.entries["printf"];
if (!printfEntry) throw new Error("Missing printf fixture entry.");
const printfParameter = printfEntry.parameters[0];
if (!printfParameter) throw new Error("Missing printf fixture parameter.");

void test("UCRT metadata schema accepts valid manifest and chunk shapes", () => {
  assert.equal(isUcrtMetadataManifest(manifest), true);
  assert.equal(isUcrtMetadataChunk(chunk), true);
});

void test("UCRT metadata schema rejects malformed entries", () => {
  assert.equal(isUcrtMetadataManifest({ ...manifest, chunks: [{ dll: "ucrtbase.dll" }] }), false);
  assert.equal(isUcrtMetadataChunk({
    ...chunk,
    entries: { printf: { ...chunk.entries["printf"], sourceKind: "winapi" } }
  }), false);
  assert.equal(isUcrtMetadataChunk({
    ...chunk,
    entries: {
      printf: {
        ...printfEntry,
        parameters: [{ ...printfParameter, direction: "sideways" }]
      }
    }
  }), false);
});
