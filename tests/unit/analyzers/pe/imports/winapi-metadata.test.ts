"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createPeImportMetadataLookup,
  createWinapiMetadataLookup,
  enrichPeImportMetadata
} from "../../../../../analyzers/pe/imports/winapi-metadata.js";
import type {
  UcrtMetadataChunk,
  UcrtMetadataEntry,
  UcrtMetadataManifest
} from "../../../../../ucrt-metadata-schema.js";
import type {
  WinapiMetadataChunk,
  WinapiMetadataEntrypointIndex,
  WinapiMetadataEntry,
  WinapiMetadataManifest
} from "../../../../../winapi-metadata-schema.js";
import { createPeWithImportLinking } from "../../../../fixtures/pe-import-linking-fixture.js";

const source = {
  packageName: "Microsoft.Windows.SDK.Win32Metadata",
  packageVersion: "71.0.14-preview",
  fileName: "Windows.Win32.winmd"
};

const ucrtSource = {
  headerPackageName: "Microsoft.Windows.SDK.CPP",
  importLibraryPackageName: "Microsoft.Windows.SDK.CPP.x64",
  packageVersion: "10.0.28000.1839",
  headerRoot: "c/Include/10.0.28000.0/ucrt",
  importLibraryPath: "c/ucrt/x64/ucrt.lib",
  architecture: "x64"
};

const createEntry = (
  module: string,
  entrypoint: string,
  namespace = "Windows.Win32.System.Threading"
): WinapiMetadataEntry => ({
  sourceKind: "winapi",
  id: `MethodDef:${module}:${entrypoint}`,
  module,
  entrypoint,
  namespace,
  api: entrypoint,
  signature: `void ${entrypoint}(u4 milliseconds)`,
  returnType: "void",
  rawReturnType: "void",
  parameters: [{
    name: "milliseconds",
    type: "u4",
    rawType: "u4",
    direction: "in",
    x86StackBytes: 4
  }],
  callingConvention: "winapi",
  variadic: false,
  noReturn: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: ["windows5.1.2600"]
});

const createUcrtEntry = (module: string, entrypoint: string): UcrtMetadataEntry => ({
  sourceKind: "ucrt",
  id: `UCRT:${module}:${entrypoint}`,
  module,
  entrypoint,
  namespace: "UCRT.stdio",
  api: entrypoint,
  signature: `int ${entrypoint}(const char * format, ...)`,
  returnType: "int",
  rawReturnType: "int",
  parameters: [{
    name: "format",
    type: "const char *",
    rawType: "const char *",
    direction: "in",
    x86StackBytes: 4
  }],
  callingConvention: "cdecl",
  variadic: true,
  noReturn: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: []
});

const createChunk = (
  dll: string,
  entries: Record<string, WinapiMetadataEntry>
): WinapiMetadataChunk => ({
  formatVersion: 2,
  generatedAt: "2026-06-26T00:00:00.000Z",
  source,
  dll,
  moduleKey: dll.toLowerCase(),
  entryCount: Object.keys(entries).length,
  entries
});

const createUcrtChunk = (
  dll: string,
  entries: Record<string, UcrtMetadataEntry>
): UcrtMetadataChunk => ({
  formatVersion: 2,
  generatedAt: "2026-06-26T00:00:00.000Z",
  source: ucrtSource,
  dll,
  moduleKey: dll.toLowerCase(),
  entryCount: Object.keys(entries).length,
  entries
});

const manifest: WinapiMetadataManifest = {
  formatVersion: 2,
  generatedAt: "2026-06-26T00:00:00.000Z",
  source,
  entryCounts: { dlls: 3, entries: 4 },
  entrypointIndex: { path: "entrypoint-index.json", entries: 2, references: 2 },
  chunks: [
    {
      dll: "api-ms-win-core-synch-l1-2-0.dll",
      moduleKey: "api-ms-win-core-synch-l1-2-0.dll",
      path: "api-ms-win-core-synch-l1-2-0.dll.json",
      entries: 1
    },
    { dll: "KERNEL32.dll", moduleKey: "kernel32.dll", path: "kernel32.dll.json", entries: 1 },
    { dll: "USER32.dll", moduleKey: "user32.dll", path: "user32.dll.json", entries: 2 }
  ]
};

const entrypointIndex: WinapiMetadataEntrypointIndex = {
  formatVersion: 2,
  generatedAt: manifest.generatedAt,
  source,
  entryCount: 2,
  referenceCount: 2,
  entries: {
    MessageBoxW: ["user32.dll"],
    Sleep: ["kernel32.dll"]
  }
};

const ucrtManifest: UcrtMetadataManifest = {
  formatVersion: 2,
  generatedAt: "2026-06-26T00:00:00.000Z",
  source: ucrtSource,
  entryCounts: { dlls: 2, entries: 2 },
  chunks: [
    {
      dll: "api-ms-win-crt-stdio-l1-1-0.dll",
      moduleKey: "api-ms-win-crt-stdio-l1-1-0.dll",
      path: "api-ms-win-crt-stdio-l1-1-0.dll.json",
      entries: 1
    },
    { dll: "ucrtbase.dll", moduleKey: "ucrtbase.dll", path: "ucrtbase.dll.json", entries: 1 }
  ]
};

const createLookup = (seenPaths: string[] = []) => {
  const assets: Record<string, unknown> = {
    "winapi-metadata/manifest.json": manifest,
    "winapi-metadata/entrypoint-index.json": entrypointIndex,
    "winapi-metadata/api-ms-win-core-synch-l1-2-0.dll.json": createChunk(
      "api-ms-win-core-synch-l1-2-0.dll",
      { WaitOnAddress: createEntry("api-ms-win-core-synch-l1-2-0.dll", "WaitOnAddress") }
    ),
    "winapi-metadata/kernel32.dll.json": createChunk("KERNEL32.dll", {
      Sleep: createEntry("KERNEL32.dll", "Sleep")
    }),
    "winapi-metadata/user32.dll.json": createChunk("USER32.dll", {
      MessageBoxA: createEntry("USER32.dll", "MessageBoxA", "Windows.Win32.UI.WindowsAndMessaging"),
      MessageBoxW: createEntry("USER32.dll", "MessageBoxW", "Windows.Win32.UI.WindowsAndMessaging")
    })
  };
  return createWinapiMetadataLookup(async path => {
    seenPaths.push(path);
    return assets[path] ?? null;
  });
};

void test("enrichPeImportMetadata attaches direct exact WinAPI metadata matches", async () => {
  const pe = await enrichPeImportMetadata(createPeWithImportLinking(), createLookup());

  assert.equal(pe.imports.entries[0]?.functions[0]?.winapiMetadata?.module, "KERNEL32.dll");
  assert.equal(pe.imports.entries[1]?.functions[0]?.winapiMetadata?.entrypoint, "MessageBoxW");
});

void test("enrichPeImportMetadata resolves API Set imports through exact entrypoint fallback", async () => {
  const seenPaths: string[] = [];
  const pe = createPeWithImportLinking();
  pe.imports.entries[0]!.dll = "api-ms-win-core-synch-l1-2-0.dll";

  const enriched = await enrichPeImportMetadata(pe, createLookup(seenPaths));

  assert.equal(enriched.imports.entries[0]?.functions[0]?.winapiMetadata?.module, "KERNEL32.dll");
  assert.ok(seenPaths.includes("winapi-metadata/entrypoint-index.json"));
  assert.ok(seenPaths.includes("winapi-metadata/kernel32.dll.json"));
});

void test("enrichPeImportMetadata does not mix decorated Ansi and Unicode entrypoints", async () => {
  const pe = createPeWithImportLinking();
  pe.imports.entries[1]!.functions = [{ hint: 2, name: "MessageBox" }];

  const enriched = await enrichPeImportMetadata(pe, createLookup());

  assert.equal(enriched.imports.entries[1]?.functions[0]?.winapiMetadata, undefined);
});

void test("enrichPeImportMetadata attaches UCRT metadata for api-ms-win-crt imports", async () => {
  const seenPaths: string[] = [];
  const assets: Record<string, unknown> = {
    "winapi-metadata/manifest.json": manifest,
    "ucrt-metadata/manifest.json": ucrtManifest,
    "ucrt-metadata/api-ms-win-crt-stdio-l1-1-0.dll.json": createUcrtChunk(
      "api-ms-win-crt-stdio-l1-1-0.dll",
      { printf: createUcrtEntry("api-ms-win-crt-stdio-l1-1-0.dll", "printf") }
    ),
    "ucrt-metadata/ucrtbase.dll.json": createUcrtChunk(
      "ucrtbase.dll",
      { printf: createUcrtEntry("ucrtbase.dll", "printf") }
    )
  };
  const pe = createPeWithImportLinking();
  pe.imports.entries[0]!.dll = "api-ms-win-crt-stdio-l1-1-0.dll";
  pe.imports.entries[0]!.functions = [{ hint: 1, name: "printf" }];
  const lookup = createPeImportMetadataLookup(async path => {
    seenPaths.push(path);
    return assets[path] ?? null;
  });

  const enriched = await enrichPeImportMetadata(pe, lookup);

  assert.equal(enriched.imports.entries[0]?.functions[0]?.apiMetadata?.sourceKind, "ucrt");
  assert.equal(enriched.imports.entries[0]?.functions[0]?.apiMetadata?.module, "api-ms-win-crt-stdio-l1-1-0.dll");
  assert.equal(enriched.imports.entries[0]?.functions[0]?.winapiMetadata, undefined);
  assert.ok(seenPaths.includes("ucrt-metadata/manifest.json"));
  assert.ok(!seenPaths.includes("winapi-metadata/entrypoint-index.json"));
});
