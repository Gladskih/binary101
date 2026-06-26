"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createWinapiMetadataLookup,
  enrichPeImportMetadata
} from "../../../../../analyzers/pe/imports/winapi-metadata.js";
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

const createEntry = (
  module: string,
  entrypoint: string,
  namespace = "Windows.Win32.System.Threading"
): WinapiMetadataEntry => ({
  id: `MethodDef:${module}:${entrypoint}`,
  module,
  entrypoint,
  namespace,
  api: entrypoint,
  signature: `void ${entrypoint}(u4 milliseconds)`,
  returnType: "void",
  rawReturnType: "void",
  parameters: [{ name: "milliseconds", type: "u4", rawType: "u4", x86StackBytes: 4 }],
  callingConvention: "winapi",
  x86StackBytes: 4,
  variadic: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: ["windows5.1.2600"]
});

const createChunk = (
  dll: string,
  entries: Record<string, WinapiMetadataEntry>
): WinapiMetadataChunk => ({
  formatVersion: 1,
  generatedAt: "2026-06-26T00:00:00.000Z",
  source,
  dll,
  moduleKey: dll.toLowerCase(),
  entryCount: Object.keys(entries).length,
  entries
});

const manifest: WinapiMetadataManifest = {
  formatVersion: 1,
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
  formatVersion: 1,
  generatedAt: manifest.generatedAt,
  source,
  entryCount: 2,
  referenceCount: 2,
  entries: {
    MessageBoxW: ["user32.dll"],
    Sleep: ["kernel32.dll"]
  }
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
