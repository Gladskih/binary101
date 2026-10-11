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
import {
  createWinapiImportMetadataEntry as createEntry, createUcrtImportMetadataEntry as createUcrtEntry
} from "../../../../fixtures/pe-import-api-metadata.js";
import { createPeWithImportLinking } from "../../../../fixtures/pe-import-linking-fixture.js";
import { createPeImportNamesFile } from "../../../../fixtures/pe-import-names-file.js";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { getImportFunctionDisplayName } from "../../../../../analyzers/pe/imports/function-name.js";
import {
  createImportFunctionTableModel, renderImportFunctionTable
} from "../../../../../renderers/pe/import-function-table.js";

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

void test("WinAPI and UCRT enrichment preserves unknown C++ import presentation and raw lookup keys", async () => {
  const parsed = await parsePe(new File([createPeImportNamesFile()], "mixed-imports.exe"));
  assert.ok(parsed && isPeWindowsParseResult(parsed) && parsed.delayImports);
  parsed.imports.entries[0]!.dll = "KERNEL32.dll";
  parsed.delayImports.entries[0]!.name = "ucrtbase.dll";
  parsed.delayImports.entries[0]!.functions[0]!.name = "printf";
  const sleep = createEntry("KERNEL32.dll", "Sleep");
  const printf = createUcrtEntry("ucrtbase.dll", "printf");
  const keys: string[] = [];

  const enriched = await enrichPeImportMetadata(parsed, { findEntry: async (dll, name) => {
    keys.push(`${dll}:${name}`);
    if (dll === "KERNEL32.dll" && name === "Sleep") return sleep;
    if (dll === "ucrtbase.dll" && name === "printf") return printf;
    return null;
  } });

  assert.equal(enriched.imports.entries[0]?.functions[0]?.apiMetadata, sleep);
  assert.equal(enriched.imports.entries[0]?.functions[0]?.winapiMetadata, sleep);
  assert.equal(enriched.delayImports?.entries[0]?.functions[0]?.apiMetadata, printf);
  assert.equal(enriched.delayImports?.entries[0]?.functions[0]?.winapiMetadata, undefined);
  assert.equal(keys.filter(key => key === "KERNEL32.dll:Sleep").length, 1);
  assert.ok(keys.includes("KERNEL32.dll:??$square@H@demo@@YAHH@Z"));
  assert.ok(keys.includes("ucrtbase.dll:??$square@H@demo@@YAHH@Z"));
  assert.ok(keys.every(key => !key.includes("__cdecl")));
  for (const functions of [enriched.imports.entries[0]!.functions,
    enriched.delayImports!.entries[0]!.functions]) {
    assert.equal(getImportFunctionDisplayName(functions[250]!), "int __cdecl demo::square<int>(int)");
  }
  assert.match(renderImportFunctionTable([enriched.imports.entries[0]!.functions[0]!],
    "winapi", 0, new Map(), 4), /Win32Metadata - winapi/);
  assert.match(renderImportFunctionTable([enriched.delayImports!.entries[0]!.functions[0]!],
    "ucrt", 0, new Map(), 4), /UCRT - cdecl, variadic/);
});

for (const metadataField of ["apiMetadata", "winapiMetadata"] as const) {
  void test(`catalogue ${metadataField} takes precedence over a decoded C++ signature`, async () => {
    const parsed = await parsePe(new File([createPeImportNamesFile()], "imports.exe"));
    assert.ok(parsed && isPeWindowsParseResult(parsed));
    const fn = parsed.imports.entries[0]!.functions[250]!;
    fn[metadataField] = createEntry("eager.dll", fn.name!);

    const html = renderImportFunctionTable([fn], "catalogue", 0, new Map(), 4);

    assert.match(html, /Win32Metadata - winapi/);
    assert.match(html, /milliseconds/);
    assert.doesNotMatch(html, /int __cdecl demo::square/);
    assert.doesNotMatch(html, /<code class="dim">/);
    const model = createImportFunctionTableModel([fn], "catalogue", 0, new Map(), 4);
    assert.equal(model.sortValueAt!(0, 3), `Windows.Win32.System.Threading void ${fn.name}(u4 milliseconds)`);
  });
}

for (const [metadata, label] of [
  [createEntry("KERNEL32.dll", "Sleep"), "Win32Metadata"],
  [createUcrtEntry("ucrtbase.dll", "printf"), "UCRT"]
] as const) {
  void test(`${label} import API sorting retains the source label when no namespace is present`, () => {
    const fn = { name: metadata.entrypoint, apiMetadata: { ...metadata, namespace: null } };

    const model = createImportFunctionTableModel([fn], "metadata", 0, new Map(), 4);

    assert.equal(model.rowAt(0)?.cells[3]?.sortValue, `${label} ${metadata.signature}`);
    assert.equal(model.sortValueAt!(0, 3), `${label} ${metadata.signature}`);
  });
}
