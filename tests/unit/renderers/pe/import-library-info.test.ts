"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  getImportLibraryInfo,
  renderImportLibraryInfoNote,
  renderImportLibraryNameWithInfo
} from "../../../../renderers/pe/import-library-info.js";

void test("getImportLibraryInfo describes sourced common Windows DLL names", () => {
  assert.deepEqual(getImportLibraryInfo("C:\\Windows\\System32\\KERNEL32.dll"), {
    summary: "Core Win32 file, process, thread, memory, synchronization, and loader APIs."
  });
  assert.deepEqual(getImportLibraryInfo("USER32.dll"), {
    summary: "Window manager, message, input, menu, dialog, and user-interface APIs."
  });
  assert.deepEqual(getImportLibraryInfo("ntdll.dll"), {
    summary: "Native NT and RTL runtime APIs, including internal OS interfaces and status helpers."
  });
  assert.deepEqual(getImportLibraryInfo("VCRUNTIME140.dll"), {
    summary: "Microsoft Visual C++ runtime support library."
  });
});

void test("getImportLibraryInfo recognizes Windows API set contract names", () => {
  assert.deepEqual(getImportLibraryInfo("api-ms-win-core-synch-l1-2-0.dll"), {
    summary:
      "Windows API set contract: a loader-level virtual DLL name mapped to an implementation."
  });
});

void test("getImportLibraryInfo returns null for unknown DLL names", () => {
  assert.equal(getImportLibraryInfo("plugin.dll"), null);
  assert.equal(getImportLibraryInfo("   "), null);
});

void test("renderImportLibraryNameWithInfo appends notes only for sourced patterns", () => {
  const html = renderImportLibraryNameWithInfo("api-ms-win-core-synch-l1-2-0.dll");
  assert.ok(html.startsWith("api-ms-win-core-synch-l1-2-0.dll"));
  assert.ok(html.includes("Name-based DLL note"));
  assert.ok(html.includes("Windows API set contract"));
  assert.ok(!html.includes("<a "));
});

void test("renderImportLibraryInfoNote marks sourced descriptions as name-based", () => {
  assert.equal(
    renderImportLibraryInfoNote("ntdll.dll"),
    "Name-based DLL note: Native NT and RTL runtime APIs, including internal OS interfaces and status helpers."
  );
});

void test("renderImportLibraryInfoNote returns an empty string for unknown module names", () => {
  assert.equal(renderImportLibraryInfoNote("plugin.dll"), "");
});
