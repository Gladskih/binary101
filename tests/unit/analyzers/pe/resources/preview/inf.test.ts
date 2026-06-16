"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { addRegInstPreview } from "../../../../../../analyzers/pe/resources/preview/inf.js";

const encoder = new TextEncoder();
// Windows code page identifier for UTF-8. Source:
// https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
const WINDOWS_UTF8_CODE_PAGE = 65001;

void test("addRegInstPreview parses INF-style sections, directives, and AddReg entries", () => {
  const addRegText = "AddReg=RegAll";
  const registryText = "HKLM,Software\\Binary101,Enabled,,1";
  const lines = [
    "; registration resource",
    "[Version]",
    "Signature=\"$CHICAGO$\"",
    "[RegDll]",
    addRegText,
    "[RegAll]",
    registryText
  ];
  const result = addRegInstPreview(
    encoder.encode(lines.join("\r\n")),
    "REGINST",
    WINDOWS_UTF8_CODE_PAGE
  );

  assert.equal(result?.preview?.previewKind, "inf");
  const sections = result?.preview?.infPreview?.sections;
  const comments = lines.filter(line => line.startsWith(";"));
  const entries = lines.filter(line =>
    line && !line.startsWith(";") && !line.startsWith("[")
  );
  assert.equal(sections?.length, ["Version", "RegDll", "RegAll"].length);
  assert.equal(result?.preview?.infPreview?.commentCount, comments.length);
  assert.equal(result?.preview?.infPreview?.entryCount, entries.length);
  const addRegEntry = sections
    ?.find(section => section.name === "RegDll")
    ?.entries.find(entry => entry.key === "AddReg");
  assert.deepEqual(addRegEntry, {
    line: lines.indexOf(addRegText) + 1,
    kind: "directive",
    key: "AddReg",
    value: "RegAll"
  });
  const registryEntry = sections
    ?.find(section => section.name === "RegAll")
    ?.entries.find(entry => entry.value === registryText);
  assert.deepEqual(registryEntry, {
    line: lines.indexOf(registryText) + 1,
    kind: "entry",
    key: null,
    value: registryText
  });
  assert.equal(result?.issues, undefined);
});

void test("addRegInstPreview reports malformed INF structure without throwing", () => {
  const result = addRegInstPreview(
    encoder.encode(["LooseDirective=Value", "[Broken", "[Good]", "Name=Value"].join("\n")),
    "REGINST",
    WINDOWS_UTF8_CODE_PAGE
  );

  assert.equal(result?.preview?.previewKind, "inf");
  assert.equal(result?.preview?.infPreview?.sections.length, 1);
  assert.ok(result?.issues?.some(issue => /before any section/i.test(issue)));
  assert.ok(result?.issues?.some(issue => /malformed section header/i.test(issue)));
});

void test("addRegInstPreview ignores unrelated resource types", () => {
  assert.equal(
    addRegInstPreview(encoder.encode("[Version]\n"), "RCDATA", WINDOWS_UTF8_CODE_PAGE),
    null
  );
});
