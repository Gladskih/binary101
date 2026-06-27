"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeClrCustomAttributeInfo } from "../../../../analyzers/pe/clr/types.js";
import { hasDoesNotReturnAttribute } from "../../../../scripts/winapi-metadata/winmd-assets.js";

const customAttribute = (attributeType: string | null): PeClrCustomAttributeInfo => ({
  row: 1,
  parent: { table: "MethodDef", tableId: 0x06, row: 1, raw: 1, valid: true },
  parentName: "Windows.Win32.System.Threading.Apis.ExitProcess",
  constructor: null,
  constructorName: ".ctor",
  attributeType,
  valueBlobIndex: 1,
  fixedArguments: [],
  namedArguments: []
});

void test("hasDoesNotReturnAttribute reads WinMD no-return metadata", () => {
  assert.equal(hasDoesNotReturnAttribute([
    customAttribute("Windows.Win32.Foundation.Metadata.DocumentationAttribute"),
    customAttribute("System.Diagnostics.CodeAnalysis.DoesNotReturnAttribute")
  ]), true);
  assert.equal(hasDoesNotReturnAttribute([
    customAttribute("Windows.Win32.Foundation.Metadata.DocumentationAttribute")
  ]), false);
});
