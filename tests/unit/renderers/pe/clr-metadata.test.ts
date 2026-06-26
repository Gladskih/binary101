"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createClrMetadataTablesWithParameterNames } from "../../../fixtures/pe-clr-metadata-tables.js";
import { renderClrMetadataTables } from "../../../../renderers/pe/clr-metadata.js";

void test("renderClrMetadataTables renders CLR parameter names without shifting return parameters", () => {
  const out: string[] = [];
  renderClrMetadataTables(createClrMetadataTablesWithParameterNames(), out);
  const html = out.join("");
  assert.match(html, /Demo\.Buffer::Copy/);
  assert.match(html, /bool returnValue \(string source, i4 length\)/);
  assert.match(html, /\? \(\? value\)/);
  assert.match(html, /NoSignature<\/td><td>0x00001236<\/td><td>0x0006<\/td><td>-<\/td>/);
  assert.match(html, /Parameter rows/);
  assert.match(html, /<th>RID<\/th><th>Sequence<\/th><th>Name<\/th><th>Flags<\/th>/);
  assert.match(html, /<td>1<\/td><td>0<\/td><td>returnValue<\/td><td>0x0002<\/td>/);
  assert.match(html, /<td>2<\/td><td>1<\/td><td>source<\/td><td>0x0001<\/td>/);
  assert.match(html, /<td>3<\/td><td>2<\/td><td>length<\/td><td>0x0000<\/td>/);
  assert.doesNotMatch(html, /string returnValue, i4 source/);
});
