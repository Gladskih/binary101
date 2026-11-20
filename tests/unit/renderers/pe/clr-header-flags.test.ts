import assert from "node:assert/strict";
import { test } from "node:test";
import { renderClr } from "../../../../renderers/pe/clr.js";

void test("renderClr interprets the architecture bits together and explains a nil token", () => {
  // CoreCLR corhdr.h defines 32BITREQUIRED | 32BITPREFERRED as preference.
  const clr = {
    cb: 72, MajorRuntimeVersion: 2, MinorRuntimeVersion: 5, MetaDataRVA: 0, MetaDataSize: 0,
    Flags: 0x00020002, EntryPointToken: 0, ResourcesRVA: 0, ResourcesSize: 0,
    StrongNameSignatureRVA: 0, StrongNameSignatureSize: 0, CodeManagerTableRVA: 0,
    CodeManagerTableSize: 0, VTableFixupsRVA: 0, VTableFixupsSize: 0, ExportAddressTableJumpsRVA: 0,
    ExportAddressTableJumpsSize: 0, ManagedNativeHeaderRVA: 0, ManagedNativeHeaderSize: 0
  };
  const out: string[] = [];

  renderClr(clr, out);
  const html = out.join("");

  assert.match(html, /Prefers a 32-bit process when possible/);
  assert.doesNotMatch(html, /Requires a 32-bit process/);
  assert.match(html, /0x00000000 \(no managed entry point\)/);
});
