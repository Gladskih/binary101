"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderClr } from "../../renderers/pe/directories.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

void test("renderClr includes extended COR20 fields and native entrypoint interpretation", () => {
  const pe = {
    clr: {
      cb: 0x48,
      MajorRuntimeVersion: 4,
      MinorRuntimeVersion: 0,
      MetaDataRVA: 0x200,
      MetaDataSize: 0x80,
      Flags: 0x00000010,
      EntryPointToken: 0x1234,
      ResourcesRVA: 0x300,
      ResourcesSize: 0x40,
      StrongNameSignatureRVA: 0x340,
      StrongNameSignatureSize: 0x20,
      CodeManagerTableRVA: 0x360,
      CodeManagerTableSize: 0x10,
      VTableFixupsRVA: 0x380,
      VTableFixupsSize: 0x10,
      ExportAddressTableJumpsRVA: 0x3a0,
      ExportAddressTableJumpsSize: 0x08,
      ManagedNativeHeaderRVA: 0x3a8,
      ManagedNativeHeaderSize: 0x18
    }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderClr(pe, out);
  const html = out.join("");

  assert.ok(html.includes("CLR (.NET) header"));
  assert.ok(html.includes("EntryPointRVA"));
  assert.ok(html.includes("Resources"));
  assert.ok(html.includes("StrongNameSignature"));
  assert.ok(html.includes("CodeManagerTable"));
  assert.ok(html.includes("VTableFixups"));
  assert.ok(html.includes("ExportAddressTableJumps"));
  assert.ok(html.includes("ManagedNativeHeader"));
});

void test("renderClr decodes managed entrypoint tokens, metadata stream types, and vtable flags", () => {
  const pe = {
    clr: {
      cb: 0x48,
      MajorRuntimeVersion: 4,
      MinorRuntimeVersion: 0,
      MetaDataRVA: 0x200,
      MetaDataSize: 0x80,
      Flags: 0x00000001,
      EntryPointToken: 0x06000001,
      VTableFixupsRVA: 0x380,
      VTableFixupsSize: 0x08,
      vtableFixups: [
        {
          RVA: 0x380,
          Count: 2,
          Type: 0x0011
        }
      ],
      meta: {
        version: "v4.0.30319",
        verMajor: 1,
        verMinor: 1,
        signature: 0x424a5342,
        flags: 0,
        reserved: 0,
        streamCount: 2,
        streams: [
          { name: "#~", offset: 0x40, size: 0x80 },
          { name: "#Strings", offset: 0xc0, size: 0x50 }
        ]
      }
    }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderClr(pe, out);
  const html = out.join("");

  assert.ok(html.includes("EntryPointToken"));
  assert.ok(html.includes("MethodDef, RID 1"));
  assert.ok(html.includes("Metadata root"));
  assert.ok(html.includes("424a5342"));
  assert.ok(html.includes("Compressed metadata tables"));
  assert.ok(html.includes("String heap"));
  assert.ok(html.includes("32BIT | CALL_MOST_DERIVED"));
});
