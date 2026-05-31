"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDecodedEntryDetails } from "../../renderers/pe/debug-payload-details.js";
import {
  createDebugViewEntry,
  createDebugViewSection
} from "../fixtures/pe-debug-view-subject.js";
import { createBasePe } from "../fixtures/pe-renderer-headers-fixture.js";

const renderDetails = (entries: ReturnType<typeof createDebugViewEntry>[]): string => {
  const pe = createBasePe();
  const out: string[] = [];
  const debug = createDebugViewSection(entries);
  renderDecodedEntryDetails(pe, debug, out);
  return out.join("");
};

void test("renderDecodedEntryDetails renders nothing when no payload was decoded", () => {
  const html = renderDetails([createDebugViewEntry(0xff, 0, 0, 0)]);

  assert.equal(html, "");
});

void test("renderDecodedEntryDetails renders CodeView NB10 fields", () => {
  const html = renderDetails([{
    ...createDebugViewEntry(2, 0, 0x80, 26),
    codeView: { signature: "NB10", offset: 0, timestamp: 0x3aef6cec, age: 1, path: "crtdll.pdb" }
  }]);

  assert.match(html, /Entry #1: CODEVIEW/);
  assert.match(html, /NB10/);
  assert.match(html, /0x3aef6cec/);
  assert.match(html, /crtdll\.pdb/);
});

void test("renderDecodedEntryDetails renders tabular FPO and POGO payloads", () => {
  const html = renderDetails([
    {
      ...createDebugViewEntry(3, 0, 0x90, 16),
      fpo: { records: [{
        startOffset: 0x1000,
        procedureSize: 0x20,
        localDwordCount: 2,
        parameterDwordCount: 3,
        prologByteCount: 0x12,
        savedRegisterCount: 5,
        hasStructuredExceptionHandling: true,
        usesBasePointer: true,
        frameType: 2
      }] }
    },
    {
      ...createDebugViewEntry(13, 0, 0xa0, 16),
      pogo: { signature: 0x4c544347, signatureName: "LTCG", entries: [{
        startRva: 0x2000,
        size: 0x40,
        name: ".text$mn"
      }] }
    }
  ]);

  assert.match(html, /FPO/);
  assert.match(html, /0x00001000/);
  assert.match(html, /POGO records describe linker chunks/);
  assert.match(html, /\.text\$mn/);
});

void test("renderDecodedEntryDetails renders small decoded payload fields", () => {
  const html = renderDetails([
    { ...createDebugViewEntry(16, 0, 0xb0, 0), repro: { hashLength: null, hashBytes: [] } },
    {
      ...createDebugViewEntry(17, 0, 0xc0, 9),
      embeddedPortablePdb: { signature: "MPDB", uncompressedSize: 115724, compressedSize: 91953 }
    },
    {
      ...createDebugViewEntry(19, 0, 0xd0, 9),
      pdbChecksum: { algorithmName: "SHA256", checksumBytes: [0xaa, 0xbb] }
    },
    { ...createDebugViewEntry(20, 0, 0xe0, 4), exDllCharacteristics: { value: 0x41 } },
    { ...createDebugViewEntry(10, 0, 0xf0, 4), rawPayload: { previewBytes: [0xb4, 0x9c] } }
  ]);

  assert.match(html, /Hash length/);
  assert.match(html, /MPDB/);
  assert.match(html, /SHA256/);
  assert.match(html, /0x00000041/);
  assert.match(html, /CET_COMPAT/);
  assert.match(html, /FORWARD_CFI_COMPAT/);
  assert.match(html, /HOTPATCH_COMPATIBLE/);
  assert.match(html, /b4 9c/);
});

void test("renderDecodedEntryDetails renders EXCEPTION pdata analysis", () => {
  const html = renderDetails([{
    ...createDebugViewEntry(5, 0x2000, 0x90, 12),
    exception: {
      functionCount: 1,
      beginRvas: [0x1000],
      handlerRvas: [],
      uniqueUnwindInfoCount: 0,
      handlerUnwindInfoCount: 0,
      chainedUnwindInfoCount: 0,
      invalidEntryCount: 0,
      issues: [],
      format: "amd64"
    }
  }]);

  assert.match(html, /Entry #1: EXCEPTION/);
  assert.match(html, /Exception directory \(\.pdata\)/);
  assert.match(html, /x64 \.pdata maps code ranges/);
});
