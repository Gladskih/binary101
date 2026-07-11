"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  PeChpeArm64EcMetadata,
  PeLoadConfigReferences
} from "../../../../analyzers/pe/load-config/reference-types.js";
import { renderLoadConfigReferences } from "../../../../renderers/pe/load-config-references.js";

const createArm64EcMetadata = (): PeChpeArm64EcMetadata => ({
  kind: "arm64ec",
  rva: 0x3000,
  version: 2,
  codeMapRva: 0x3100,
  codeMapCount: 1,
  codeMap: [{ startRva: 0x4000, length: 0x20, kind: "ARM64EC" }],
  codeRangesToEntryPointsRva: 0x3200,
  redirectionMetadataRva: 0x3300,
  osArm64xDispatchCallNoRedirectRva: 0x7000,
  osArm64xDispatchRetRva: 0,
  osArm64xDispatchCallRva: 0,
  osArm64xDispatchIcallRva: 0,
  osArm64xDispatchIcallCfgRva: 0,
  alternateEntryPointRva: 0,
  auxiliaryIatRva: 0,
  codeRangesToEntryPointsCount: 1,
  redirectionMetadataCount: 1,
  getX64InformationFunctionPointerRva: 0,
  setX64InformationFunctionPointerRva: 0,
  extraRfeTableRva: 0,
  extraRfeTableSize: 0,
  osArm64xDispatchFptrRva: 0,
  auxiliaryIatCopyRva: 0,
  extraRfeEntries: [{
    beginRva: 0x1f00, unwindKind: "exception", exceptionInformationRva: 0x1f80
  }],
  auxiliaryDelayloadIatRva: 0,
  auxiliaryDelayloadIatCopyRva: 0,
  hybridImageInfoBitfield: 0,
  entryPointRanges: [{ startRva: 0x4000, endRva: 0x4020, entryPointRva: 0x4004 }],
  redirections: [{ sourceRva: 0x5000, destinationRva: 0x6000 }]
});

const createReferences = (): PeLoadConfigReferences => ({
    lockPrefixTable: { tableRva: 0x1000, values: [0x140002000n], terminated: true },
    securityCookie: { rva: 0x2000, value: 0x1234n },
    pointerSlots: { GuardCFCheckFunctionPointer: { rva: 0x2010, value: 0x140002100n } },
    chpeMetadata: createArm64EcMetadata(),
    enclaveConfiguration: {
      rva: 0x8000,
      size: 0x50,
      minimumRequiredConfigSize: 0x4c,
      policyFlags: 1,
      numberOfImports: 1,
      importListRva: 0x8100,
      importEntrySize: 0x50,
      familyId: Array.from({ length: 16 }, () => 1),
      imageId: Array.from({ length: 16 }, () => 2),
      imageVersion: 3,
      securityVersion: 4,
      enclaveSize: 0x200000n,
      numberOfThreads: 2,
      enclaveFlags: 1,
      imports: [{
        matchType: "AUTHOR_ID",
        minimumSecurityVersion: 5,
        uniqueOrAuthorId: Array.from({ length: 32 }, () => 3),
        familyId: Array.from({ length: 16 }, () => 4),
        imageId: Array.from({ length: 16 }, () => 5),
        nameRva: 0x8200,
        name: "enclave.dll",
        reserved: 0
      }]
    },
    hotPatch: {
      rva: 0x9000,
      version: 4,
      size: 0x24,
      sequenceNumber: 1,
      baseImageListOffset: 0x100,
      baseImageCount: 1,
      bufferOffset: 0,
      extraPatchSize: 0,
      minSequenceNumber: 0,
      flags: 2,
      baseImages: [{
        sequenceNumber: 1,
        flags: 0,
        originalTimeDateStamp: 0x12345678,
        originalCheckSum: 0x87654321,
        offset: 0x120,
        codeIntegrityInfoOffset: 0x200,
        codeIntegritySize: 0x20,
        patchTableOffset: 0x300,
        bufferOffset: 0
      }]
    },
    volatileMetadata: {
      rva: 0xa000,
      size: 24,
      minimumVersion: 1,
      maximumVersion: 2,
      accessTableRva: 0xa100,
      accessTableSize: 4,
      infoRangeTableRva: 0xa200,
      infoRangeTableSize: 8,
      accessRvas: [0xb000],
      infoRanges: [{ rva: 0xb000, size: 0x40 }]
    },
    opaque: [{
      name: "UmaFunctionPointers",
      pointerVa: 0x14000c000n,
      reason: "No public target layout."
    }]
});

void test("renderLoadConfigReferences renders decoded structures and labels opaque targets", () => {
  const html = renderLoadConfigReferences(createReferences(), 16);
  assert.ok(html.includes("Referenced Load Config data"));
  assert.ok(html.includes("LockPrefixTable"));
  assert.ok(html.includes("CHPE metadata"));
  assert.ok(html.includes("Extra ARM64 runtime functions"));
  assert.ok(html.includes("Enclave configuration"));
  assert.ok(html.includes("enclave.dll"));
  assert.ok(html.includes("Hot patch information"));
  assert.ok(html.includes("Volatile metadata"));
  assert.ok(html.includes("Volatile access RVAs"));
  assert.ok(html.includes("UmaFunctionPointers"));
});

void test("renderLoadConfigReferences renders x86 metadata and omits absent optional sections", () => {
  const html = renderLoadConfigReferences({
    chpeMetadata: {
      kind: "x86",
      rva: 0x100,
      version: 1,
      codeMapRva: 0,
      codeMapCount: 0,
      codeMap: [],
      wowA64ExceptionHandlerRva: 1,
      wowA64DispatchCallRva: 2,
      wowA64DispatchIndirectCallRva: 3,
      wowA64DispatchIndirectCallCfgRva: 4,
      wowA64DispatchRetRva: 5,
      wowA64DispatchRetLeafRva: 6,
      wowA64DispatchJumpRva: 7
    },
    enclaveConfiguration: {
      rva: 0x200,
      size: 76,
      minimumRequiredConfigSize: 76,
      policyFlags: 0,
      numberOfImports: 0,
      importListRva: 0,
      importEntrySize: 0,
      familyId: [],
      imageId: [],
      imageVersion: 0,
      securityVersion: 0,
      enclaveSize: 0n,
      numberOfThreads: 0,
      imports: []
    },
    hotPatch: {
      rva: 0x300,
      version: 1,
      size: 20,
      sequenceNumber: 0,
      baseImageListOffset: 0,
      baseImageCount: 0,
      baseImages: []
    }
  }, 16);

  assert.ok(html.includes("WowA64 exception handler RVA"));
  assert.ok(html.includes("Hot patch information"));
  assert.ok(!html.includes("Compiler IAT RVA"));
  assert.equal(renderLoadConfigReferences({}, 16), "");
});
