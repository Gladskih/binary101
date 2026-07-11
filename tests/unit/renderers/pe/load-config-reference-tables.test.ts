"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeLoadConfigReferences } from "../../../../analyzers/pe/load-config/reference-types.js";
import {
  getLoadConfigReferenceTableModel,
  LOAD_CONFIG_REFERENCE_TABLE_IDS
} from "../../../../renderers/pe/load-config-reference-tables.js";

const createTableReferences = (): PeLoadConfigReferences => ({
  lockPrefixTable: { tableRva: 0x100, values: [0x140000100n], terminated: true },
  chpeMetadata: {
    kind: "arm64ec",
    rva: 0x200,
    version: 1,
    codeMapRva: 0x300,
    codeMapCount: 1,
    codeMap: [{ startRva: 0x400, length: 0x20, kind: "ARM64EC" }],
    codeRangesToEntryPointsRva: 0x500,
    redirectionMetadataRva: 0x600,
    osArm64xDispatchCallNoRedirectRva: 0,
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
    extraRfeEntries: [
      { beginRva: 0x910, unwindKind: "exception", exceptionInformationRva: 0xa00 },
      {
        beginRva: 0x920,
        unwindKind: "packed",
        functionLengthBytes: 16,
        savedFpRegisterField: 0,
        savedIntegerRegisterCount: 0,
        homesIntegerParameters: false,
        chainReturn: "chained",
        frameSizeBytes: 16
      },
      { beginRva: 0x930, unwindKind: "chained", targetPdataRva: 0x940 }
    ],
    entryPointRanges: [{ startRva: 0x700, endRva: 0x720, entryPointRva: 0x704 }],
    redirections: [{ sourceRva: 0x800, destinationRva: 0x900 }]
  },
  enclaveConfiguration: {
    rva: 0xa00,
    size: 80,
    minimumRequiredConfigSize: 80,
    policyFlags: 0,
    numberOfImports: 1,
    importListRva: 0xb00,
    importEntrySize: 80,
    familyId: [],
    imageId: [],
    imageVersion: 0,
    securityVersion: 0,
    enclaveSize: 0n,
    numberOfThreads: 0,
    imports: [{
      matchType: "NONE",
      minimumSecurityVersion: 0,
      uniqueOrAuthorId: [],
      familyId: [],
      imageId: [],
      nameRva: 0,
      reserved: 0
    }]
  },
  volatileMetadata: {
    rva: 0xc00,
    size: 24,
    minimumVersion: 1,
    maximumVersion: 1,
    accessTableRva: 0,
    accessTableSize: 0,
    infoRangeTableRva: 0xd00,
    infoRangeTableSize: 8,
    accessRvas: [],
    infoRanges: [{ rva: 0xe00, size: 0x40 }]
  }
});

void test("getLoadConfigReferenceTableModel exposes every parsed row through pagination", () => {
  const accessRvas = Array.from({ length: 251 }, (_, index) => 0x1000 + index * 4);
  const model = getLoadConfigReferenceTableModel({
    volatileMetadata: {
      rva: 0x800,
      size: 24,
      minimumVersion: 1,
      maximumVersion: 1,
      accessTableRva: 0x1000,
      accessTableSize: accessRvas.length * 4,
      infoRangeTableRva: 0,
      infoRangeTableSize: 0,
      accessRvas,
      infoRanges: []
    }
  }, LOAD_CONFIG_REFERENCE_TABLE_IDS.volatileAccesses);

  assert.equal(model?.rowCount, 251);
  assert.equal(model?.pageSize, 250);
  assert.ok(model?.rowAt(250)?.cells[1]?.html.includes("000013e8"));
  assert.equal(model?.rowAt(251), null);
  assert.equal(model?.sortValueAt(251, 0), "");
});

void test("getLoadConfigReferenceTableModel renders HotPatch hashes and rejects unknown IDs", () => {
  const references: PeLoadConfigReferences = {
    hotPatch: {
      rva: 0x100,
      version: 4,
      size: 36,
      sequenceNumber: 1,
      baseImageListOffset: 0x200,
      baseImageCount: 1,
      baseImages: [{
        sequenceNumber: 2,
        flags: 0,
        originalTimeDateStamp: 3,
        originalCheckSum: 4,
        offset: 0x220,
        codeIntegrityInfoOffset: 0x300,
        codeIntegritySize: 52,
        patchTableOffset: 0,
        codeIntegrityHashes: {
          sha256: Array.from({ length: 32 }, () => 0xaa),
          sha1: Array.from({ length: 20 }, () => 0xbb)
        }
      }, {
        sequenceNumber: 3,
        flags: 0,
        originalTimeDateStamp: 0,
        originalCheckSum: 0,
        offset: 0x240,
        codeIntegrityInfoOffset: 0,
        codeIntegritySize: 0,
        patchTableOffset: 0,
        bufferOffset: 5
      }]
    }
  };

  const model = getLoadConfigReferenceTableModel(
    references,
    LOAD_CONFIG_REFERENCE_TABLE_IDS.hotPatchBases
  );

  assert.ok(model?.rowAt(0)?.cells.some(cell => cell.html.includes("0xaa 0xaa")));
  assert.equal(getLoadConfigReferenceTableModel(references, "unknown"), null);
});

void test("getLoadConfigReferenceTableModel covers every Load Config reference table", () => {
  const references = createTableReferences();
  const lockPrefixes = getLoadConfigReferenceTableModel(
    references, LOAD_CONFIG_REFERENCE_TABLE_IDS.lockPrefixes
  );
  const codeMap = getLoadConfigReferenceTableModel(
    references, LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeCodeMap
  );
  const entryPoints = getLoadConfigReferenceTableModel(
    references, LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeEntryPoints
  );
  const redirections = getLoadConfigReferenceTableModel(
    references, LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeRedirections
  );
  const runtimeFunctions = getLoadConfigReferenceTableModel(
    references, LOAD_CONFIG_REFERENCE_TABLE_IDS.chpeRuntimeFunctions
  );
  const imports = getLoadConfigReferenceTableModel(
    references, LOAD_CONFIG_REFERENCE_TABLE_IDS.enclaveImports
  );
  const ranges = getLoadConfigReferenceTableModel(
    references, LOAD_CONFIG_REFERENCE_TABLE_IDS.volatileRanges
  );

  assert.equal(lockPrefixes?.rowCount, 1);
  assert.equal(codeMap?.sortValueAt(0, 3), "ARM64EC");
  assert.ok(entryPoints?.rowAt(0));
  assert.ok(redirections?.rowAt(0));
  assert.equal(runtimeFunctions?.rowCount, 3);
  assert.ok(runtimeFunctions?.rowAt(0)?.cells[3]?.html.includes("00000a00"));
  assert.equal(runtimeFunctions?.rowAt(1)?.cells[7]?.html, "no");
  assert.ok(runtimeFunctions?.rowAt(2)?.cells[3]?.html.includes("00000940"));
  assert.ok(imports?.rowAt(0));
  assert.ok(ranges?.rowAt(0));
  assert.equal(lockPrefixes?.rowAt(1), null);
  assert.equal(codeMap?.rowAt(1), null);
  assert.equal(entryPoints?.sortValueAt(1, 0), "");
  assert.equal(redirections?.sortValueAt(1, 0), "");
  assert.equal(imports?.sortValueAt(1, 0), "");
  assert.equal(ranges?.sortValueAt(1, 0), "");
  assert.equal(runtimeFunctions?.sortValueAt(3, 0), "");
});
