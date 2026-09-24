"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeWindowsParseResult } from "../../../../../analyzers/pe/core/parse-result.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { collectControlTransferInstructionRvas } from
  "../../../../../ui/pe-disassembly-control-transfer-hints.js";

void test("collectControlTransferInstructionRvas keeps mapped sites without duplicates", () => {
  const pe = ({
    opt: { SizeOfImage: 0x4000 },
    sections: [{ name: inlinePeSectionName(".text"), virtualAddress: 0x1000,
      virtualSize: 0x1000, sizeOfRawData: 0x1000, pointerToRawData: 0x200,
      characteristics: 0x20000000 }], // IMAGE_SCN_MEM_EXECUTE.
    rvaToOff: (rva: number) => rva - 0xe00,
    loadcfg: { dynamicRelocations: { entries: [{ symbol: 3n, controlTransfers: [
      { kind: "import", rva: 0x1010, indirectCall: true, iatIndex: 1 },
      { kind: "import", rva: 0x1010, indirectCall: true, iatIndex: 1 },
      { kind: "import", rva: 0x2010, indirectCall: true, iatIndex: 1 }
    ] }] } }
  }) as PeWindowsParseResult;

  assert.deepEqual(collectControlTransferInstructionRvas(pe, 0x2000), [0x1010]);
});

void test("collectControlTransferInstructionRvas handles missing DVRT payloads", () => {
  const withoutLoadConfig = ({ loadcfg: null }) as PeWindowsParseResult;
  const withoutDecodedRecords = ({ loadcfg: { dynamicRelocations: {
    entries: [{ kind: "v1", symbol: 9n, baseRelocSize: 0, availableBytes: 0 }]
  } } }) as PeWindowsParseResult;

  assert.deepEqual(collectControlTransferInstructionRvas(withoutLoadConfig, 0), []);
  assert.deepEqual(collectControlTransferInstructionRvas(withoutDecodedRecords, 0), []);
});
