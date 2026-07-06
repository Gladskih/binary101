"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  collectDirectIatSlotRvas,
  createDirectIatReferenceCounter,
  getIatSlotRva
} from "../../../../../analyzers/pe/disassembly/import-references.js";
import type { PeDelayImportEntry } from "../../../../../analyzers/pe/imports/delay.js";
import type { PeImportParseResult } from "../../../../../analyzers/pe/imports/index.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../../../../../analyzers/pe/layout/rva-limits.js";
import {
  fixtureIced,
  instruction,
  mem,
  reg
} from "../../../../helpers/pe-entrypoint-emulation-fixture.js";

const IMAGE_BASE_AMD64 = 0x140000000n;
const IMAGE_BASE_I386 = 0x400000n;
const IAT_RVA = 0x2000;
const DELAY_IAT_RVA = 0x4000;
const IMPORT_LOOKUP_TABLE_RVA = 0x3000;
const DELAY_IMPORT_ATTRIBUTES_RVA_BASED = 1;
const INVALID_THUNK_ENTRY_SIZE = Uint16Array.BYTES_PER_ELEMENT;

const createImports = (firstThunkRva = IAT_RVA): PeImportParseResult => ({
  thunkEntrySize: BigUint64Array.BYTES_PER_ELEMENT,
  entries: [{
    dll: "KERNEL32.dll",
    originalFirstThunkRva: IMPORT_LOOKUP_TABLE_RVA,
    timeDateStamp: 0,
    forwarderChain: 0,
    firstThunkRva,
    lookupSource: "import-lookup-table",
    thunkTableTerminated: true,
    functions: [{ name: "Sleep" }, { name: "ExitProcess" }]
  }]
});

const createDelayImports = (): { entries: PeDelayImportEntry[] } => ({
  entries: [{
    Attributes: DELAY_IMPORT_ATTRIBUTES_RVA_BASED,
    ModuleHandleRVA: 0,
    ImportAddressTableRVA: DELAY_IAT_RVA,
    ImportNameTableRVA: 0,
    BoundImportAddressTableRVA: 0,
    UnloadInformationTableRVA: 0,
    TimeDateStamp: 0,
    name: "USER32.dll",
    functions: [{ name: "MessageBoxW" }]
  }]
});

const absoluteCall = (address: bigint) => instruction(
  "Call",
  [mem("UInt64", undefined, address)],
  { flowControl: "IndirectCall", indirectControlFlow: "near-call" }
);

const ipRelativeCall = (address: bigint) => instruction(
  "Call",
  [mem("UInt64", "RIP", address)],
  { flowControl: "IndirectCall", indirectControlFlow: "near-call" }
);

const ipRelativeJump = (address: bigint) => instruction(
  "Jmp",
  [mem("UInt64", "RIP", address)],
  { flowControl: "IndirectBranch", indirectControlFlow: "near-jump" }
);

void test("collectDirectIatSlotRvas indexes eager and delay IAT slots", () => {
  const issues: string[] = [];

  const slots = collectDirectIatSlotRvas(
    true,
    createImports(),
    createDelayImports(),
    issues
  );

  assert.deepEqual([...slots], [
    IAT_RVA,
    IAT_RVA + BigUint64Array.BYTES_PER_ELEMENT,
    DELAY_IAT_RVA
  ]);
  assert.deepEqual(issues, []);
});

void test("collectDirectIatSlotRvas skips overflowing malformed slot ranges", () => {
  const issues: string[] = [];
  const lastAlignedRva = PE_RVA_EXCLUSIVE_LIMIT - BigUint64Array.BYTES_PER_ELEMENT;

  const slots = collectDirectIatSlotRvas(true, createImports(lastAlignedRva), null, issues);

  assert.deepEqual([...slots], [lastAlignedRva]);
  assert.equal(issues.length, 1);
  assert.match(issues[0] ?? "", /32-bit RVA range/i);
});

void test("getIatSlotRva rejects malformed offsets, indexes, and thunk sizes", () => {
  assert.equal(getIatSlotRva(0, 0, Uint32Array.BYTES_PER_ELEMENT), null);
  assert.equal(getIatSlotRva(IAT_RVA, -1, Uint32Array.BYTES_PER_ELEMENT), null);
  assert.equal(getIatSlotRva(IAT_RVA, 0, INVALID_THUNK_ENTRY_SIZE), null);
  assert.equal(
    getIatSlotRva(PE_RVA_EXCLUSIVE_LIMIT - Uint32Array.BYTES_PER_ELEMENT, 1, Uint32Array.BYTES_PER_ELEMENT),
    null
  );
});

void test("collectDirectIatSlotRvas reports a mismatched eager thunk width", () => {
  const issues: string[] = [];
  const imports = { ...createImports(), thunkEntrySize: Uint32Array.BYTES_PER_ELEMENT };

  collectDirectIatSlotRvas(true, imports, null, issues);

  assert.match(issues[0] ?? "", /does not match 8-byte image pointers/i);
});

void test("direct IAT reference counter separates IP-relative calls and jumps", () => {
  const counter = createDirectIatReferenceCounter(
    fixtureIced,
    IMAGE_BASE_AMD64,
    new Set([IAT_RVA])
  );
  const targetVa = IMAGE_BASE_AMD64 + BigInt(IAT_RVA);

  counter.record(ipRelativeCall(targetVa));
  counter.record(ipRelativeJump(targetVa));

  assert.deepEqual(counter.references(), [{
    slotRva: IAT_RVA,
    callReferenceCount: 1,
    jumpReferenceCount: 1
  }]);
});

void test("direct IAT reference counter counts absolute memory calls", () => {
  const counter = createDirectIatReferenceCounter(
    fixtureIced,
    IMAGE_BASE_I386,
    new Set([IAT_RVA])
  );

  counter.record(absoluteCall(IMAGE_BASE_I386 + BigInt(IAT_RVA)));

  assert.deepEqual(counter.references(), [{
    slotRva: IAT_RVA,
    callReferenceCount: 1,
    jumpReferenceCount: 0
  }]);
});

void test("direct IAT reference counter sorts slots by RVA", () => {
  const higherSlotRva = IAT_RVA + BigUint64Array.BYTES_PER_ELEMENT;
  const counter = createDirectIatReferenceCounter(
    fixtureIced,
    IMAGE_BASE_AMD64,
    new Set([IAT_RVA, higherSlotRva])
  );

  counter.record(ipRelativeCall(IMAGE_BASE_AMD64 + BigInt(higherSlotRva)));
  counter.record(ipRelativeCall(IMAGE_BASE_AMD64 + BigInt(IAT_RVA)));

  assert.deepEqual(counter.references(), [
    { slotRva: IAT_RVA, callReferenceCount: 1, jumpReferenceCount: 0 },
    { slotRva: higherSlotRva, callReferenceCount: 1, jumpReferenceCount: 0 }
  ]);
});

void test("direct IAT reference counter rejects ambiguous or non-direct targets", () => {
  const counter = createDirectIatReferenceCounter(fixtureIced, 0n, new Set([IAT_RVA]));
  const rejected = [
    instruction("Call", [reg("RAX")], {
      flowControl: "IndirectCall"
    }),
    instruction("Call", [mem("UInt64", "RAX", BigInt(IAT_RVA))], {
      flowControl: "IndirectCall",
      indirectControlFlow: "near-call"
    }),
    Object.assign(absoluteCall(BigInt(IAT_RVA)), {
      isIpRelMemoryOperand: true,
      memoryBase: fixtureIced.Register?.["RAX"] ?? 0
    }),
    instruction("Call", [mem("UInt64", undefined, BigInt(IAT_RVA))], {
      flowControl: "IndirectCall",
      indirectControlFlow: "far-call"
    }),
    absoluteCall(BigInt(IMPORT_LOOKUP_TABLE_RVA)),
    Object.assign(absoluteCall(BigInt(IAT_RVA)), { isJmpNearIndirect: true })
  ];

  rejected.forEach(decoded => counter.record(decoded));

  assert.deepEqual(counter.references(), []);
});

void test("direct IAT reference counter rejects inconsistent instruction metadata", () => {
  const counter = createDirectIatReferenceCounter(
    fixtureIced,
    IMAGE_BASE_AMD64,
    new Set([IAT_RVA])
  );
  const targetVa = IMAGE_BASE_AMD64 + BigInt(IAT_RVA);
  const rejectedCall = Object.assign(ipRelativeCall(targetVa), {
    isIpRelMemoryOperand: false
  });
  const rejectedJump = Object.assign(ipRelativeJump(targetVa), {
    flowControl: fixtureIced.FlowControl["IndirectCall"]
  });

  counter.record(rejectedCall);
  counter.record(rejectedJump);

  assert.deepEqual(counter.references(), []);
});
