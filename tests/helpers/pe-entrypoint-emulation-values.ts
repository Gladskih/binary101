"use strict";

import type { KnownValueBits } from "../../analyzers/pe/disassembly/entrypoint/emulation/state.js";
import type { FixtureMemorySize } from "./pe-entrypoint-emulation-fixture.js";

type FixtureCellSize = Extract<FixtureMemorySize, "UInt8" | "UInt16" | "UInt32" | "UInt64">;

type AddressPair = {
  source: bigint;
  destination: bigint;
};

// Intel SDM Vol. 2 MOVS defines byte/word/dword/qword element widths.
// These literals are test oracles, not aliases for production constants.
export const bitsOf = (size: FixtureCellSize): KnownValueBits => {
  if (size === "UInt8") return 8;
  if (size === "UInt16") return 16;
  if (size === "UInt32") return 32;
  return 64;
};

export const bytesOf = (size: FixtureCellSize): bigint => BigInt(bitsOf(size) / 8);

// Page-spaced addresses make incidental source/destination ranges easy to separate.
const fixturePageBytes = (): bigint => 0x1000n;

export const fixtureAddressPair = (slot = 0): AddressPair => {
  const source = fixturePageBytes() * BigInt(slot * 2 + 1);
  return { source, destination: source + fixturePageBytes() };
};

export const highFixtureAddressPair = (slot = 0): AddressPair => {
  const pair = fixtureAddressPair(slot);
  const firstAddressAboveUint32 = 1n << 32n;
  return {
    source: firstAddressAboveUint32 + pair.source,
    destination: firstAddressAboveUint32 + pair.destination
  };
};

// Above UINT16_MAX: a 16-bit SI/DI implementation cannot accidentally pass a
// test that is meant to prove 32-bit ESI/EDI addressing.
export const fixtureAddressPairRequiring32BitPointers = (slot = 0): AddressPair => {
  const pair = fixtureAddressPair(slot);
  const firstAddressAboveUint16 = 1n << 16n;
  return {
    source: firstAddressAboveUint16 + pair.source,
    destination: firstAddressAboveUint16 + pair.destination
  };
};

// Large enough that a dense per-element copy would dominate state.memory.size;
// sparse MOVS should instead scale with the few materialized cells in the test.
export const sparseElementCount = (): bigint => 1024n * 1024n;

// First repeat count that cannot be represented by ECX; x86-64 REP MOVS must
// read RCX here. Intel SDM Vol. 2 MOVS/REP.
export const repeatCountRequiringRcx = (): bigint => (1n << 32n) + 1n;

export const distantFixtureDestination = (): bigint => {
  const pair = fixtureAddressPair();
  return pair.source + sparseElementCount() * bytesOf("UInt32") + fixturePageBytes();
};

// The exact bit pattern is incidental; each slot produces a stable distinct
// value with data in both low and high halves so truncation tests are meaningful.
export const fixtureValue = (slot: number, bits: KnownValueBits): bigint => {
  const halfWidth = BigInt(bits / 2);
  const marker = BigInt(slot);
  return (marker << halfWidth) | marker;
};

export const lowBits = (value: bigint, bits: KnownValueBits): bigint =>
  value & ((1n << BigInt(bits)) - 1n);
