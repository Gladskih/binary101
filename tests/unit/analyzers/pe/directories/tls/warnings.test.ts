"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseTlsDirectory32 } from "../../../../../../analyzers/pe/directories/tls.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import { expectDefined } from "../../../../../helpers/expect-defined.js";
import type { PeSection } from "../../../../../../analyzers/pe/types.js";

const IMAGE_TLS_DIRECTORY32_SIZE = 0x18; // IMAGE_TLS_DIRECTORY32

const createTlsSubject = (): { bytes: Uint8Array; view: DataView; tlsRva: number } => {
  const tlsRva = 0x20;
  const bytes = new Uint8Array(0x100).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(tlsRva + 8, 0x80, true);
  return { bytes, view, tlsRva };
};

const createSection = (virtualSize: number, sizeOfRawData: number): PeSection => ({
  name: { kind: "inline", value: ".data" },
  virtualSize,
  virtualAddress: 0x80,
  sizeOfRawData,
  pointerToRawData: 0x80,
  characteristics: 0
});

void test("parseTlsDirectory warns when TLS Characteristics sets reserved bits", async () => {
  const { bytes, view, tlsRva } = createTlsSubject();
  view.setUint32(tlsRva + 20, 1, true);

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    value => value,
    0n
  ));

  assert.ok(tls.warnings?.some(warning => /Characteristics|reserved/i.test(warning)));
});

void test("parseTlsDirectory warns when the TLS raw-data VA range is invalid", async () => {
  const { bytes, view, tlsRva } = createTlsSubject();
  view.setUint32(tlsRva + 0, 0x90, true);
  view.setUint32(tlsRva + 4, 0x80, true);

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    value => value,
    0n
  ));

  assert.ok(tls.warnings?.some(warning => /raw data VA range is invalid/i.test(warning)));
});

void test("parseTlsDirectory warns when AddressOfIndex is not a valid image VA", async () => {
  const { bytes, view, tlsRva } = createTlsSubject();
  view.setUint32(tlsRva + 8, 0x200, true);

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    value => value,
    0n
  ));

  assert.ok(tls.warnings?.some(warning => /AddressOfIndex|valid image VA/i.test(warning)));
});

void test("parseTlsDirectory accepts AddressOfIndex in a virtual data tail", async () => {
  const { bytes, view, tlsRva } = createTlsSubject();
  view.setUint32(tlsRva + 8, 0xb0, true);

  const tls = expectDefined(await parseTlsDirectory32(
    new MockFile(bytes),
    [{ name: "TLS", rva: tlsRva, size: IMAGE_TLS_DIRECTORY32_SIZE }],
    value => value < 0xa0 ? value : null,
    0n,
    [createSection(0x40, 0x20)]
  ));

  assert.equal(tls.warnings?.some(warning => /AddressOfIndex/i.test(warning)), undefined);
});
