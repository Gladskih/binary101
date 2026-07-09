"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectVirtualHardDisk, detectVirtualHardDiskHeader } from "../../../../analyzers/vhd/probe.js";
import { MockFile } from "../../../helpers/mock-file.js";

const fromAscii = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "ascii"));
const viewOf = (bytes: Uint8Array): DataView =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
// MS-VHDX 2.1: file identifier signature is ASCII "vhdxfile".
const VHDX_FILE_IDENTIFIER_SIGNATURE = "vhdxfile";
// Microsoft VHD Image Format Specification: the footer cookie is ASCII "conectix".
const VHD_FOOTER_COOKIE = "conectix";
// Microsoft VHD Image Format Specification: VHD footers are 512 bytes; older
// images may use a 511-byte footer.
const CURRENT_VHD_FOOTER_BYTE_LENGTH = 512;
const LEGACY_VHD_FOOTER_BYTE_LENGTH = 511;
const VHD_FIXTURE_PAYLOAD_BYTE_LENGTH = 1024;

void test("detectVirtualHardDiskHeader recognizes VHDX file identifiers", () => {
  assert.equal(
    detectVirtualHardDiskHeader(viewOf(fromAscii(VHDX_FILE_IDENTIFIER_SIGNATURE))),
    "Virtual Hard Disk v2 image (VHDX)"
  );
});

void test("detectVirtualHardDiskHeader recognizes VHD footer copies at the start", () => {
  const bytes = new Uint8Array(CURRENT_VHD_FOOTER_BYTE_LENGTH).fill(0);
  bytes.set(fromAscii(VHD_FOOTER_COOKIE));
  assert.equal(
    detectVirtualHardDiskHeader(viewOf(bytes)),
    "Virtual Hard Disk image (VHD)"
  );
});

void test("detectVirtualHardDisk reads footer-only VHD images", async () => {
  const bytes = new Uint8Array(
    VHD_FIXTURE_PAYLOAD_BYTE_LENGTH + CURRENT_VHD_FOOTER_BYTE_LENGTH
  ).fill(0);
  bytes.set(fromAscii(VHD_FOOTER_COOKIE), VHD_FIXTURE_PAYLOAD_BYTE_LENGTH);
  assert.equal(
    await detectVirtualHardDisk(
      new MockFile(bytes, "fixed.vhd"),
      viewOf(bytes.subarray(0, CURRENT_VHD_FOOTER_BYTE_LENGTH))
    ),
    "Virtual Hard Disk image (VHD)"
  );
});

void test("detectVirtualHardDisk accepts legacy 511-byte VHD footers", async () => {
  const bytes = new Uint8Array(
    VHD_FIXTURE_PAYLOAD_BYTE_LENGTH + LEGACY_VHD_FOOTER_BYTE_LENGTH
  ).fill(0);
  bytes.set(fromAscii(VHD_FOOTER_COOKIE), VHD_FIXTURE_PAYLOAD_BYTE_LENGTH);
  assert.equal(
    await detectVirtualHardDisk(
      new MockFile(bytes, "legacy.vhd"),
      viewOf(bytes.subarray(0, CURRENT_VHD_FOOTER_BYTE_LENGTH))
    ),
    "Virtual Hard Disk image (VHD)"
  );
});

void test("detectVirtualHardDisk rejects truncated and unrelated data", async () => {
  const unrelated = new MockFile(fromAscii("not a virtual hard disk"), "data.bin");
  assert.equal(detectVirtualHardDiskHeader(viewOf(fromAscii("vhdx"))), null);
  assert.equal(detectVirtualHardDiskHeader(viewOf(fromAscii(VHD_FOOTER_COOKIE))), null);
  assert.equal(await detectVirtualHardDisk(unrelated, viewOf(fromAscii("not a virtual hard disk"))), null);
});
