"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectCpioHeader } from "../../../../analyzers/cpio/probe.js";

const viewOf = (bytes: Uint8Array): DataView =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
// Linux initramfs buffer format: newc/crc CPIO magic strings.
const CPIO_NEWC_MAGIC = "070701";
const CPIO_CRC_MAGIC = "070702";
const UNKNOWN_CPIO_MAGIC = "070703";
// Linux initramfs buffer format: after magic, newc/crc headers contain thirteen
// 8-hex-digit fields.
const CPIO_HEADER_FIELD_COUNT = 13;
const CPIO_HEADER_FIELD_HEX_DIGITS = 8;

const cpioFixedHeader = (magic: string, fieldCharacter = "0"): DataView =>
  viewOf(
    new TextEncoder().encode(
      magic + fieldCharacter.repeat(CPIO_HEADER_FIELD_COUNT * CPIO_HEADER_FIELD_HEX_DIGITS)
    )
  );

void test("detectCpioHeader recognizes newc and crc initramfs CPIO headers", () => {
  assert.equal(detectCpioHeader(cpioFixedHeader(CPIO_NEWC_MAGIC)), "Linux initramfs (CPIO newc archive)");
  assert.equal(detectCpioHeader(cpioFixedHeader(CPIO_CRC_MAGIC)), "Linux initramfs (CPIO crc archive)");
});

void test("detectCpioHeader rejects truncated and malformed CPIO headers", () => {
  assert.equal(detectCpioHeader(viewOf(new TextEncoder().encode(CPIO_NEWC_MAGIC))), null);
  assert.equal(detectCpioHeader(cpioFixedHeader(CPIO_NEWC_MAGIC, "G")), null);
  assert.equal(detectCpioHeader(cpioFixedHeader(UNKNOWN_CPIO_MAGIC)), null);
});
