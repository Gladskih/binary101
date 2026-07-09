"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { parseLinuxBootProtocol } from "../../../../analyzers/pe/linux-boot.js";
import { MockFile } from "../../../helpers/mock-file.js";

// RFC 1952, section 2.3.1: gzip ID1=0x1f, ID2=0x8b, CM=8 means "deflate".
// https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1
const RFC1952_GZIP_ID1 = 0x1f;
const RFC1952_GZIP_ID2 = 0x8b;
const RFC1952_DEFLATE_COMPRESSION_METHOD = 8;
const SETUP_SECTS_OFFSET = 0x1f1;
const BOOT_FLAG_OFFSET = 0x1fe;
const LINUX_MAGIC_OFFSET = 0x202;
const VERSION_OFFSET = 0x206;
const KERNEL_VERSION_OFFSET = 0x20e;
const LOAD_FLAGS_OFFSET = 0x211;
const KERNEL_ALIGNMENT_OFFSET = 0x230;
const RELOCATABLE_KERNEL_OFFSET = 0x234;
const XLOADFLAGS_OFFSET = 0x236;
const CMDLINE_SIZE_OFFSET = 0x238;
const PAYLOAD_OFFSET = 0x248;
const PAYLOAD_LENGTH_OFFSET = 0x24c;
const PREFERRED_ADDRESS_OFFSET = 0x258;
const INIT_SIZE_OFFSET = 0x260;
const HANDOVER_OFFSET = 0x264;
const KERNEL_INFO_OFFSET = 0x268;
// Linux/x86 Boot Protocol 2.15 introduced kernel_info.
const LINUX_BOOT_PROTOCOL_2_15 = 0x020f;
// Protocol 2.04 predates the modern fields gated in this test.
const LINUX_BOOT_PROTOCOL_2_04 = 0x0204;

const createFile = (bytes: Uint8Array): MockFile =>
  new MockFile(bytes, "linux-bzimage-pe.exe");

const parseBytes = (bytes: Uint8Array) => {
  const file = createFile(bytes);
  return parseLinuxBootProtocol(createFileRangeReader(file, 0, file.size), file);
};

const writeAscii = (bytes: Uint8Array, offset: number, text: string): void => {
  for (let index = 0; index < text.length; index += 1) bytes[offset + index] = text.charCodeAt(index);
};

const createLinuxBootBytes = (): Uint8Array => {
  const bytes = new Uint8Array(0x600).fill(0);
  const view = new DataView(bytes.buffer);
  bytes[SETUP_SECTS_OFFSET] = 1;
  view.setUint16(BOOT_FLAG_OFFSET, 0xaa55, true);
  writeAscii(bytes, LINUX_MAGIC_OFFSET, "HdrS");
  view.setUint16(VERSION_OFFSET, LINUX_BOOT_PROTOCOL_2_15, true);
  view.setUint16(KERNEL_VERSION_OFFSET, 0x180, true);
  writeAscii(bytes, 0x380, "6.18.33-test");
  bytes[LOAD_FLAGS_OFFSET] = 0x81;
  view.setUint32(KERNEL_ALIGNMENT_OFFSET, 0x01000000, true);
  bytes[RELOCATABLE_KERNEL_OFFSET] = 1;
  view.setUint16(XLOADFLAGS_OFFSET, 0x000b, true);
  view.setUint32(CMDLINE_SIZE_OFFSET, 2047, true);
  view.setUint32(PAYLOAD_OFFSET, 0x20, true);
  view.setUint32(PAYLOAD_LENGTH_OFFSET, 6, true);
  view.setBigUint64(PREFERRED_ADDRESS_OFFSET, 0x1000000n, true);
  view.setUint32(INIT_SIZE_OFFSET, 0x03be0000, true);
  view.setUint32(HANDOVER_OFFSET, 0x1074102, true);
  view.setUint32(KERNEL_INFO_OFFSET, 0x80, true);
  bytes.set([RFC1952_GZIP_ID1, RFC1952_GZIP_ID2, RFC1952_DEFLATE_COMPRESSION_METHOD, 0, 1, 2], 0x420);
  writeAscii(bytes, 0x480, "LToP");
  view.setUint32(0x484, 16, true);
  view.setUint32(0x488, 16, true);
  view.setUint32(0x48c, 0x8000000a, true);
  return bytes;
};

void test("parseLinuxBootProtocol extracts bzImage metadata and compressed payload range", async () => {
  const parsed = await parseBytes(createLinuxBootBytes());

  assert.ok(parsed);
  assert.equal(parsed.setupSectorsRaw, 1);
  assert.equal(parsed.setupSectors, 1);
  assert.equal(parsed.protocolVersion, LINUX_BOOT_PROTOCOL_2_15);
  assert.equal(parsed.kernelVersion, "6.18.33-test");
  assert.equal(parsed.loadFlags, 0x81);
  assert.equal(parsed.xloadFlags, 0x000b);
  assert.equal(parsed.kernelAlignment, 0x01000000);
  assert.equal(parsed.relocatableKernel, true);
  assert.equal(parsed.cmdlineSize, 2047);
  assert.equal(parsed.preferredAddress, 0x1000000n);
  assert.equal(parsed.initSize, 0x03be0000);
  assert.equal(parsed.handoverOffset, 0x1074102);
  assert.equal(parsed.payload?.offset, 0x20);
  assert.equal(parsed.payload?.length, 6);
  assert.equal(parsed.payload?.fileOffset, 0x420);
  assert.equal(parsed.payload?.endOffset, 0x426);
  assert.equal(parsed.payload?.format, "gzip");
  assert.equal(parsed.payload?.magicHex, "1f 8b 08 00");
  assert.equal(parsed.payload?.gzip?.isGzip, true);
  assert.equal(parsed.payload?.gzip?.header.truncated, true);
  assert.ok(parsed.payload?.gzip?.issues.some(issue => /base header is truncated/i.test(issue)));
  assert.equal(parsed.kernelInfo?.fileOffset, 0x480);
  assert.equal(parsed.kernelInfo?.header, "LToP");
  assert.equal(parsed.kernelInfo?.setupTypeMax, 0x8000000a);
});

void test("parseLinuxBootProtocol treats missing HdrS as not a Linux boot image", async () => {
  const bytes = createLinuxBootBytes();
  bytes[LINUX_MAGIC_OFFSET] = 0;

  assert.equal(await parseBytes(bytes), null);
});

void test("parseLinuxBootProtocol warns when declared payload exceeds the file", async () => {
  const bytes = createLinuxBootBytes();
  new DataView(bytes.buffer).setUint32(PAYLOAD_LENGTH_OFFSET, bytes.length, true);

  const parsed = await parseBytes(bytes);

  assert.ok(parsed?.warnings?.some(warning => /payload range points outside/i.test(warning)));
  assert.equal(parsed?.payload?.fileOffset, 0x420);
});

void test("parseLinuxBootProtocol warns when recognized Linux setup header is truncated", async () => {
  const parsed = await parseBytes(createLinuxBootBytes().slice(0, LOAD_FLAGS_OFFSET));

  assert.ok(parsed);
  assert.ok(parsed.warnings?.some(warning => /field loadflags .* truncated/i.test(warning)));
  assert.ok(parsed.warnings?.some(warning => /field payload_offset .* truncated/i.test(warning)));
});

void test("parseLinuxBootProtocol skips fields gated by newer protocol versions", async () => {
  const bytes = createLinuxBootBytes();
  const view = new DataView(bytes.buffer);
  view.setUint16(VERSION_OFFSET, LINUX_BOOT_PROTOCOL_2_04, true);
  view.setUint32(PAYLOAD_LENGTH_OFFSET, 0, true);

  const parsed = await parseBytes(bytes);

  assert.equal(parsed?.protocolVersion, LINUX_BOOT_PROTOCOL_2_04);
  assert.equal(parsed?.kernelAlignment, undefined);
  assert.equal(parsed?.cmdlineSize, undefined);
  assert.equal(parsed?.xloadFlags, undefined);
  assert.equal(parsed?.preferredAddress, undefined);
  assert.equal(parsed?.handoverOffset, undefined);
  assert.equal(parsed?.kernelInfoOffset, undefined);
  assert.equal(parsed?.payload, undefined);
});

void test("parseLinuxBootProtocol reports out-of-file kernel_info ranges", async () => {
  const bytes = createLinuxBootBytes();
  new DataView(bytes.buffer).setUint32(KERNEL_INFO_OFFSET, bytes.length, true);

  const parsed = await parseBytes(bytes);

  assert.equal(parsed?.kernelInfo?.fileOffset, 0xa00);
  assert.ok(parsed?.kernelInfo?.warnings?.some(warning => /kernel_info range points outside/i.test(warning)));
});

void test("parseLinuxBootProtocol uses four setup sectors when setup_sects is zero", async () => {
  const bytes = createLinuxBootBytes();
  bytes[SETUP_SECTS_OFFSET] = 0;
  new DataView(bytes.buffer).setUint32(PAYLOAD_OFFSET, 0x10, true);
  const expanded = new Uint8Array(0xc00).fill(0);
  expanded.set(bytes);
  expanded.set([RFC1952_GZIP_ID1, RFC1952_GZIP_ID2, RFC1952_DEFLATE_COMPRESSION_METHOD, 0], 0xa10);

  const parsed = await parseBytes(expanded);

  assert.equal(parsed?.setupSectors, 4);
  assert.equal(parsed?.payload?.fileOffset, 0xa10);
});
