"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { GzipParseResult } from "../../../../analyzers/gzip/types.js";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { renderLinuxBoot } from "../../../../renderers/pe/linux-boot.js";

const render = (pe: PeWindowsParseResult): string => {
  const out: string[] = [];
  renderLinuxBoot(pe, out);
  return out.join("");
};

const gzipPayloadSummary = {
  issues: [],
  stream: { compressedOffset: 10, compressedSize: 17201862, trailerOffset: 17201872 }
} as unknown as GzipParseResult;

const renderFlagOnlyLinuxBoot = (loadFlags: number, xloadFlags: number): string =>
  render({
    linuxBoot: {
      setupSectorsRaw: 1,
      setupSectors: 1,
      bootFlag: 0xaa55,
      protocolVersion: 0x020f,
      kernelVersionOffset: 0,
      loadFlags,
      xloadFlags
    }
  } as PeWindowsParseResult);

void test("renderLinuxBoot shows metadata and compressed payload download control", () => {
  const html = render({
    linuxBoot: {
      setupSectorsRaw: 31,
      setupSectors: 31,
      bootFlag: 0xaa55,
      protocolVersion: 0x020f,
      kernelVersionOffset: 0x3960,
      kernelVersion: "6.18.33-test",
      loadFlags: 0x01,
      xloadFlags: 0x000b,
      kernelAlignment: 0x01000000,
      relocatableKernel: true,
      cmdlineSize: 2047,
      preferredAddress: 0x1000000n,
      initSize: 0x03be0000,
      handoverOffset: 0x1074102,
      kernelInfoOffset: 0x1080d20,
      payload: {
        offset: 0x2cc,
        length: 17201880,
        fileOffset: 0x42cc,
        endOffset: 0x106bda4,
        format: "gzip",
        magicHex: "1f 8b 08 00",
        gzip: gzipPayloadSummary
      },
      kernelInfo: {
        fileOffset: 0x1084d20,
        header: "LToP",
        size: 16,
        totalSize: 16,
        setupTypeMax: 0x8000000a
      }
    }
  } as PeWindowsParseResult);

  assert.match(html, /Linux boot protocol/);
  assert.match(html, /6\.18\.33-test/);
  assert.match(html, /data-pe-linux-payload-download/);
  assert.match(html, /data-linux-payload-start="17100"/);
  assert.match(html, /data-linux-payload-end="17218980"/);
  assert.match(html, /gzip analyzer/);
  assert.match(html, /LToP/);
});

void test("renderLinuxBoot skips absent Linux boot metadata", () => {
  assert.equal(render({ linuxBoot: null } as PeWindowsParseResult), "");
});

void test("renderLinuxBoot names Linux-defined 0x60 flag bits", () => {
  // Linux/x86 Boot Protocol loadflags bits 5 and 6 are QUIET and KEEP_SEGMENTS;
  // Linux UAPI bootparam.h xloadflags bits 5 and 6 are 5LEVEL and 5LEVEL_ENABLED.
  const html = renderFlagOnlyLinuxBoot(0x60, 0x0060);

  assert.match(html, /QUIET/);
  assert.match(html, /KEEP_SEGMENTS/);
  assert.match(html, /5LEVEL/);
  assert.match(html, /5LEVEL_ENABLED/);
  assert.doesNotMatch(html, /UNKNOWN_BITS_0x0060/);
});
