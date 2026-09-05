"use strict";

import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import type { PeSection } from "../../analyzers/pe/types.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import { MockFile } from "../helpers/mock-file.js";
import { createPeWithSectionAndIat } from "./sample-files-pe.js";

// Synthetic layout, independent of the production parser: .data occupies [0x100, 0x700),
// maps to RVA 0x2000, and contains a locator at +0x48 and a path at +0x180.
// A 0x1000-byte file also leaves room for an appended bundle header at 0x800.
const DATA_OFFSET = 0x100;
const DATA_RVA = 0x2000;
const DATA_SIZE = 0x600;

// dotnet/runtime src/native/corehost/apphost/bundle_marker.c:
// Literal marker bytes; also SHA-256 of UTF-8 ".net core bundle\n", including LF.
// https://github.com/dotnet/runtime/blob/main/src/native/corehost/apphost/bundle_marker.c
const BUNDLE_SIGNATURE = Uint8Array.from([
  0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
  0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
  0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
  0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
]);

export type PeAppHostFixture = {
  bytes: Uint8Array;
  file: MockFile;
  reader: ReturnType<typeof createFileRangeReader>;
  section: PeSection;
};

export const createPeAppHostFixture = (
  bundleHeaderOffset = 0n,
  applicationPath = "Fixture.dll"
): PeAppHostFixture => {
  const bytes = new Uint8Array(0x1000);
  const markerOffset = DATA_OFFSET + 0x48;
  new DataView(bytes.buffer).setBigInt64(markerOffset, bundleHeaderOffset, true);
  bytes.set(BUNDLE_SIGNATURE, markerOffset + 8);
  bytes.set(new TextEncoder().encode(`${applicationPath}\0`), DATA_OFFSET + 0x180);
  const file = new MockFile(bytes, "fixture.exe");
  return {
    bytes,
    file,
    reader: createFileRangeReader(file, 0, file.size),
    section: {
      name: inlinePeSectionName(".data"),
      virtualSize: DATA_SIZE,
      virtualAddress: DATA_RVA,
      sizeOfRawData: DATA_SIZE,
      pointerToRawData: DATA_OFFSET,
      // Microsoft PE format: initialized, readable, writable data.
      characteristics: 0xc0000040
    }
  };
};

export const writeBundleHeader = (fixture: PeAppHostFixture, offset: number): void => {
  // Packed header_fixed_t: major@0, minor@4, count@8; ID length@12 and ID@13.
  // v2 fields: two (int64 offset, int64 size) locations, then uint64 flags at +32.
  // https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/header.h
  const view = new DataView(fixture.bytes.buffer);
  view.setUint32(offset, 6, true);
  view.setUint32(offset + 4, 0, true);
  view.setInt32(offset + 8, 3, true);
  const bundleId = new TextEncoder().encode("fixture-id");
  fixture.bytes[offset + 12] = bundleId.byteLength;
  fixture.bytes.set(bundleId, offset + 13);
  const versionTwoOffset = offset + 13 + bundleId.byteLength;
  view.setBigInt64(versionTwoOffset, 0x700n, true);
  view.setBigInt64(versionTwoOffset + 8, 0x20n, true);
  view.setBigInt64(versionTwoOffset + 16, 0x720n, true);
  view.setBigInt64(versionTwoOffset + 24, 0x30n, true);
  view.setBigUint64(versionTwoOffset + 32, 1n, true);
  refreshPeAppHostFixture(fixture);
};

export const refreshPeAppHostFixture = (fixture: PeAppHostFixture): void => {
  fixture.file = new MockFile(fixture.bytes, "fixture.exe");
  fixture.reader = createFileRangeReader(fixture.file, 0, fixture.file.size);
};

export const appHostFixtureRva = (fileOffset: number): number =>
  DATA_RVA + fileOffset - DATA_OFFSET;

export const createIntegratedPeAppHostFile = (): MockFile => {
  const bytes = createPeWithSectionAndIat();
  const view = new DataView(bytes.buffer);
  // The sample PE section header begins at 0x138; Characteristics is at +0x24.
  view.setUint32(0x15c, 0xc0000040, true);
  bytes.set(BUNDLE_SIGNATURE, 0x228);
  bytes.set(new TextEncoder().encode("Integrated.dll\0"), 0x280);
  return new MockFile(bytes, "integrated-apphost.exe");
};
