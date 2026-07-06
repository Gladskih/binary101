"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { COFF_FILE_HEADER_BYTE_LENGTH } from "../../../../../analyzers/coff/layout.js";
import { isPeWindowsParseResult, parsePe } from "../../../../../analyzers/pe/index.js";
import { createPeWithSectionAndIat } from "../../../../fixtures/sample-files-pe.js";
import { MockFile } from "../../../../helpers/mock-file.js";

// Microsoft PE/COFF: e_lfanew lives at IMAGE_DOS_HEADER offset 0x3c.
const DOS_PE_HEADER_POINTER_OFFSET = 0x3c;
// MS-DOS MZ header fields that WinMD SDK files commonly zero: e_cblp, e_cp, e_cparhdr.
const DOS_E_CBLP_OFFSET = 0x02;
const DOS_E_CP_OFFSET = 0x04;
const DOS_E_CPARHDR_OFFSET = 0x08;
// tests/fixtures/sample-files-pe.ts maps RVA 0x1100 to file offset 0x300.
const CLR_HEADER_RVA = 0x1100;
const CLR_HEADER_OFFSET = 0x300;
// Microsoft PE format: data-directory indices for IAT and CLR Runtime Header.
const IMAGE_DIRECTORY_ENTRY_IAT = 12;
const IMAGE_DIRECTORY_ENTRY_CLR_RUNTIME = 14;
// Microsoft PE/COFF: PE signature is 4 bytes and IMAGE_FILE_HEADER is 20 bytes.
const PE_SIGNATURE_SIZE = 4;
// Microsoft PE/COFF: IMAGE_OPTIONAL_HEADER32.DataDirectory begins 96 bytes into the optional header.
const PE32_DATA_DIRECTORIES_OFFSET = 0x60;
// ECMA-335 II.25.3.3: IMAGE_COR20_HEADER is 0x48 bytes.
const IMAGE_COR20_HEADER_SIZE = 0x48;
// ECMA-335 II.25.3.3 IMAGE_COR20_HEADER field offsets.
const COR20_CB_OFFSET = 0x00;
const COR20_MAJOR_RUNTIME_VERSION_OFFSET = 0x04;
const COR20_MINOR_RUNTIME_VERSION_OFFSET = 0x06;
const COR20_METADATA_OFFSET = 0x08;
const COR20_FLAGS_OFFSET = 0x10;
// ECMA-335 II.25.3.3 stores the metadata directory at offset 0x08.
const COR20_METADATA_SIZE_OFFSET = 0x0c;
// CLR runtime version 2.5 is the conventional WinMD/Windows Runtime metadata header version.
const WINMD_MAJOR_RUNTIME_VERSION = 2;
const WINMD_MINOR_RUNTIME_VERSION = 5;
// ECMA-335 II.25.3.3.1: COMIMAGE_FLAGS_ILONLY.
const COMIMAGE_FLAGS_ILONLY = 0x01;
// ECMA-335 II.24.2.1: metadata root signature "BSJB" = 0x424A5342.
const CLR_METADATA_ROOT_SIGNATURE = 0x424a5342;
// Microsoft Learn, "Windows Metadata (WinMD) files": a WinMD metadata root version
// string identifies Windows Runtime metadata. Windows SDK WinMDs use this compact token.
const WINMD_METADATA_VERSION = "WindowsRuntime 1.2";

const getPeView = (bytes: Uint8Array): DataView =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

const getDataDirectoryEntryOffset = (bytes: Uint8Array, index: number): number => {
  const view = getPeView(bytes);
  return (
    view.getUint32(DOS_PE_HEADER_POINTER_OFFSET, true) +
    PE_SIGNATURE_SIZE +
    COFF_FILE_HEADER_BYTE_LENGTH +
    PE32_DATA_DIRECTORIES_OFFSET +
    index * 8
  );
};

const writeDataDirectoryEntry = (
  view: DataView,
  bytes: Uint8Array,
  index: number,
  rva: number,
  size: number
): void => {
  const entryOffset = getDataDirectoryEntryOffset(bytes, index);
  view.setUint32(entryOffset, rva, true);
  view.setUint32(entryOffset + 4, size, true);
};

const writeMetadataRoot = (
  view: DataView,
  bytes: Uint8Array,
  offset: number,
  version: string
): number => {
  const versionBytes = new TextEncoder().encode(`${version}\0`);
  const versionLength = (versionBytes.length + 3) & ~3;
  view.setUint32(offset, CLR_METADATA_ROOT_SIGNATURE, true);
  view.setUint16(offset + 4, 1, true);
  view.setUint16(offset + 6, 1, true);
  view.setUint32(offset + 8, 0, true);
  view.setUint32(offset + 12, versionLength, true);
  bytes.set(versionBytes, offset + 16);
  view.setUint16(offset + 16 + versionLength, 0, true);
  view.setUint16(offset + 18 + versionLength, 0, true);
  return 20 + versionLength;
};

const createPeWithClrMetadataVersion = (version: string): Uint8Array => {
  const bytes = createPeWithSectionAndIat();
  const view = getPeView(bytes);
  const metadataRva = CLR_HEADER_RVA + IMAGE_COR20_HEADER_SIZE;
  const metadataOffset = CLR_HEADER_OFFSET + IMAGE_COR20_HEADER_SIZE;
  view.setUint16(DOS_E_CPARHDR_OFFSET, 0, true);
  view.setUint16(DOS_E_CP_OFFSET, 0, true);
  view.setUint16(DOS_E_CBLP_OFFSET, 0, true);
  writeDataDirectoryEntry(view, bytes, IMAGE_DIRECTORY_ENTRY_IAT, 0, 0);
  writeDataDirectoryEntry(
    view,
    bytes,
    IMAGE_DIRECTORY_ENTRY_CLR_RUNTIME,
    CLR_HEADER_RVA,
    IMAGE_COR20_HEADER_SIZE
  );
  view.setUint32(CLR_HEADER_OFFSET + COR20_CB_OFFSET, IMAGE_COR20_HEADER_SIZE, true);
  view.setUint16(CLR_HEADER_OFFSET + COR20_MAJOR_RUNTIME_VERSION_OFFSET, WINMD_MAJOR_RUNTIME_VERSION, true);
  view.setUint16(CLR_HEADER_OFFSET + COR20_MINOR_RUNTIME_VERSION_OFFSET, WINMD_MINOR_RUNTIME_VERSION, true);
  view.setUint32(CLR_HEADER_OFFSET + COR20_METADATA_OFFSET, metadataRva, true);
  view.setUint32(
    CLR_HEADER_OFFSET + COR20_METADATA_SIZE_OFFSET,
    writeMetadataRoot(view, bytes, metadataOffset, version),
    true
  );
  view.setUint32(CLR_HEADER_OFFSET + COR20_FLAGS_OFFSET, COMIMAGE_FLAGS_ILONLY, true);
  return bytes;
};

void test("parsePe marks WinMD PE files from CLR metadata version and suppresses DOS noise", async () => {
  const result = await parsePe(new MockFile(createPeWithClrMetadataVersion(WINMD_METADATA_VERSION), "x.winmd"));
  assert.ok(result);
  assert.ok(isPeWindowsParseResult(result));
  assert.equal(result.subtype, "winmd");
  assert.equal(result.clr?.meta?.version, WINMD_METADATA_VERSION);
  assert.ok(!result.warnings?.some(warning => /DOS header size e_cparhdr|DOS e_cp is zero/i.test(warning)));
});

void test("parsePe keeps DOS warnings for ordinary CLR PE files", async () => {
  const result = await parsePe(new MockFile(createPeWithClrMetadataVersion("v4.0.30319"), "clr.dll"));
  assert.ok(result);
  assert.ok(isPeWindowsParseResult(result));
  assert.equal(result.subtype, undefined);
  assert.ok(result.warnings?.some(warning => /DOS header size e_cparhdr/i.test(warning)));
  assert.ok(result.warnings?.some(warning => /DOS e_cp is zero/i.test(warning)));
});
