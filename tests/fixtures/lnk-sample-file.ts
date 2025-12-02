"use strict";

import { MockFile } from "../helpers/mock-file.js";
import {
  FILETIME_EPOCH_BIAS_MS,
  concatParts,
  makeNullTerminatedAscii,
  makeNullTerminatedUnicode,
  writeGuid
} from "./lnk-fixture-helpers.js";
import {
  buildEnvironmentBlock,
  buildIdList,
  buildKnownFolderBlock,
  buildLinkInfo,
  buildPropertyStoreBlock,
  buildUnicodeStringData,
  buildVolumeId,
  createDosTimestamp
} from "./lnk-block-builders.js";

export const createLnkFile = () => {
  const linkFlags =
    0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040 | 0x00000080;
  const header = new Uint8Array(0x4c).fill(0);
  const hdv = new DataView(header.buffer);
  hdv.setUint32(0, 0x4c, true);
  writeGuid(header, 4, "00021401-0000-0000-c000-000000000046");
  hdv.setUint32(0x14, linkFlags, true);
  hdv.setUint32(0x18, 0x00000020, true);
  const filetime = (BigInt(Date.UTC(2024, 0, 2, 12, 0, 0)) + FILETIME_EPOCH_BIAS_MS) * 10000n;
  hdv.setBigUint64(0x1c, filetime, true);
  hdv.setBigUint64(0x24, filetime, true);
  hdv.setBigUint64(0x2c, filetime, true);
  hdv.setUint32(0x34, 12345, true);
  hdv.setUint32(0x38, 1, true);
  hdv.setUint32(0x3c, 1, true);

  const dosTimestamp = createDosTimestamp();

  const volumeId = buildVolumeId("DATA");
  const localBasePath = makeNullTerminatedAscii("C:\\Program Files\\Example");
  const commonPathSuffix = makeNullTerminatedAscii("app.exe");
  const localBasePathUnicode = makeNullTerminatedUnicode("C:\\Program Files\\Example");
  const commonPathSuffixUnicode = makeNullTerminatedUnicode("app.exe");
  const linkInfo = buildLinkInfo(
    volumeId,
    localBasePath,
    commonPathSuffix,
    localBasePathUnicode,
    commonPathSuffixUnicode
  );

  const strings = [
    buildUnicodeStringData("Sample shortcut"),
    buildUnicodeStringData(".\\Example\\app.exe"),
    buildUnicodeStringData("C:\\Program Files\\Example"),
    buildUnicodeStringData("--demo"),
    buildUnicodeStringData("%SystemRoot%\\system32\\shell32.dll,0")
  ];
  const envBlock = buildEnvironmentBlock("%USERPROFILE%\\Example\\app.exe");
  const knownFolderBlock = buildKnownFolderBlock();
  const propertyStoreBlock = buildPropertyStoreBlock();
  const terminalBlock = new Uint8Array(4).fill(0);

  const bytes = concatParts([
    header,
    buildIdList(dosTimestamp),
    linkInfo,
    ...strings,
    envBlock,
    knownFolderBlock,
    propertyStoreBlock,
    terminalBlock
  ]);
  return new MockFile(bytes, "sample.lnk", "application/octet-stream");
};
