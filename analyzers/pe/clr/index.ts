"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "../types.js";

import {
  buildCor20Issues,
  COR20_HEADER_MIN_BYTES,
  COR20_HEADER_SIZE_BYTES,
  readCor20Header
} from "./cor20-header.js";
import { parseClrMetadataRoot } from "./metadata-root.js";
import { parseVTableFixups } from "./vtable-fixups.js";
import type { PeClrHeader } from "./types.js";

export type { PeClrHeader, PeClrMeta, PeClrStreamInfo, PeClrVTableFixup } from "./types.js";

// ECMA-335 II.25.3.3.1 ("Runtime flags"):
// https://carlwa.com/ecma-335/#ii.25.3.3.1-runtime-flags
const COMIMAGE_FLAGS_ILONLY = 0x00000001;
const COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002;
// Modern .NET CorFlags includes ILLibrary=0x00000004 even though older ECMA-335 tables omit it:
// https://source.dot.net/System.Reflection.Metadata/System/Reflection/PortableExecutable/CorFlags.cs.html
// https://learn.microsoft.com/en-us/dotnet/api/system.reflection.portableexecutable.corflags
const COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004;
// ECMA-335 II.25.3.3.1 ("Runtime flags"):
// https://carlwa.com/ecma-335/#ii.25.3.3.1-runtime-flags
const COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008;
const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010;
const COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x00010000;
// Modern .NET CorFlags includes Prefers32Bit=0x00020000:
// https://source.dot.net/System.Reflection.Metadata/System/Reflection/PortableExecutable/CorFlags.cs.html
// https://learn.microsoft.com/en-us/dotnet/api/system.reflection.portableexecutable.corflags
const COMIMAGE_FLAGS_32BITPREFERRED = 0x00020000;
const KNOWN_COMIMAGE_FLAGS =
  COMIMAGE_FLAGS_ILONLY |
  COMIMAGE_FLAGS_32BITREQUIRED |
  COMIMAGE_FLAGS_IL_LIBRARY |
  COMIMAGE_FLAGS_STRONGNAMESIGNED |
  COMIMAGE_FLAGS_NATIVE_ENTRYPOINT |
  COMIMAGE_FLAGS_TRACKDEBUGDATA |
  COMIMAGE_FLAGS_32BITPREFERRED;
// ECMA-335 II.25.3.3.2 says the managed entry point metadata token is always MethodDef or File.
// Table ids come from II.22.26 MethodDef: 0x06 and II.22.19 File: 0x26:
// https://carlwa.com/ecma-335/#ii.25.3.3.2-entry-point-metadata-token
const TOKEN_TABLE_METHODDEF = 0x06;
const TOKEN_TABLE_FILE = 0x26;

const addOptionalDirIssues = (
  name: string,
  rva: number,
  size: number,
  fileSize: number,
  rvaToOff: RvaToOffset,
  issues: string[]
): void => {
  if (rva === 0 && size === 0) return;
  if (rva === 0 && size !== 0) {
    issues.push(`${name} has a non-zero size but RVA is 0.`);
    return;
  }
  if (rva !== 0 && size === 0) {
    issues.push(`${name} has an RVA but size is 0.`);
    return;
  }
  const off = rvaToOff(rva);
  if (off == null) {
    issues.push(`${name} RVA could not be mapped to a file offset.`);
    return;
  }
  if (off < 0 || off >= fileSize) {
    issues.push(`${name} location is outside the file.`);
    return;
  }
  if (off + size > fileSize) {
    issues.push(`${name} data is truncated; spills past end of file.`);
  }
};

export async function parseClrDirectory(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<PeClrHeader | null> {
  const dir = dataDirs.find(d => d.name === "CLR_RUNTIME");
  if (!dir) return null;
  if (dir.rva === 0 && dir.size === 0) return null;
  const fileSize = reader.size;
  const issues: string[] = [];
  if (dir.rva === 0 && dir.size !== 0) issues.push("CLR directory has a non-zero size but RVA is 0.");
  if (dir.rva !== 0 && dir.size === 0) issues.push("CLR directory has an RVA but size is 0.");
  if (dir.rva === 0) {
    const empty = readCor20Header(new DataView(new ArrayBuffer(0)));
    if (issues.length) empty.issues = issues;
    return empty;
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    issues.push("CLR directory RVA could not be mapped to a file offset.");
    const empty = readCor20Header(new DataView(new ArrayBuffer(0)));
    if (issues.length) empty.issues = issues;
    return empty;
  }
  if (base < 0 || base >= fileSize) {
    issues.push("CLR directory location is outside the file.");
    const empty = readCor20Header(new DataView(new ArrayBuffer(0)));
    if (issues.length) empty.issues = issues;
    return empty;
  }
  const availableSize = Math.min(dir.size, Math.max(0, fileSize - base));
  issues.push(...buildCor20Issues(dir.size, availableSize));
  const clr = readCor20Header(
    await reader.read(base, Math.min(availableSize, COR20_HEADER_SIZE_BYTES))
  );
  if (clr.cb !== 0 && clr.cb !== COR20_HEADER_SIZE_BYTES) {
    issues.push(`CLR header cb is ${clr.cb} bytes; expected ${COR20_HEADER_SIZE_BYTES} (0x48).`);
  }
  if (clr.cb !== 0 && clr.cb < COR20_HEADER_MIN_BYTES) {
    issues.push("CLR header cb is smaller than the minimum header size (0x18 bytes).");
  }
  if (clr.cb !== 0 && dir.size !== 0 && dir.size < clr.cb) {
    issues.push("CLR directory size is smaller than the header cb field; header appears truncated.");
  }
  const unknownFlagBits = clr.Flags & ~KNOWN_COMIMAGE_FLAGS;
  if (unknownFlagBits !== 0) {
    issues.push(
      `CLR header Flags contains unknown bits (0x${unknownFlagBits.toString(16).padStart(8, "0")}).`
    );
  }
  if ((clr.Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) === 0 && clr.EntryPointToken !== 0) {
    const tokenTable = (clr.EntryPointToken >>> 24) & 0xff;
    if (tokenTable !== TOKEN_TABLE_METHODDEF && tokenTable !== TOKEN_TABLE_FILE) {
      issues.push("Managed EntryPointToken must reference a MethodDef or File token.");
    }
  }
  if (clr.MetaDataRVA === 0 && clr.MetaDataSize !== 0) {
    issues.push("Metadata has a non-zero size but RVA is 0.");
  }
  if (clr.MetaDataRVA !== 0 && clr.MetaDataSize === 0) {
    issues.push("Metadata has an RVA but size is 0.");
  }
  if (clr.MetaDataRVA !== 0 && clr.MetaDataSize !== 0) {
    const metaOffset = rvaToOff(clr.MetaDataRVA);
    if (metaOffset == null) {
      issues.push("Metadata RVA could not be mapped to a file offset.");
    } else {
      const meta = await parseClrMetadataRoot(reader, metaOffset, clr.MetaDataSize, issues);
      if (meta) clr.meta = meta;
    }
  }
  addOptionalDirIssues("Resources", clr.ResourcesRVA, clr.ResourcesSize, fileSize, rvaToOff, issues);
  addOptionalDirIssues(
    "StrongNameSignature",
    clr.StrongNameSignatureRVA,
    clr.StrongNameSignatureSize,
    fileSize,
    rvaToOff,
    issues
  );
  addOptionalDirIssues(
    "CodeManagerTable",
    clr.CodeManagerTableRVA,
    clr.CodeManagerTableSize,
    fileSize,
    rvaToOff,
    issues
  );
  addOptionalDirIssues(
    "ExportAddressTableJumps",
    clr.ExportAddressTableJumpsRVA,
    clr.ExportAddressTableJumpsSize,
    fileSize,
    rvaToOff,
    issues
  );
  addOptionalDirIssues(
    "ManagedNativeHeader",
    clr.ManagedNativeHeaderRVA,
    clr.ManagedNativeHeaderSize,
    fileSize,
    rvaToOff,
    issues
  );
  const fixups = await parseVTableFixups(
    reader,
    rvaToOff,
    fileSize,
    clr.VTableFixupsRVA,
    clr.VTableFixupsSize,
    issues
  );
  if (fixups) clr.vtableFixups = fixups;
  if (issues.length) clr.issues = issues;
  return clr;
}
