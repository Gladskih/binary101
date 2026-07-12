"use strict";

import { crc32 } from "../../crc32.js";
import { extractInnoSetupEngine } from "./inno-setup-engine.js";
import type {
  InnoSetupDetectorInput,
  PeInnoSetupFinding,
  PePackerDetectorResult
} from "./types.js";

// Inno Setup stores its loader offset table in RCDATA resource 11111. Legacy
// revision 1 is the 44-byte table decoded by innoextract's loader::offsets.
// https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Shared.Struct.pas
// https://github.com/dscharrer/innoextract/blob/master/src/loader/offsets.cpp
const OFFSET_TABLE_RESOURCE_ID = 11111;
const OFFSET_TABLE_BYTES = 44;
const OFFSET_TABLE_REVISION = 1;
const OFFSET_TABLE_MAGIC = Uint8Array.of(
  0x72, 0x44, 0x6c, 0x50, 0x74, 0x53, 0xcd, 0xe6, 0xd7, 0x7b, 0x0b, 0x2a
);

const hasMagic = (bytes: Uint8Array): boolean =>
  OFFSET_TABLE_MAGIC.every((value, index) => bytes[index] === value);

const createFinding = (tableOffset: number, view: DataView): PeInnoSetupFinding => ({
  id: "inno-setup",
  name: "Inno Setup installer",
  kind: "installer",
  confidence: "high",
  evidence: [
    "The RCDATA 11111 loader offset table has a recognized ID and matching CRC-32.",
    "All declared Inno Setup data, header, engine, and total-size bounds are ordered and in-file.",
    "The embedded setup engine decoded as LZMA, passed chunk and output CRC-32 checks, and is PE."
  ],
  dataOffset: view.getUint32(36, true),
  headerOffset: view.getUint32(32, true),
  offsetTableOffset: tableOffset,
  setupExeCrc32: view.getUint32(28, true),
  setupExeOffset: view.getUint32(20, true),
  setupExeStoredSize: 0,
  setupExeUnpackedSize: view.getUint32(24, true),
  totalSize: view.getUint32(16, true)
});

const validateBounds = (finding: PeInnoSetupFinding, fileSize: number): boolean =>
  finding.dataOffset < finding.headerOffset &&
  finding.headerOffset < finding.setupExeOffset &&
  finding.setupExeOffset < finding.totalSize &&
  finding.totalSize <= fileSize &&
  finding.setupExeUnpackedSize > 0;

const readFinding = async (
  input: InnoSetupDetectorInput,
  tableOffset: number,
  warnings: string[]
): Promise<PeInnoSetupFinding | null> => {
  const table = await input.reader.read(tableOffset, OFFSET_TABLE_BYTES);
  if (table.byteLength !== OFFSET_TABLE_BYTES) {
    warnings.push("Inno Setup loader offset table is truncated.");
    return null;
  }
  const bytes = new Uint8Array(table.buffer, table.byteOffset, table.byteLength);
  if (!hasMagic(bytes)) return null;
  if (table.getUint32(12, true) !== OFFSET_TABLE_REVISION) {
    warnings.push("Inno Setup loader offset table revision is unsupported.");
    return null;
  }
  if (crc32(bytes.subarray(0, 40)) !== table.getUint32(40, true)) {
    warnings.push("Inno Setup loader offset table CRC-32 does not match.");
    return null;
  }
  const baseFinding = createFinding(tableOffset, table);
  if (!validateBounds(baseFinding, input.reader.size)) {
    warnings.push("Inno Setup loader offsets are out of bounds or incorrectly ordered.");
    return null;
  }
  const blockHeader = await input.reader.read(baseFinding.setupExeOffset, 9);
  if (blockHeader.byteLength !== 9) {
    warnings.push("Inno Setup embedded engine block header is truncated.");
    return null;
  }
  const finding = {
    ...baseFinding,
    setupExeStoredSize: blockHeader.getUint32(4, true)
  };
  const blockEnd = finding.setupExeOffset + 9 + finding.setupExeStoredSize;
  if (!Number.isSafeInteger(blockEnd) || blockEnd > finding.totalSize) {
    warnings.push("Inno Setup embedded engine block extends past the declared total size.");
    return null;
  }
  try {
    await extractInnoSetupEngine(input.reader, finding);
  } catch (error) {
    warnings.push(error instanceof Error ? error.message : String(error));
    return null;
  }
  return finding;
};

export const detectInnoSetup = async (
  input: InnoSetupDetectorInput
): Promise<PePackerDetectorResult<PeInnoSetupFinding>> => {
  const findings: PeInnoSetupFinding[] = [];
  const warnings: string[] = [];
  for (const path of input.resources?.paths ?? []) {
    if (path.nodes[0]?.id !== 10 || path.nodes[1]?.id !== OFFSET_TABLE_RESOURCE_ID ||
        path.dataFileOffset == null) continue;
    if (path.size !== OFFSET_TABLE_BYTES) {
      warnings.push("Inno Setup loader offset table resource has an unsupported size.");
      continue;
    }
    const finding = await readFinding(input, path.dataFileOffset, warnings);
    if (finding) findings.push(finding);
  }
  return { findings, warnings };
};
