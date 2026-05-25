"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import { parseCodeViewEntry, type PeCodeViewEntry } from "./codeview.js";
import {
  parseEmbeddedPortablePdbInfo,
  type PeEmbeddedPortablePdbInfo
} from "./embedded-portable-pdb.js";
import {
  parseExDllCharacteristicsInfo,
  type PeExDllCharacteristicsInfo
} from "./ex-dll-characteristics.js";
import { parseFpoInfo, type PeFpoInfo } from "./fpo.js";
import { parseMiscDebugInfo, type PeMiscDebugInfo } from "./misc.js";
import { parsePdbChecksumInfo, type PePdbChecksumInfo } from "./pdb-checksum.js";
import { parsePogoInfo, type PePogoInfo } from "./pogo.js";
import { parseR2rPerfMapInfo, type PeR2rPerfMapInfo } from "./r2r-perfmap.js";
import { parseRawDebugPayload, type PeRawDebugPayload } from "./raw-payload.js";
import { parseReproInfo, type PeReproInfo } from "./repro.js";
import {
  IMAGE_DEBUG_TYPE_CODEVIEW,
  IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB,
  IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS,
  IMAGE_DEBUG_TYPE_FPO,
  IMAGE_DEBUG_TYPE_MISC,
  IMAGE_DEBUG_TYPE_PDB_CHECKSUM,
  IMAGE_DEBUG_TYPE_POGO,
  IMAGE_DEBUG_TYPE_R2R_PERFMAP,
  IMAGE_DEBUG_TYPE_REPRO,
  IMAGE_DEBUG_TYPE_SPGO,
  IMAGE_DEBUG_TYPE_VC_FEATURE
} from "./types.js";
import { parseVcFeatureInfo, type PeVcFeatureInfo } from "./vc-feature.js";

export type PeDebugPayloads = {
  codeView?: PeCodeViewEntry;
  fpo?: PeFpoInfo;
  misc?: PeMiscDebugInfo;
  vcFeature?: PeVcFeatureInfo;
  pogo?: PePogoInfo;
  repro?: PeReproInfo;
  embeddedPortablePdb?: PeEmbeddedPortablePdbInfo;
  pdbChecksum?: PePdbChecksumInfo;
  exDllCharacteristics?: PeExDllCharacteristicsInfo;
  r2rPerfMap?: PeR2rPerfMapInfo;
  rawPayload?: PeRawDebugPayload;
};

type DecodeInput = {
  type: number;
  typeName: string;
  fileSize: number;
  rvaToOff: RvaToOffset;
  addressOfRawDataRva: number;
  pointerToRawDataOff: number;
  dataSize: number;
};

const hasDecodedPayload = (payloads: PeDebugPayloads): boolean =>
  Boolean(
    payloads.codeView ||
      payloads.fpo ||
      payloads.misc ||
      payloads.vcFeature ||
      payloads.pogo ||
      payloads.repro ||
      payloads.embeddedPortablePdb ||
      payloads.pdbChecksum ||
      payloads.exDllCharacteristics ||
      payloads.r2rPerfMap ||
      payloads.rawPayload
  );

const readRawFallback = (
  reader: FileRangeReader,
  input: DecodeInput,
  addWarning: (message: string) => void
): Promise<PeRawDebugPayload | null> =>
  input.dataSize > 0
    ? parseRawDebugPayload(
        input.typeName,
        reader,
        input.fileSize,
        input.rvaToOff,
        input.addressOfRawDataRva,
        input.pointerToRawDataOff,
        input.dataSize,
        addWarning
      )
    : Promise.resolve(null);

const parseKnownPayload = async (
  reader: FileRangeReader,
  input: DecodeInput,
  addWarning: (message: string) => void
): Promise<PeDebugPayloads> => {
  const args = [
    reader,
    input.fileSize,
    input.rvaToOff,
    input.addressOfRawDataRva,
    input.pointerToRawDataOff,
    input.dataSize,
    addWarning
  ] as const;
  if (input.type === IMAGE_DEBUG_TYPE_CODEVIEW) {
    const codeView = await parseCodeViewEntry(...args);
    return codeView ? { codeView } : {};
  }
  if (input.type === IMAGE_DEBUG_TYPE_FPO) {
    const fpo = await parseFpoInfo(...args);
    return fpo ? { fpo } : {};
  }
  if (input.type === IMAGE_DEBUG_TYPE_MISC) {
    const misc = await parseMiscDebugInfo(...args);
    return misc ? { misc } : {};
  }
  if (input.type === IMAGE_DEBUG_TYPE_VC_FEATURE) {
    const vcFeature = await parseVcFeatureInfo(...args);
    return vcFeature ? { vcFeature } : {};
  }
  if (input.type === IMAGE_DEBUG_TYPE_POGO || input.type === IMAGE_DEBUG_TYPE_SPGO) {
    const pogo = await parsePogoInfo(...args);
    return pogo ? { pogo } : {};
  }
  if (input.type === IMAGE_DEBUG_TYPE_REPRO) {
    const repro = await parseReproInfo(...args);
    return repro ? { repro } : {};
  }
  if (input.type === IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB) {
    const embeddedPortablePdb = await parseEmbeddedPortablePdbInfo(...args);
    return embeddedPortablePdb ? { embeddedPortablePdb } : {};
  }
  if (input.type === IMAGE_DEBUG_TYPE_PDB_CHECKSUM) {
    const pdbChecksum = await parsePdbChecksumInfo(...args);
    return pdbChecksum ? { pdbChecksum } : {};
  }
  if (input.type === IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS) {
    const exDllCharacteristics = await parseExDllCharacteristicsInfo(...args);
    return exDllCharacteristics ? { exDllCharacteristics } : {};
  }
  if (input.type === IMAGE_DEBUG_TYPE_R2R_PERFMAP) {
    const r2rPerfMap = await parseR2rPerfMapInfo(...args);
    return r2rPerfMap ? { r2rPerfMap } : {};
  }
  return {};
};

export const decodeDebugEntryPayload = async (
  reader: FileRangeReader,
  input: DecodeInput,
  addWarning: (message: string) => void
): Promise<PeDebugPayloads> => {
  const payloads = await parseKnownPayload(reader, input, addWarning);
  if (hasDecodedPayload(payloads)) return payloads;
  const rawPayload = await readRawFallback(reader, input, addWarning);
  return rawPayload ? { ...payloads, rawPayload } : payloads;
};
