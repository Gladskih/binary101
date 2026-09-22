"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { CoffDebugInfo } from "../../coff/debug-types.js";
import type { RvaToOffset } from "../types.js";
import { parseCodeViewEntry, type PeCodeViewEntry } from "./codeview.js";
import { parseCoffDebugInfo } from "./coff.js";
import {
  parseEmbeddedPortablePdbInfo,
  type PeEmbeddedPortablePdbInfo
} from "./embedded-portable-pdb.js";
import { parseExceptionDebugInfo } from "./exception.js";
import type { PeExceptionDirectory } from "../exception/index.js";
import {
  parseExDllCharacteristicsInfo,
  type PeExDllCharacteristicsInfo
} from "./ex-dll-characteristics.js";
import { parseFpoInfo, type PeFpoInfo } from "./fpo.js";
import { parseMiscDebugInfo, type PeMiscDebugInfo } from "./misc.js";
import { parseOmapInfo, type PeOmapInfo } from "./omap.js";
import { parsePdbChecksumInfo, type PePdbChecksumInfo } from "./pdb-checksum.js";
import { parsePogoInfo, type PePogoInfo } from "./pogo.js";
import { parseR2rPerfMapInfo, type PeR2rPerfMapInfo } from "./r2r-perfmap.js";
import { parseRawDebugPayload, type PeRawDebugPayload } from "./raw-payload.js";
import { parseReproInfo, type PeReproInfo } from "./repro.js";
import {
  IMAGE_DEBUG_TYPE_COFF,
  IMAGE_DEBUG_TYPE_CODEVIEW,
  IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB,
  IMAGE_DEBUG_TYPE_EXCEPTION,
  IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS,
  IMAGE_DEBUG_TYPE_FPO,
  IMAGE_DEBUG_TYPE_MISC,
  IMAGE_DEBUG_TYPE_OMAP_TO_SRC,
  IMAGE_DEBUG_TYPE_OMAP_FROM_SRC,
  IMAGE_DEBUG_TYPE_PDB_CHECKSUM,
  IMAGE_DEBUG_TYPE_POGO,
  IMAGE_DEBUG_TYPE_R2R_PERFMAP,
  IMAGE_DEBUG_TYPE_REPRO,
  IMAGE_DEBUG_TYPE_SPGO,
  IMAGE_DEBUG_TYPE_VC_FEATURE
} from "./types.js";
import { parseVcFeatureInfo, type PeVcFeatureInfo } from "./vc-feature.js";

export type PeDebugPayloads = {
  coff?: CoffDebugInfo;
  codeView?: PeCodeViewEntry;
  fpo?: PeFpoInfo;
  misc?: PeMiscDebugInfo;
  omap?: PeOmapInfo;
  vcFeature?: PeVcFeatureInfo;
  pogo?: PePogoInfo;
  repro?: PeReproInfo;
  embeddedPortablePdb?: PeEmbeddedPortablePdbInfo;
  exception?: PeExceptionDirectory;
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
  machine: number;
};

const hasDecodedPayload = (payloads: PeDebugPayloads): boolean =>
  Boolean(
    payloads.codeView ||
      payloads.coff ||
      payloads.fpo ||
      payloads.misc ||
      payloads.omap ||
      payloads.vcFeature ||
      payloads.pogo ||
      payloads.repro ||
      payloads.embeddedPortablePdb ||
      payloads.exception ||
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

type DebugPayloadParser = (
  ...args: Parameters<typeof parseOmapInfo>
) => Promise<PeDebugPayloads[keyof PeDebugPayloads] | null>;

const PAYLOAD_DECODERS: Partial<Record<number, readonly [keyof PeDebugPayloads, DebugPayloadParser]>> = {
  [IMAGE_DEBUG_TYPE_COFF]: ["coff", parseCoffDebugInfo],
  [IMAGE_DEBUG_TYPE_CODEVIEW]: ["codeView", parseCodeViewEntry],
  [IMAGE_DEBUG_TYPE_FPO]: ["fpo", parseFpoInfo],
  [IMAGE_DEBUG_TYPE_MISC]: ["misc", parseMiscDebugInfo],
  [IMAGE_DEBUG_TYPE_OMAP_TO_SRC]: ["omap", parseOmapInfo],
  [IMAGE_DEBUG_TYPE_OMAP_FROM_SRC]: ["omap", parseOmapInfo],
  [IMAGE_DEBUG_TYPE_VC_FEATURE]: ["vcFeature", parseVcFeatureInfo],
  [IMAGE_DEBUG_TYPE_POGO]: ["pogo", parsePogoInfo],
  [IMAGE_DEBUG_TYPE_SPGO]: ["pogo", parsePogoInfo],
  [IMAGE_DEBUG_TYPE_REPRO]: ["repro", parseReproInfo],
  [IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB]: ["embeddedPortablePdb", parseEmbeddedPortablePdbInfo],
  [IMAGE_DEBUG_TYPE_PDB_CHECKSUM]: ["pdbChecksum", parsePdbChecksumInfo],
  [IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS]: ["exDllCharacteristics", parseExDllCharacteristicsInfo],
  [IMAGE_DEBUG_TYPE_R2R_PERFMAP]: ["r2rPerfMap", parseR2rPerfMapInfo]
};

const parseKnownPayload = async (
  reader: FileRangeReader,
  input: DecodeInput,
  addWarning: (message: string) => void
): Promise<PeDebugPayloads> => {
  if (input.type === IMAGE_DEBUG_TYPE_EXCEPTION) {
    const exception = await parseExceptionDebugInfo(
      reader, input.fileSize, input.rvaToOff, input.addressOfRawDataRva,
      input.pointerToRawDataOff, input.dataSize, input.machine, addWarning
    );
    return exception ? { exception } : {};
  }
  const decoder = PAYLOAD_DECODERS[input.type];
  if (!decoder) return {};
  const [key, parse] = decoder;
  const payload = await parse(reader, input.fileSize, input.rvaToOff,
    input.addressOfRawDataRva, input.pointerToRawDataOff, input.dataSize, addWarning);
  return payload ? { [key]: payload } : {};
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
