"use strict";

import type { IcedInstructionObject, IcedX86Module } from "../../x86/disassembly-iced.js";
import type { PeDelayImportEntry } from "../imports/delay.js";
import type { PeImportParseResult } from "../imports/index.js";
import type { RvaToOffset } from "../types.js";
import {
  collectPeApiStringCallArguments,
  peApiStringImportSlotRva,
  summarizePeApiStringInstruction
} from "./api-string-call-arguments.js";
import { buildPeApiStringImportTargets } from "./api-string-import-targets.js";
import {
  peApiStringAddressToRva,
  type PeApiStringPendingReference,
  type PeApiStringRecentInstruction,
  type PeApiStringReferenceCollector
} from "./api-string-reference-model.js";
import {
  peApiStringReferenceKey,
  readPeApiStringCandidate
} from "./api-string-reader.js";
import type { PeApiStringReference } from "./types.js";

// Small local window for argument setup immediately before a direct imported call.
const MAX_RECENT_INSTRUCTIONS = 16;

const recordCandidateCall = (
  candidates: PeApiStringPendingReference[],
  callSiteRva: number,
  collected: readonly PeApiStringPendingReference[]
): void => {
  for (const candidate of collected) {
    candidates.push({
      ...candidate,
      callSite: { ...candidate.callSite, instructionRva: callSiteRva }
    });
  }
};

const mergeReference = (
  references: Map<string, PeApiStringReference>,
  decoded: Omit<PeApiStringReference, "callSites">,
  candidate: PeApiStringPendingReference
): void => {
  const key = peApiStringReferenceKey(decoded);
  const current = references.get(key);
  if (current) {
    current.callSites.push(candidate.callSite);
    return;
  }
  references.set(key, { ...decoded, callSites: [candidate.callSite] });
};

export const createPeApiStringReferenceCollector = (
  iced: IcedX86Module,
  opts: {
    imageBase: bigint;
    is64Bit: boolean;
    imports?: PeImportParseResult | undefined;
    delayImports?: { entries: PeDelayImportEntry[] } | null | undefined;
    headerRvaLimit?: number | undefined;
    rvaToOff: RvaToOffset;
  }
): PeApiStringReferenceCollector => {
  const targets = buildPeApiStringImportTargets(opts.is64Bit, opts.imports, opts.delayImports);
  const recent: PeApiStringRecentInstruction[] = [];
  const candidates: PeApiStringPendingReference[] = [];
  const bitness = opts.is64Bit ? 64 : 32;
  let previousNextIp: bigint | null = null;
  return {
    record: (instruction: IcedInstructionObject): void => {
      if (previousNextIp != null && instruction.ip !== previousNextIp) recent.length = 0;
      const slotRva = peApiStringImportSlotRva(iced, opts.imageBase, instruction);
      const target = slotRva == null ? null : targets.get(slotRva);
      const callSiteRva = peApiStringAddressToRva(instruction.ip, opts.imageBase);
      if (target && callSiteRva != null) {
        recordCandidateCall(
          candidates,
          callSiteRva,
          collectPeApiStringCallArguments(bitness, target, recent)
        );
      }
      recent.push(summarizePeApiStringInstruction(iced, instruction));
      if (recent.length > MAX_RECENT_INSTRUCTIONS) recent.shift();
      previousNextIp = instruction.nextIP;
    },
    references: async reader => {
      const references = new Map<string, PeApiStringReference>();
      for (const candidate of candidates) {
        const decoded = await readPeApiStringCandidate(
          reader,
          opts.rvaToOff,
          opts.imageBase,
          candidate,
          { headerRvaLimit: opts.headerRvaLimit }
        );
        if (decoded) mergeReference(references, decoded, candidate);
      }
      return [...references.values()].sort((left, right) =>
        left.rva - right.rva || left.encoding.localeCompare(right.encoding));
    }
  };
};
