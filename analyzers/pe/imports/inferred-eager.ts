"use strict";

import type { PeIatDirectory } from "./iat.js";
import type { PeImportParseResult } from "./index.js";
import type {
  PeDeclaredIatRelation,
  PeImportLinkingFinding,
  PeInferredEagerIat,
  PeInferredEagerIatRange
} from "./linking-model.js";

const compareDeclaredIat = (
  ranges: PeInferredEagerIatRange[],
  iat: PeIatDirectory | null
): PeDeclaredIatRelation => {
  if (!iat?.rva || !iat.size) return "declared-absent";
  const declaredStart = iat.rva >>> 0;
  const declaredEnd = declaredStart + (iat.size >>> 0);
  const coversAllRanges = ranges.every(
    range => range.startRva >= declaredStart && range.endRva <= declaredEnd
  );
  if (!coversAllRanges) return "declared-misses-inferred";
  if (
    ranges.length === 1 &&
    ranges[0]?.startRva === declaredStart &&
    ranges[0]?.endRva === declaredEnd
  ) {
    return "exact-match";
  }
  return "declared-covers-inferred";
};

const mergeRanges = (
  ranges: PeInferredEagerIatRange[]
): PeInferredEagerIatRange[] => {
  const sorted = [...ranges].sort((left, right) => left.startRva - right.startRva);
  const merged: PeInferredEagerIatRange[] = [];
  sorted.forEach(range => {
    const previous = merged[merged.length - 1];
    if (!previous || range.startRva > previous.endRva) {
      merged.push({
        ...range,
        importIndices: [...range.importIndices]
      });
      return;
    }
    previous.endRva = Math.max(previous.endRva, range.endRva);
    previous.size = previous.endRva - previous.startRva;
    previous.importIndices = [...new Set([...previous.importIndices, ...range.importIndices])];
    previous.descriptorCount = previous.importIndices.length;
  });
  return merged;
};

const createRange = (
  importIndex: number,
  firstThunkRva: number,
  functionCount: number,
  thunkEntrySize: number,
  thunkTableTerminated: boolean
): PeInferredEagerIatRange | null => {
  if (!firstThunkRva) return null;
  const slotCount = functionCount + (thunkTableTerminated ? 1 : 0);
  if (!slotCount) return null;
  const startRva = firstThunkRva >>> 0;
  const size = slotCount * thunkEntrySize;
  return {
    startRva,
    endRva: startRva + size,
    size,
    importIndices: [importIndex],
    descriptorCount: 1
  };
};

const buildFindings = (
  inferredEagerIat: PeInferredEagerIat
): PeImportLinkingFinding[] => {
  if (inferredEagerIat.relationToDeclared === "declared-absent") {
    return [{
      code: "declared-iat-absent-inferred-eager",
      severity: "info",
      message:
        "IMAGE_DIRECTORY_ENTRY_IAT is absent, but eager IAT ranges were inferred from FirstThunk values in the import descriptors."
    }];
  }
  if (inferredEagerIat.relationToDeclared === "exact-match") {
    return [{
      code: "declared-iat-exact-match",
      severity: "confirmed",
      message:
        "IMAGE_DIRECTORY_ENTRY_IAT exactly matches the inferred eager IAT range built from FirstThunk values."
    }];
  }
  if (inferredEagerIat.relationToDeclared === "declared-covers-inferred") {
    return [{
      code: "declared-iat-covers-inferred-eager",
      severity: "confirmed",
      message:
        "IMAGE_DIRECTORY_ENTRY_IAT covers all inferred eager IAT ranges built from FirstThunk values."
    }];
  }
  return [{
    code: "declared-iat-misses-inferred-eager",
    severity: "warning",
    message:
      "IMAGE_DIRECTORY_ENTRY_IAT does not cover all eager IAT ranges inferred from FirstThunk values."
  }];
};

export const analyzeInferredEagerIat = (
  imports: PeImportParseResult,
  iat: PeIatDirectory | null
): { inferredEagerIat: PeInferredEagerIat | null; findings: PeImportLinkingFinding[] } => {
  const rawRanges = imports.entries
    .map((entry, importIndex) =>
      createRange(
        importIndex,
        entry.firstThunkRva,
        entry.functions.length,
        imports.thunkEntrySize,
        entry.thunkTableTerminated
      )
    )
    .filter((range): range is PeInferredEagerIatRange => range != null);
  if (!rawRanges.length) return { inferredEagerIat: null, findings: [] };
  const ranges = mergeRanges(rawRanges);
  const aggregateStartRva = ranges[0]?.startRva ?? 0;
  const aggregateEndRva = ranges[ranges.length - 1]?.endRva ?? aggregateStartRva;
  const inferredEagerIat: PeInferredEagerIat = {
    ranges,
    aggregateStartRva,
    aggregateEndRva,
    aggregateSize: aggregateEndRva - aggregateStartRva,
    thunkEntrySize: imports.thunkEntrySize,
    relationToDeclared: compareDeclaredIat(ranges, iat)
  };
  return {
    inferredEagerIat,
    findings: buildFindings(inferredEagerIat)
  };
};
