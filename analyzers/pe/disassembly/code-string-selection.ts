"use strict";

import type {
  PeApiStringEncoding,
  PeApiStringReference,
  PeCodeStringReference
} from "./types.js";

const SIMPLEST_ENCODINGS: readonly PeApiStringEncoding[] = ["ascii", "utf-8", "utf-16le"];
const LATIN_SCRIPT = /^\p{Script=Latin}$/u;
const LATIN_CONTEXT = /^[\p{Decimal_Number}\s._:/\\?&=%+#@,;'"()[\]{}<>!-]$/u;

const sortInstructionRvas = (rvas: number[]): number[] =>
  rvas.sort((left, right) => left - right);

const mergeInstructionRvas = (
  left: readonly number[],
  right: readonly number[]
): number[] => sortInstructionRvas([...new Set([...left, ...right])]);

const encodingRank = (encoding: PeApiStringEncoding): number =>
  SIMPLEST_ENCODINGS.indexOf(encoding);

const compareEncoding = (
  left: PeApiStringEncoding,
  right: PeApiStringEncoding
): number => encodingRank(left) - encodingRank(right) || left.localeCompare(right);

const compareReferences = (
  left: PeCodeStringReference,
  right: PeCodeStringReference
): number =>
  left.rva - right.rva ||
  compareEncoding(left.encoding, right.encoding) ||
  left.byteLength - right.byteLength ||
  left.text.localeCompare(right.text);

const selectSimplestReference = (
  references: readonly PeCodeStringReference[]
): PeCodeStringReference =>
  [...references].sort((left, right) =>
    compareEncoding(left.encoding, right.encoding) ||
    right.byteLength - left.byteLength ||
    left.text.localeCompare(right.text))[0] as PeCodeStringReference;

const apiEncodingsByRva = (
  references: readonly PeApiStringReference[]
): Map<number, Set<PeApiStringEncoding>> => {
  const out = new Map<number, Set<PeApiStringEncoding>>();
  for (const reference of references) {
    const encodings = out.get(reference.rva) ?? new Set<PeApiStringEncoding>();
    encodings.add(reference.encoding);
    out.set(reference.rva, encodings);
  }
  return out;
};

const groupReferencesByRva = (
  references: readonly PeCodeStringReference[]
): Map<number, PeCodeStringReference[]> => {
  const out = new Map<number, PeCodeStringReference[]>();
  for (const reference of references) {
    out.set(reference.rva, [...(out.get(reference.rva) ?? []), reference]);
  }
  return out;
};

const isPredominantlyLatin = (text: string): boolean => {
  let latinWeight = 0;
  let otherWeight = 0;
  let latinLetters = 0;
  for (const character of text) {
    if (LATIN_SCRIPT.test(character)) {
      latinWeight += 1;
      latinLetters += 1;
    } else if (LATIN_CONTEXT.test(character)) {
      latinWeight += 1;
    } else {
      otherWeight += 1;
    }
  }
  return latinLetters > 0 && latinWeight > otherWeight;
};

const selectReferencesForRva = (
  references: readonly PeCodeStringReference[],
  apiEncodings: Set<PeApiStringEncoding> | undefined
): PeCodeStringReference[] => {
  const first = references[0];
  if (!first) return [];
  if (apiEncodings?.size === 1) {
    const apiMatches = references.filter(reference => apiEncodings.has(reference.encoding));
    if (apiMatches.length > 0) return [selectSimplestReference(apiMatches)];
  }
  if (references.every(reference => reference.text === first.text)) {
    return [selectSimplestReference(references)];
  }
  const latinReferences = references.filter(reference => isPredominantlyLatin(reference.text));
  return latinReferences.length > 0
    ? [selectSimplestReference(latinReferences)]
    : [...references].sort(compareReferences);
};

const referenceEnd = (reference: PeCodeStringReference): number => {
  if (!Number.isSafeInteger(reference.byteLength) || reference.byteLength <= 0) {
    return reference.rva;
  }
  const end = reference.rva + reference.byteLength;
  return Number.isSafeInteger(end) && end >= reference.rva ? end : reference.rva;
};

const containsReference = (
  outer: PeCodeStringReference,
  inner: PeCodeStringReference
): boolean =>
  outer.rva < inner.rva && referenceEnd(inner) <= referenceEnd(outer);

const mergeContainedReferences = (
  references: readonly PeCodeStringReference[]
): PeCodeStringReference[] => {
  const out: PeCodeStringReference[] = [];
  const ordered = [...references].sort((left, right) =>
    left.rva - right.rva ||
    referenceEnd(right) - referenceEnd(left) ||
    compareReferences(left, right));
  for (const reference of ordered) {
    const containerIndex = out.findIndex(candidate => containsReference(candidate, reference));
    if (containerIndex < 0) {
      out.push(reference);
      continue;
    }
    const container = out[containerIndex];
    if (!container) continue;
    out[containerIndex] = {
      ...container,
      instructionRvas: mergeInstructionRvas(
        container.instructionRvas,
        reference.instructionRvas
      )
    };
  }
  return out.sort(compareReferences);
};

export const selectPeCodeStringReferences = (
  references: readonly PeCodeStringReference[],
  apiReferences: readonly PeApiStringReference[]
): PeCodeStringReference[] => {
  const apiEncodings = apiEncodingsByRva(apiReferences);
  const selected: PeCodeStringReference[] = [];
  for (const [rva, rvaReferences] of groupReferencesByRva(references)) {
    selected.push(...selectReferencesForRva(rvaReferences, apiEncodings.get(rva)));
  }
  return mergeContainedReferences(selected);
};
