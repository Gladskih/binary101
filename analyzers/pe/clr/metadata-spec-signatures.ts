"use strict";

import type { PeClrMethodSignature, PeClrSequenceSignature, PeClrTypeSignature } from "./types.js";
import { SignatureCursor } from "./signature-cursor.js";
import { parseSignatureType, parseTypeSequence } from "./signature-grammar.js";
import { parseMethodSignatureCore } from "./signature-method.js";

export const parseTypeSpecSignature = (
  blob: Uint8Array,
  context: string
): PeClrTypeSignature => {
  const issues: string[] = [];
  const cursor = new SignatureCursor(blob, issues, context);
  const type = parseSignatureType(cursor);
  cursor.finish();
  return { type, ...(issues.length ? { issues } : {}) };
};

const parseSequence = (cursor: SignatureCursor, header: number): string[] => {
  if (cursor.readU8() !== header) {
    cursor.fail(`does not start with signature header 0x${header.toString(16)}`);
    return [];
  }
  const count = cursor.readCount();
  if (count == null) return [];
  if (!count) {
    cursor.fail("type sequence has no elements");
    return [];
  }
  return parseTypeSequence(cursor, count);
};

export const parseMethodSpecSignature = (
  blob: Uint8Array,
  context: string
): PeClrSequenceSignature => {
  // ECMA-335 II.23.2.15: GENERICINST=0x0a followed by a type count and types.
  const issues: string[] = [];
  const cursor = new SignatureCursor(blob, issues, context);
  const types = parseSequence(cursor, 0x0a);
  cursor.finish();
  return { types, ...(issues.length ? { issues } : {}) };
};

export const parseStandaloneSignature = (
  blob: Uint8Array,
  context: string
): PeClrMethodSignature | PeClrSequenceSignature => {
  // ECMA-335 II.23.2.6: LOCAL_SIG=0x07; other StandAloneSig rows encode call-site methods.
  const cursor = new SignatureCursor(blob, [], context);
  return finishStandalone(cursor, blob[0] === 0x07
    ? { types: parseSequence(cursor, 0x07) }
    : parseMethodSignatureCore(cursor) ?? { types: [] });
};

const finishStandalone = (
  cursor: SignatureCursor,
  parsed: PeClrMethodSignature | PeClrSequenceSignature
): PeClrMethodSignature | PeClrSequenceSignature => {
  cursor.finish();
  return { ...parsed, ...(cursor.issues.length ? { issues: cursor.issues } : {}) };
};

export const parsePropertySignature = (
  blob: Uint8Array,
  context: string
): PeClrMethodSignature | PeClrSequenceSignature => {
  // ECMA-335 II.23.2.5: PROPERTY=0x08, optionally HASTHIS=0x20, then count and types.
  if (blob[0] !== 0x08 && blob[0] !== 0x28) {
    return { types: [], issues: [`${context} signature has an invalid PROPERTY header.`] };
  }
  return parseStandaloneSignature(blob, context);
};
