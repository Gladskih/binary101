"use strict";

import type { PeClrMethodSignature } from "./types.js";
import { SignatureCursor } from "./signature-cursor.js";
import { parseFieldSignatureCore, parseMethodSignatureCore } from "./signature-grammar.js";

const parseSignature = (
  blob: Uint8Array | null,
  context: string,
  parse: (cursor: SignatureCursor) => PeClrMethodSignature | null
): PeClrMethodSignature | undefined => {
  if (!blob) return undefined;
  const issues: string[] = [];
  const cursor = new SignatureCursor(blob, issues, context);
  const parsed = parse(cursor);
  cursor.finish();
  if (!parsed) return { callingConvention: 0, parameterCount: 0, returnType: null, parameterTypes: [], issues };
  return issues.length ? { ...parsed, issues } : parsed;
};

export const parseMethodSignature = (
  blob: Uint8Array | null,
  context: string
): PeClrMethodSignature | undefined => parseSignature(blob, context, parseMethodSignatureCore);

export const parseMemberRefSignature = (
  blob: Uint8Array | null,
  context: string
): PeClrMethodSignature | undefined => parseSignature(
  blob, context, blob?.[0] === 0x06 ? parseFieldSignatureCore : parseMethodSignatureCore
);

export const parseFieldSignature = (
  blob: Uint8Array | null,
  context: string
): PeClrMethodSignature | undefined => parseSignature(blob, context, parseFieldSignatureCore);
