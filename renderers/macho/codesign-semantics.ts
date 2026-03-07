"use strict";

import {
  codeDirectoryExecSegFlags,
  codeDirectoryFlagNamesFor,
  codeDirectoryHashName,
  codeSignatureMagicName,
  codeSignatureSlotName
} from "../../analyzers/macho/codesign-info.js";

const codeSignatureBlobLabel = (magic: number | null): string =>
  magic == null ? "Unknown" : codeSignatureMagicName(magic) || `0x${magic.toString(16)}`;

const codeSignatureSlotLabelFor = (type: number): string => codeSignatureSlotName(type);
const codeDirectoryFlagLabels = (flags: number): string[] => codeDirectoryFlagNamesFor(flags);
const codeDirectoryHashLabel = (hashType: number): string => codeDirectoryHashName(hashType) || `hash ${hashType}`;
const codeDirectoryExecSegLabels = (flags: bigint | null): string[] =>
  flags == null ? [] : codeDirectoryExecSegFlags(flags);

const pageSizeBytes = (pageSizeShift: number): number | null => (pageSizeShift === 0 ? null : 1 << pageSizeShift);

export {
  codeDirectoryExecSegLabels,
  codeDirectoryFlagLabels,
  codeDirectoryHashLabel,
  codeSignatureBlobLabel,
  codeSignatureSlotLabelFor,
  pageSizeBytes
};
