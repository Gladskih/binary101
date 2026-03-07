"use strict";

import {
  codeDirectoryExecSegFlags,
  codeDirectoryFlagNamesFor,
  codeDirectoryHashName,
  codeSignatureMagicName,
  codeSignatureSlotName
} from "../../analyzers/macho/codesign-info.js";
import { formatByteSize } from "./value-format.js";

const codeSignatureBlobLabel = (magic: number | null): string =>
  magic == null ? "Unknown" : codeSignatureMagicName(magic) || `0x${magic.toString(16)}`;

const codeSignatureSlotLabelFor = (type: number): string => codeSignatureSlotName(type);
const codeDirectoryFlagLabels = (flags: number): string[] => codeDirectoryFlagNamesFor(flags);
const codeDirectoryHashLabel = (hashType: number): string => codeDirectoryHashName(hashType) || `hash ${hashType}`;
const codeDirectoryExecSegLabels = (flags: bigint | null): string[] =>
  flags == null ? [] : codeDirectoryExecSegFlags(flags);
const pageSizeLabel = (pageSizeShift: number): string =>
  pageSizeShift === 0 ? "Infinite" : formatByteSize(1n << BigInt(pageSizeShift));

export {
  codeDirectoryExecSegLabels,
  codeDirectoryFlagLabels,
  codeDirectoryHashLabel,
  codeSignatureBlobLabel,
  codeSignatureSlotLabelFor,
  pageSizeLabel
};
