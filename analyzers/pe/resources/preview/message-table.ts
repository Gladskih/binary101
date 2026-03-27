"use strict";

// Microsoft Learn, MESSAGE_RESOURCE_BLOCK: LowId, HighId, OffsetToEntries are three DWORDs.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-message_resource_block
const MESSAGE_BLOCK_HEADER_SIZE = 12;
// Microsoft Learn, MESSAGE_RESOURCE_ENTRY: Length and Flags are the leading WORD fields.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-message_resource_entry
const MESSAGE_ENTRY_HEADER_SIZE = 4;

const getCodePageEncoding = (codePage: number): string | null => {
  // Microsoft Learn, Code Page Identifiers:
  // 65001 = UTF-8, 20127 = US-ASCII, 932 = Shift-JIS, and 1250..1258 = Windows-1250..1258.
  // https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
  if (codePage === 65001) return "utf-8";
  if (codePage === 20127) return "us-ascii";
  if (codePage === 932) return "shift_jis";
  if (codePage >= 1250 && codePage <= 1258) {
    return `windows-${codePage}`;
  }
  return null;
};

const decodeAsciiBestEffort = (bytes: Uint8Array): string => Array.from(bytes, byte => {
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d) {
      return String.fromCharCode(byte);
    }
    return "\ufffd";
  })
  .join("");

const decodeMessageEntryText = (
  entryBytes: Uint8Array,
  isUnicode: boolean,
  codePage: number
): { text: string; issue?: string } => {
  if (!entryBytes.length) return { text: "" };
  if (isUnicode) {
    let text = "";
    for (let index = 0; index + 1 < entryBytes.length; index += 2) {
      const first = entryBytes[index];
      const second = entryBytes[index + 1];
      if (first === undefined || second === undefined) break;
      const code = first | (second << 8);
      if (code === 0) break;
      text += String.fromCharCode(code);
    }
    return { text };
  }
  const zeroIndex = entryBytes.indexOf(0);
  const slice = zeroIndex === -1 ? entryBytes : entryBytes.slice(0, zeroIndex);
  const encoding = getCodePageEncoding(codePage);
  if (!encoding) {
    return {
      text: decodeAsciiBestEffort(slice),
      issue: codePage
        ? `ANSI message entry uses unsupported code page ${codePage}; `
          + "preview fell back to ASCII-only decoding."
        : "ANSI message entry does not declare a supported code page; "
          + "preview fell back to ASCII-only decoding."
    };
  }
  try {
    return { text: new TextDecoder(encoding, { fatal: false }).decode(slice) };
  } catch {
    return {
      text: decodeAsciiBestEffort(slice),
      issue: `ANSI message entry could not be decoded as ${encoding}; `
        + "preview fell back to ASCII-only decoding."
    };
  }
};

export type MessageTablePreview = {
  messages: Array<{ id: number; strings: string[] }>;
  truncated: boolean;
  issues: string[];
};

export const decodeMessageTablePreview = (
  data: Uint8Array,
  codePage: number
): MessageTablePreview | null => {
  if (data.byteLength < 4) return null;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const blockCount = dv.getUint32(0, true);
  const maxBlocks = Math.min(
    blockCount,
    Math.floor((data.byteLength - 4) / MESSAGE_BLOCK_HEADER_SIZE)
  );
  const messages: Array<{ id: number; strings: string[] }> = [];
  const issues: string[] = [];
  const addIssue = (message: string): void => {
    if (!issues.includes(message)) issues.push(message);
  };
  let truncated = maxBlocks < blockCount;
  for (let blockIndex = 0; blockIndex < maxBlocks; blockIndex += 1) {
    const blockOff = 4 + blockIndex * MESSAGE_BLOCK_HEADER_SIZE;
    if (blockOff + MESSAGE_BLOCK_HEADER_SIZE > data.byteLength) {
      truncated = true;
      break;
    }
    const lowId = dv.getUint32(blockOff, true);
    const highId = dv.getUint32(blockOff + 4, true);
    const entryOffset = dv.getUint32(blockOff + 8, true);
    if (highId < lowId || entryOffset >= data.byteLength) {
      truncated = true;
      continue;
    }
    const blockEnd = blockIndex + 1 < maxBlocks
      ? Math.min(
          data.byteLength,
          dv.getUint32(4 + (blockIndex + 1) * MESSAGE_BLOCK_HEADER_SIZE + 8, true)
        )
      : data.byteLength;
    const entryCount = highId - lowId + 1;
    let pos = entryOffset;
    for (let entryIndex = 0; entryIndex < entryCount; entryIndex += 1) {
      if (pos + MESSAGE_ENTRY_HEADER_SIZE > blockEnd) {
        truncated = true;
        break;
      }
      const length = dv.getUint16(pos, true);
      const flags = dv.getUint16(pos + 2, true);
      if (length < MESSAGE_ENTRY_HEADER_SIZE || pos + length > blockEnd) {
        truncated = true;
        break;
      }
      const entryBytes = data.subarray(pos + MESSAGE_ENTRY_HEADER_SIZE, pos + length);
      // Microsoft Learn, MESSAGE_RESOURCE_ENTRY: Flags == 0x0001 means the text is Unicode.
      // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-message_resource_entry
      const decoded = decodeMessageEntryText(
        entryBytes,
        (flags & 0x0001) !== 0,
        codePage
      );
      messages.push({ id: lowId + entryIndex, strings: [decoded.text] });
      if (decoded.issue) addIssue(decoded.issue);
      pos += length;
    }
  }
  return { messages, truncated, issues };
};
