"use strict";

import type { PeClrMeta, PeClrStreamInfo } from "./clr-types.js";

export const CLR_METADATA_ROOT_MIN_BYTES = 0x18;

// ECMA-335 II.24.2.2 ("Stream header"): "The name is limited to 32 characters."
const CLR_STREAM_NAME_SPEC_LIMIT = 32;
// ECMA-335 II.24.2.1 ("Metadata root"): signature "BSJB" = 0x424A5342.
const CLR_METADATA_SIGNATURE_BSJB = 0x424a5342;
const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

interface Cursor {
  offset: number;
}

interface MetadataReader {
  readAt: (relativeOffset: number, byteLength: number) => Promise<DataView | null>;
}

const alignTo4 = (value: number): number => (value + 3) & ~3;

const toHex = (value: number, width: number): string =>
  "0x" + value.toString(16).padStart(width, "0");

const decodeUtf8NullTerminated = (bytes: Uint8Array): { text: string; terminated: boolean } => {
  const terminator = bytes.indexOf(0);
  const textBytes = terminator === -1 ? bytes : bytes.subarray(0, terminator);
  return {
    text: utf8Decoder.decode(textBytes),
    terminated: terminator !== -1
  };
};


const readU16At = async (
  reader: MetadataReader,
  cursor: Cursor
): Promise<number | null> => {
  const view = await reader.readAt(cursor.offset, 2);
  if (!view) return null;
  cursor.offset += 2;
  return view.getUint16(0, true);
};

const readU32At = async (
  reader: MetadataReader,
  cursor: Cursor
): Promise<number | null> => {
  const view = await reader.readAt(cursor.offset, 4);
  if (!view) return null;
  cursor.offset += 4;
  return view.getUint32(0, true);
};

const readBytesAt = async (
  reader: MetadataReader,
  cursor: Cursor,
  byteLength: number
): Promise<Uint8Array | null> => {
  const view = await reader.readAt(cursor.offset, byteLength);
  if (!view) return null;
  cursor.offset += byteLength;
  return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
};

const readStreamNameAt = async (
  reader: MetadataReader,
  cursor: Cursor,
  declaredMetaSize: number
): Promise<{ name: string; nullTerminatedWithinLimit: boolean } | null> => {
  if (cursor.offset >= declaredMetaSize) return null;
  const bytes: number[] = [];
  let terminated = false;
  const remainingBytes = declaredMetaSize - cursor.offset;
  for (let index = 0; index < remainingBytes; index += 1) {
    const byteView = await reader.readAt(cursor.offset, 1);
    if (!byteView) return null;
    cursor.offset += 1;
    const byteValue = byteView.getUint8(0);
    if (byteValue === 0) {
      terminated = true;
      break;
    }
    bytes.push(byteValue);
  }
  cursor.offset = alignTo4(cursor.offset);
  return {
    name: utf8Decoder.decode(new Uint8Array(bytes)),
    nullTerminatedWithinLimit: terminated && bytes.length <= CLR_STREAM_NAME_SPEC_LIMIT
  };
};

const parseMetadataRootWithReader = async (
  reader: MetadataReader,
  declaredMetaSize: number,
  issues: string[]
): Promise<PeClrMeta | null> => {
  const cursor: Cursor = { offset: 0 };
  const signature = await readU32At(reader, cursor);
  if (signature == null) {
    issues.push("Metadata root is truncated; missing signature.");
    return null;
  }
  if (signature !== CLR_METADATA_SIGNATURE_BSJB) {
    issues.push(
      `Metadata root signature ${toHex(signature, 8)} is unexpected; expected ` +
        `${toHex(CLR_METADATA_SIGNATURE_BSJB, 8)} ("BSJB").`
    );
    return null;
  }
  const verMajor = await readU16At(reader, cursor);
  const verMinor = await readU16At(reader, cursor);
  const reserved = await readU32At(reader, cursor);
  const versionLength = await readU32At(reader, cursor);
  if (
    verMajor == null ||
    verMinor == null ||
    reserved == null ||
    versionLength == null
  ) {
    issues.push("Metadata root is truncated; missing required header fields.");
    return null;
  }
  if (versionLength > declaredMetaSize - cursor.offset) {
    issues.push("Metadata root version string is truncated or out of bounds.");
    return null;
  }
  let version = "";
  if (versionLength > 0) {
    const versionBytes = await readBytesAt(reader, cursor, versionLength);
    if (!versionBytes) {
      issues.push("Metadata root version string is truncated or out of bounds.");
      return null;
    }
    const decodedVersion = decodeUtf8NullTerminated(versionBytes);
    version = decodedVersion.text;
    if (!decodedVersion.terminated) {
      issues.push("Metadata root version string is not null-terminated within the declared length.");
    }
    cursor.offset = alignTo4(cursor.offset);
  }
  const flags = await readU16At(reader, cursor);
  const streamCountRaw = await readU16At(reader, cursor);
  if (flags == null || streamCountRaw == null) {
    issues.push("Metadata root is truncated; missing stream header fields.");
    return null;
  }
  const streams: PeClrStreamInfo[] = [];
  const seenStreamNames = new Set<string>();
  for (let streamIndex = 0; streamIndex < streamCountRaw; streamIndex += 1) {
    const offset = await readU32At(reader, cursor);
    const size = await readU32At(reader, cursor);
    if (offset == null || size == null) {
      issues.push("Metadata stream headers are truncated; some stream entries are missing.");
      break;
    }
    const name = await readStreamNameAt(reader, cursor, declaredMetaSize);
    if (name == null) {
      issues.push("Metadata stream headers are truncated; some stream names are missing.");
      break;
    }
    if (!name.nullTerminatedWithinLimit) {
      issues.push(
        "Metadata stream names must be null-terminated within the ECMA-335 32-character limit."
      );
    }
    if (name.name.length > CLR_STREAM_NAME_SPEC_LIMIT) {
      issues.push(
        `Metadata stream "${name.name}" exceeds the ECMA-335 32-character stream-name limit.`
      );
    }
    if ((size & 3) !== 0) {
      issues.push(`Metadata stream "${name.name}" size is not a multiple of 4 bytes.`);
    }
    if (declaredMetaSize > 0 && offset + size > declaredMetaSize) {
      issues.push(
        `Metadata stream "${name.name}" extends past declared metadata size ` +
          `(${toHex(offset + size, 8)} > ${toHex(declaredMetaSize, 8)}).`
      );
    }
    if (seenStreamNames.has(name.name)) {
      issues.push(`Metadata stream "${name.name}" is duplicated.`);
    } else {
      seenStreamNames.add(name.name);
    }
    streams.push({ name: name.name, offset, size });
  }
  if (streams.length < streamCountRaw) {
    issues.push("Metadata stream list is incomplete; fewer streams were parsed than declared.");
  }
  return {
    version,
    verMajor,
    verMinor,
    reserved,
    flags,
    streamCount: streamCountRaw,
    signature,
    streams
  };
};

export const parseClrMetadataRoot = async (
  file: File,
  metaOffset: number,
  metaSize: number,
  issues: string[]
): Promise<PeClrMeta | null> => {
  if (metaOffset < 0 || metaOffset >= file.size) {
    issues.push("Metadata root location is outside the file.");
    return null;
  }
  const availableSize = Math.min(metaSize, Math.max(0, file.size - metaOffset));
  if (availableSize < metaSize) {
    issues.push("Metadata directory is truncated; some bytes are missing from the end of the region.");
  }
  if (availableSize < CLR_METADATA_ROOT_MIN_BYTES) {
    issues.push("Metadata root is smaller than the minimum size (0x18 bytes); header is truncated.");
    return null;
  }

  const reader: MetadataReader = {
    readAt: async (relativeOffset, byteLength) => {
      if (relativeOffset < 0 || byteLength < 0) return null;
      if (relativeOffset + byteLength > availableSize) return null;
      const slice = await file
        .slice(metaOffset + relativeOffset, metaOffset + relativeOffset + byteLength)
        .arrayBuffer();
      return new DataView(slice);
    }
  };

  try {
    return await parseMetadataRootWithReader(reader, metaSize, issues);
  } catch {
    issues.push("Metadata root could not be read.");
    return null;
  }
};
