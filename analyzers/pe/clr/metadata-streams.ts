"use strict";

import type { PeClrMeta, PeClrMetadataTables, PeClrStreamInfo } from "./types.js";
import { ClrHeapReaders, type ClrMetadataHeapData } from "./metadata-heaps.js";
import { buildClrMetadataTables } from "./metadata-model.js";
import { parseMetadataTableStream } from "./metadata-table-reader.js";

export interface ClrMetadataRelativeReader {
  availableSize: number;
  readAt: (relativeOffset: number, byteLength: number) => Promise<DataView | null>;
}

const findStream = (streams: PeClrStreamInfo[], name: string): PeClrStreamInfo | null =>
  streams.find(stream => stream.name === name) || null;

const readStreamBytes = async (
  reader: ClrMetadataRelativeReader,
  stream: PeClrStreamInfo | null,
  declaredMetaSize: number,
  issues: string[]
): Promise<Uint8Array | null> => {
  if (!stream) return null;
  if (stream.offset < 0 || stream.offset >= declaredMetaSize) {
    issues.push(`Metadata stream "${stream.name}" starts outside the declared metadata region.`);
    return null;
  }
  const availableSize = Math.max(
    0,
    Math.min(stream.size, declaredMetaSize - stream.offset, reader.availableSize - stream.offset)
  );
  if (availableSize < stream.size) {
    issues.push(`Metadata stream "${stream.name}" is truncated; parsing the available prefix.`);
  }
  const view = await reader.readAt(stream.offset, availableSize);
  if (!view || view.byteLength < availableSize) {
    issues.push(`Metadata stream "${stream.name}" could not be read.`);
    return null;
  }
  return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
};

const readHeaps = async (
  reader: ClrMetadataRelativeReader,
  meta: PeClrMeta,
  declaredMetaSize: number,
  issues: string[]
): Promise<ClrMetadataHeapData> => ({
  strings: await readStreamBytes(reader, findStream(meta.streams, "#Strings"), declaredMetaSize, issues),
  guid: await readStreamBytes(reader, findStream(meta.streams, "#GUID"), declaredMetaSize, issues),
  blob: await readStreamBytes(reader, findStream(meta.streams, "#Blob"), declaredMetaSize, issues),
  userString: await readStreamBytes(reader, findStream(meta.streams, "#US"), declaredMetaSize, issues)
});

export const parseClrMetadataTablesFromStreams = async (
  reader: ClrMetadataRelativeReader,
  meta: PeClrMeta,
  declaredMetaSize: number,
  issues: string[]
): Promise<PeClrMetadataTables | null> => {
  const tableStream = findStream(meta.streams, "#~") || findStream(meta.streams, "#-");
  if (!tableStream) return null;
  const tableBytes = await readStreamBytes(reader, tableStream, declaredMetaSize, issues);
  if (!tableBytes) return null;
  const parsedTableStream = parseMetadataTableStream(
    tableBytes,
    tableStream.name === "#-" ? "#-" : "#~",
    issues
  );
  if (!parsedTableStream) return null;
  return buildClrMetadataTables(
    parsedTableStream,
    new ClrHeapReaders(await readHeaps(reader, meta, declaredMetaSize, issues), issues)
  );
};
