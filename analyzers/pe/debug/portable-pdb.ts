import type { FileRangeReader } from "../../file-range-reader.js";
import { parseClrMetadataRootStreams } from "../clr/metadata-root.js";
import { ClrHeapReaders, readCompressedUInt } from "../clr/metadata-heaps.js";
import { decodeMetadataUtf8 } from "../clr/metadata-utf8.js";
import { parseMetadataTableStream, type ClrMetadataRow,
  type ClrParsedTableStream } from "../clr/metadata-table-reader.js";
import type { PeClrStreamInfo } from "../clr/types.js";
import { summarizeSequencePoints } from "./portable-pdb-points.js";
import type { PortablePdbDocument, PortablePdbInfo, PortablePdbLocal } from "./portable-pdb-types.js";
import { validatePortablePdbRows } from "./portable-pdb-validation.js";

const readStream = async (
  reader: FileRangeReader, streams: PeClrStreamInfo[], name: string, issues: string[]
): Promise<Uint8Array | null> => {
  const stream = streams.find(item => item.name === name);
  if (!stream) return null;
  if (stream.offset > reader.size || stream.size > reader.size - stream.offset) {
    issues.push(`Portable PDB ${name} stream extends outside the metadata image.`);
    return null;
  }
  return reader.readBytes(stream.offset, stream.size);
};

const readPdbHeader = (bytes: Uint8Array, issues: string[]) => {
  // #Pdb: 20-byte identity, entry point token, 64-bit referenced-table mask, row counts.
  // https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md
  if (bytes.length < 32) {
    issues.push("Portable PDB #Pdb header is truncated.");
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const mask = view.getBigUint64(24, true);
  const referencedRows = new Map<number, number>();
  let offset = 32;
  for (let table = 0; table < 64; table++) {
    if (!(mask & (1n << BigInt(table)))) continue;
    if (offset + 4 > bytes.length) {
      issues.push("Portable PDB referenced type-system row counts are truncated.");
      return null;
    }
    if (table > 0x2c) issues.push("Portable PDB references an invalid type-system table.");
    referencedRows.set(table, view.getUint32(offset, true));
    offset += 4;
  }
  const guid = new ClrHeapReaders({
    guid: bytes.subarray(0, 16), strings: null, blob: null, userString: null
  }, issues).getGuid(1, "Portable PDB ID");
  return { id: { guid, stamp: view.getUint32(16, true) },
    entryPoint: view.getUint32(20, true), referencedRows };
};

const scalar = (row: ClrMetadataRow, name: string): number => {
  const cell = row[name];
  return typeof cell === "number" ? cell : cell?.row ?? 0;
};

const tableRows = (parsed: ClrParsedTableStream, id: number): ClrMetadataRow[] =>
  parsed.tables.get(id)?.rows ?? [];

const documentSeparator = (bytes: Uint8Array, issues: string[]) => {
  const width = bytes[0]! < 0x80 ? 1 : bytes[0]! < 0xe0 ? 2 : bytes[0]! < 0xf0 ? 3 : 4;
  return { width, text: bytes[0] === 0 ? "" : decodeMetadataUtf8(
    bytes.subarray(0, width), issues, "Portable PDB Document separator") };
};

const documentName = (bytes: Uint8Array | null, heaps: ClrHeapReaders): string | null => {
  if (!bytes?.length) {
    heaps.issues.push("Portable PDB Document name is empty or unreadable.");
    return null;
  }
  // Separator is a UTF-8 character, not necessarily one byte (Document Name Blob).
  const separator = documentSeparator(bytes, heaps.issues);
  if (separator.text == null) return null;
  const parts: string[] = [];
  for (let offset = separator.width; offset < bytes.length;) {
    const index = readCompressedUInt(bytes, offset);
    if (!index) {
      heaps.issues.push("Portable PDB Document name has a malformed blob index.");
      return null;
    }
    const part = heaps.getBlob(index.value, "Portable PDB Document name part");
    if (!part) return null;
    const text = decodeMetadataUtf8(part, heaps.issues, "Portable PDB Document name");
    if (text == null) return null;
    parts.push(text);
    offset += index.size;
  }
  return parts.join(separator.text);
};

const readDocument = (row: ClrMetadataRow, heaps: ClrHeapReaders): PortablePdbDocument => ({
  name: documentName(heaps.getBlob(scalar(row, "Name"), "Document.Name"), heaps),
  language: heaps.getGuid(scalar(row, "Language"), "Document.Language"),
  hashAlgorithm: heaps.getGuid(scalar(row, "HashAlgorithm"), "Document.HashAlgorithm"),
  hashSize: heaps.getBlobSize(scalar(row, "Hash"), "Document.Hash")
});

const readLocals = (parsed: ClrParsedTableStream, heaps: ClrHeapReaders): PortablePdbLocal[] => [
  // Portable PDB LocalVariable (0x33) and LocalConstant (0x34) table layouts.
  ...tableRows(parsed, 0x33).map((row): PortablePdbLocal => ({
    kind: "variable", name: heaps.getString(scalar(row, "Name"), "LocalVariable.Name"),
    slot: scalar(row, "Index"), attributes: scalar(row, "Attributes")
  })),
  ...tableRows(parsed, 0x34).map((row): PortablePdbLocal => ({
    kind: "constant", name: heaps.getString(scalar(row, "Name"), "LocalConstant.Name"),
    signatureSize: heaps.getBlobSize(scalar(row, "Signature"), "LocalConstant.Signature")
  }))
];

const summarizeMethods = (rows: ClrMetadataRow[], heaps: ClrHeapReaders, documents: number) => {
  const result = { methodsWithSequencePoints: 0, sequencePoints: { visible: 0, hidden: 0 } };
  const decodedPoints = new Map<string, ReturnType<typeof summarizeSequencePoints>>();
  for (const row of rows) {
    const index = scalar(row, "SequencePoints");
    if (index === 0) continue;
    const bytes = heaps.getBlob(index, "MethodDebugInformation.SequencePoints");
    if (!bytes) continue;
    result.methodsWithSequencePoints++;
    const document = scalar(row, "Document");
    const key = `${index}:${document}`;
    let points = decodedPoints.get(key);
    if (!points) {
      points = summarizeSequencePoints(bytes, document, documents, heaps.issues);
      decodedPoints.set(key, points);
    }
    result.sequencePoints.visible += points.visible;
    result.sequencePoints.hidden += points.hidden;
  }
  return result;
};

export const parsePortablePdb = async (
  reader: FileRangeReader, issues: string[]
): Promise<PortablePdbInfo | null> => {
  const meta = await parseClrMetadataRootStreams(reader, 0, reader.size, issues);
  if (!meta || meta.signature !== 0x424a5342) return null; // ECMA-335 metadata signature "BSJB".
  const pdb = await readStream(reader, meta.streams, "#Pdb", issues);
  const tables = await readStream(reader, meta.streams, "#~", issues);
  if (!pdb || !tables) {
    issues.push("Portable PDB requires both #Pdb and #~ streams.");
    return null;
  }
  const header = readPdbHeader(pdb, issues);
  if (!header) return null;
  const parsed = parseMetadataTableStream(tables, "#~", issues, header.referencedRows);
  if (!parsed) return null;
  if (parsed.rowCounts.some(table => table.tableId < 0x30 || table.tableId > 0x37)) {
    issues.push("Standalone Portable PDB contains unsupported non-debug metadata tables.");
  }
  const heaps = new ClrHeapReaders({
    strings: await readStream(reader, meta.streams, "#Strings", issues),
    guid: await readStream(reader, meta.streams, "#GUID", issues),
    blob: await readStream(reader, meta.streams, "#Blob", issues), userString: null
  }, issues);
  validatePortablePdbRows(parsed, heaps, header.referencedRows);
  const documents = tableRows(parsed, 0x30).map(row => readDocument(row, heaps));
  return {
    id: header.id, entryPoint: header.entryPoint,
    tables: parsed.rowCounts.map(table => ({ name: table.name, declaredRows: table.rows,
      parsedRows: parsed.tables.get(table.tableId)?.rows.length ?? 0 })),
    documents, locals: readLocals(parsed, heaps),
    ...summarizeMethods(tableRows(parsed, 0x31), heaps, documents.length),
    customRecords: tableRows(parsed, 0x37).map(row => ({
      kind: heaps.getGuid(scalar(row, "Kind"), "CustomDebugInformation.Kind"),
      size: heaps.getBlobSize(scalar(row, "Value"), "CustomDebugInformation.Value")
    }))
  };
};
