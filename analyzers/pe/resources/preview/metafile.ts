import type { ResourcePreviewResult } from "./types.js";
import type { ResourceVector } from "./vector-types.js";
import { createMetafileDrawing } from "./metafile-drawing.js";
import type { MetafileDrawing } from "./metafile-drawing.js";
import { renderEmfRecord } from "./emf-records.js";
import { renderWmfRecord } from "./wmf-records.js";

// ENHMETAHEADER, METAHEADER and placeable WMF: DWORD bytes / WORD counts.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-emf/
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/
interface MetafileHeader {
  format: "EMF" | "WMF";
  start: number;
  end: number;
  count: number | null;
  bounds: ResourceVector["bounds"];
}

const emfHeader = (view: DataView, issues: string[]): MetafileHeader | null => {
  if (view.byteLength < 88) { issues.push("EMF header is truncated."); return null; }
  const size = view.getUint32(4, true);
  if (size < 88 || size > view.byteLength) { issues.push("EMF header size is invalid."); return null; }
  return { format: "EMF", start: 0, end: view.getUint32(48, true), count: view.getUint32(52, true),
    bounds: { x: view.getInt32(8, true), y: view.getInt32(12, true),
      width: view.getInt32(16, true) - view.getInt32(8, true),
      height: view.getInt32(20, true) - view.getInt32(12, true) } };
};

const placeableBounds = (view: DataView, issues: string[]): ResourceVector["bounds"] => {
  let checksum = 0;
  for (let at = 0; at < 20; at += 2) checksum ^= view.getUint16(at, true);
  if (checksum !== view.getUint16(20, true)) issues.push("Placeable WMF checksum is invalid.");
  if (!view.getUint16(14, true)) issues.push("Placeable WMF units per inch is zero.");
  return { x: view.getInt16(6, true), y: view.getInt16(8, true),
    width: view.getInt16(10, true) - view.getInt16(6, true),
    height: view.getInt16(12, true) - view.getInt16(8, true) };
};

const wmfHeader = (view: DataView, issues: string[]): MetafileHeader | null => {
  const placeable = view.byteLength >= 4 && view.getUint32(0, true) === 0x9ac6cdd7;
  const start = placeable ? 22 : 0;
  if (view.byteLength < start + 18) {
    if (placeable) issues.push("Placeable WMF header is truncated.");
    return null;
  }
  if (![1, 2].includes(view.getUint16(start, true)) || view.getUint16(start + 2, true) !== 9) return null;
  if (![0x100, 0x300].includes(view.getUint16(start + 4, true))) {
    issues.push("WMF version is unsupported."); return null;
  }
  return { format: "WMF", start: start + 18, end: start + view.getUint32(start + 6, true) * 2,
    count: null, bounds: placeable ? placeableBounds(view, issues) : { x: 0, y: 0, width: 300, height: 300 } };
};

const metafileHeader = (view: DataView, issues: string[]): MetafileHeader | null =>
  view.byteLength >= 44 && view.getUint32(0, true) === 1 && view.getUint32(40, true) === 0x464d4520
    ? emfHeader(view, issues) : wmfHeader(view, issues);

const recordHeader = (view: DataView, offset: number, header: MetafileHeader,
  issues: string[]): { type: number; size: number; offset: number } | null => {
  const limit = Math.min(view.byteLength, header.end);
  const prefix = header.format === "EMF" ? 8 : 6;
  if (prefix > limit - offset) { issues.push("Metafile record header is truncated."); return null; }
  const size = header.format === "EMF" ? view.getUint32(offset + 4, true) : view.getUint32(offset, true) * 2;
  const type = header.format === "EMF" ? view.getUint32(offset, true) : view.getUint16(offset + 4, true);
  if (size < prefix || size > limit - offset || size % (header.format === "EMF" ? 4 : 2)) {
    issues.push(`Metafile record ${type} at ${offset} has an invalid size.`); return null;
  }
  return { type, size, offset };
};

const readRecords = (view: DataView, header: MetafileHeader, drawing: MetafileDrawing) => {
  const records: NonNullable<ResourceVector["records"]> = [];
  const limit = Math.min(view.byteLength, header.end);
  let offset = header.start;
  let eof = false;
  while (offset < limit) {
    const record = recordHeader(view, offset, header, drawing.issues);
    if (!record) break;
    records.push(record);
    const data = new DataView(view.buffer, view.byteOffset + offset, record.size);
    if (header.format === "EMF") renderEmfRecord(data, drawing);
    else renderWmfRecord(data, drawing);
    offset += record.size;
    if (record.type === (header.format === "EMF" ? 14 : 0)) { eof = true; break; }
  }
  if (!eof) drawing.issues.push("Metafile has no readable EOF record.");
  if (offset < limit && eof) drawing.issues.push("Metafile contains data after EOF.");
  return records;
};

const checkDrawing = (header: MetafileHeader, drawing: MetafileDrawing, count: number): void => {
  if (header.format === "WMF" && header.start === 18) {
    drawing.issues.push("Standard WMF has no placeable bounds; the preview uses an approximate viewport.");
  }
  if (header.count !== null && header.count !== count) drawing.issues.push("EMF record count differs from its header.");
  if (drawing.omitted.size) drawing.issues.push(
    `Metafile drawing is partial; unsupported record types: ${[...drawing.omitted].join(", ")}.`);
  if (header.bounds.width <= 0 || header.bounds.height <= 0) drawing.issues.push("Metafile drawing bounds are invalid.");
};

export const addMetafilePreview = (data: Uint8Array): ResourcePreviewResult | null => {
  const view = new DataView(data.buffer, data.byteOffset, data.length);
  const issues: string[] = [];
  const header = metafileHeader(view, issues);
  if (!header) return issues.length ? { issues } : null;
  if (header.end !== data.length || header.end < header.start) issues.push("Metafile declared size differs from its payload.");
  const drawing = createMetafileDrawing(issues);
  const records = readRecords(view, header, drawing);
  checkDrawing(header, drawing, records.length);
  return { preview: { previewKind: "vector", vector: { format: header.format,
    bounds: header.bounds.width > 0 && header.bounds.height > 0 ? header.bounds :
      { x: 0, y: 0, width: 300, height: 300 }, nodes: drawing.nodes, records } },
  ...(issues.length ? { issues: [...new Set(issues)] } : {}) };
};
