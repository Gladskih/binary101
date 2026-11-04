import type { ResourceImageGroup, ResourcePreviewResult } from "./types.js";

const validateHeader = (view: DataView, type: ResourceImageGroup["type"], issues: string[]): number => {
  const count = view.getUint16(4, true);
  if (view.getUint16(0, true) !== 0 || view.getUint16(2, true) !== (type === "ICON" ? 1 : 2)) {
    issues.push("Image group has an invalid reserved field or resource type.");
  }
  if (!count) issues.push("Image group has no entries.");
  if (count > Math.floor((view.byteLength - 6) / 14)) issues.push("Image group entries are truncated.");
  if (6 + count * 14 < view.byteLength) issues.push("Image group has trailing bytes.");
  return Math.min(count, Math.floor((view.byteLength - 6) / 14));
};

const readEntry = (view: DataView, offset: number, type: ResourceImageGroup["type"]) => ({
  id: view.getUint16(offset + 12, true),
  width: type === "ICON" ? view.getUint8(offset) || 256 : view.getUint16(offset, true),
  height: type === "ICON" ? view.getUint8(offset + 1) || 256 : view.getUint16(offset + 2, true),
  planes: view.getUint16(offset + 4, true), bitCount: view.getUint16(offset + 6, true),
  size: view.getUint32(offset + 8, true)
});

export const addImageGroupPreview = (
  data: Uint8Array, typeName: string
): ResourcePreviewResult | null => {
  if (typeName !== "GROUP_ICON" && typeName !== "GROUP_CURSOR") return null;
  const issues: string[] = [];
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (data.length < 6) return { issues: ["Image group header is truncated."] };
  const type = typeName === "GROUP_ICON" ? "ICON" : "CURSOR";
  // NEWHEADER and RESDIR; cursor dimensions are WORDs rather than ICONRESDIR BYTEs.
  // https://learn.microsoft.com/en-us/windows/win32/menurc/resdir
  const count = validateHeader(view, type, issues);
  const entries: ResourceImageGroup["entries"] = [];
  for (let index = 0; index < count; index += 1) entries.push(readEntry(view, 6 + index * 14, type));
  if (entries.some(entry => !entry.width || !entry.height)) issues.push("Image group dimension is zero.");
  return { preview: { previewKind: "imageGroup", imageGroup: { type, entries } },
    ...(issues.length ? { issues } : {}) };
};
