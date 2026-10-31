import type { FileRangeReader } from "../file-range-reader.js";
import type { GResource, GResourceItem, ResourceDecodeResult } from "./types.js";
import { inspectResource, readResource, requireResource, resourceBytes } from "./reader.js";
import { readGvdbChildren, readGvdbTable } from "./gvdb-table.js";
import { validateGvdbHierarchy } from "./gvdb-hierarchy.js";

// The outer GVariant ends in NUL + type signature; (uuay) needs no framing offsets.
// https://gitlab.gnome.org/GNOME/glib/-/blob/main/gio/gresource.c (g_resource_get_info)
// https://gitlab.gnome.org/GNOME/glib/-/blob/main/gio/glib-compile-resources.c
const readValue = async (reader: FileRangeReader, item: GResourceItem): Promise<GResourceItem> => {
  requireResource(item.value.size >= 15, "Truncated GResource GVariant");
  const tail = resourceBytes(await readResource(reader, item.value, item.value.size - 7, 7));
  requireResource(new TextDecoder().decode(tail) === "\0(uuay)", "GVDB value is not a GResource (uuay)");
  const header = await readResource(reader, item.value, 0, 8);
  // GResource deliberately uses get_raw_value (never byteswaps), then GUINT32_FROM_LE.
  const uncompressedSize = header.getUint32(0, true);
  const flags = header.getUint32(4, true);
  requireResource(flags === 0 || flags === 1, "Unsupported GResource flags");
  const arraySize = item.value.size - 15;
  if (flags === 0) {
    requireResource(arraySize === uncompressedSize + 1, "GResource size and byte array disagree");
    requireResource((await readResource(reader, item.value, 8 + uncompressedSize, 1)).getUint8(0) === 0,
      "Uncompressed GResource is missing its NUL terminator");
  }
  return { ...item, flags, payload: { offset: item.value.offset + 8,
    size: flags === 0 ? uncompressedSize : arraySize,
    ...(flags === 0 ? {} : { uncompressedSize }) } };
};

export const decodeGResource = (reader: FileRangeReader, offset: number,
  size: number): Promise<ResourceDecodeResult<GResource>> => inspectResource(async () => {
  const range = { offset, size };
  const header = await readResource(reader, range, 0, 24);
  const signature = new TextDecoder().decode(resourceBytes(header).subarray(0, 8));
  requireResource(signature === "GVariant" || signature === "raVGtnai", "Invalid GVDB signature");
  const version = header.getUint32(8, true);
  const options = header.getUint32(12, true);
  requireResource(version === 0 && options === 0, "Unsupported GVDB version or options");
  const root = { offset: header.getUint32(16, true),
    size: header.getUint32(20, true) - header.getUint32(16, true) };
  const table = await readGvdbTable(reader, range, root);
  const entries: GResourceItem[] = [];
  for (const item of table.entries) {
    entries.push(item.type === "L" ? { ...item, children: await readGvdbChildren(reader, item) } :
      await readValue(reader, item));
  }
  validateGvdbHierarchy(entries, table.buckets, table.bloomWords, table.bloomShift);
  return { format: "GLib GResource", version, options, byteSwapped: signature === "raVGtnai",
    root: { ...root, offset: offset + root.offset }, bloomShift: table.bloomShift,
    bloomWords: table.bloomWords, buckets: table.buckets, entries };
});
