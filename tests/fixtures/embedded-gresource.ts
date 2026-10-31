import { deflateSync } from "node:zlib";

// GNOME gvdb-format.h, gvdb-builder.c and gio/gresource.c: LE metadata,
// djb_hash, bucket-ordered items, aligned pointers, and raw GVariant (uuay).
// https://gitlab.gnome.org/GNOME/glib/-/blob/main/gio/gresource.c
const keyHash = (path: string): number => {
  let hash = 5381;
  for (const byte of new TextEncoder().encode(path)) hash = (hash * 33 + (byte < 128 ? byte : byte - 256)) >>> 0;
  return hash;
};

const variant = (text: string): Uint8Array => {
  const content = new TextEncoder().encode(text);
  const bytes = new Uint8Array(8 + content.length + 1 + 7);
  new DataView(bytes.buffer).setUint32(0, content.length, true);
  bytes.set(content, 8);
  bytes.set(new TextEncoder().encode("\0(uuay)"), 9 + content.length);
  return bytes;
};

const compressedVariant = (): Uint8Array => {
  const content = new TextEncoder().encode("Binary101 resource oracle ".repeat(50));
  const compressed = deflateSync(content);
  const bytes = new Uint8Array(8 + compressed.length + 7);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, content.length, true);
  view.setUint32(4, 1, true);
  bytes.set(compressed, 8);
  bytes.set(new TextEncoder().encode("\0(uuay)"), 8 + compressed.length);
  return bytes;
};

const children = (...indices: number[]): Uint8Array => {
  const bytes = new Uint8Array(indices.length * 4);
  indices.forEach((index, offset) => new DataView(bytes.buffer).setUint32(offset * 4, index, true));
  return bytes;
};

export const resourceGResource = (): Uint8Array => {
  const items = [
    { key: "org/", parent: 2, path: "/org/", value: children(4), type: 76 },
    { key: "message.txt", parent: 4, path: "/org/binary101/message.txt", value: compressedVariant(), type: 118 },
    { key: "/", parent: 0xffffffff, path: "/", value: children(0), type: 76 },
    { key: "plain.txt", parent: 4, path: "/org/binary101/plain.txt",
      value: variant("Qt and GLib resource oracle."), type: 118 },
    { key: "binary101/", parent: 0, path: "/org/binary101/", value: children(1, 3), type: 76 }
  ];
  const bytes = new Uint8Array(1024);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("GVariant"));
  view.setUint32(16, 24, true);
  view.setUint32(20, 172, true); // 8-byte table header + five buckets + five 24-byte items.
  view.setUint32(24, 5 << 27, true);
  view.setUint32(28, 5, true);
  [0, 4, 4, 5, 5].forEach((value, index) => view.setUint32(32 + index * 4, value, true));
  let cursor = 172;
  items.forEach((item, index) => {
    const record = 52 + index * 24;
    const key = new TextEncoder().encode(item.key);
    view.setUint32(record, keyHash(item.path), true);
    view.setUint32(record + 4, item.parent, true);
    view.setUint32(record + 8, cursor, true);
    view.setUint16(record + 12, key.length, true);
    bytes[record + 14] = item.type;
    bytes.set(key, cursor);
    cursor = Math.ceil((cursor + key.length) / 8) * 8;
    view.setUint32(record + 16, cursor, true);
    bytes.set(item.value, cursor);
    cursor += item.value.length;
    view.setUint32(record + 20, cursor, true);
  });
  return bytes.slice(0, cursor);
};
