import { MockFile } from "../helpers/mock-file.js";
import { resourceRcc } from "./embedded-rcc.js";
import { resourceGResource } from "./embedded-gresource.js";
import { resourceElf } from "./embedded-elf.js";
import { resourcePe } from "./embedded-pe.js";

// Ordinary tests build their inputs locally in memory, without compiler tools or files.
export const embeddedResourceFixture = (name: string): Uint8Array => {
  if (name === "oracle.gresource") return resourceGResource();
  if (name === "qt-arrays.o") return resourceElf(1);
  if (name === "qt-glib.so") return resourceElf(3);
  if (name === "qt-glib.dll") return resourcePe();
  const version = /^oracle-v([123])\.rcc$/.exec(name)?.[1];
  if (version) return resourceRcc(Number(version));
  throw new Error(`Unknown resource fixture: ${name}`);
};

export const overwriteResource = (bytes: Uint8Array, offset: number, value: number,
  encoding: "u8" | "be16" | "be32" | "le16" | "le32" = "le32"): Uint8Array => {
  const copy = new Uint8Array(bytes);
  const view = new DataView(copy.buffer);
  if (encoding === "u8") view.setUint8(offset, value);
  else if (encoding.endsWith("16")) view.setUint16(offset, value, encoding === "le16");
  else view.setUint32(offset, value, encoding === "le32");
  return copy;
};

export const minimalRcc = (version = 1, content = new TextEncoder().encode("hello")) => {
  const nodeSize = version === 1 ? 14 : 22;
  const tree = version === 3 ? 24 : 20;
  const names = tree + nodeSize * 2;
  const data = names + 8;
  const bytes = new Uint8Array(data + 4 + content.length);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("qres"));
  view.setUint32(4, version);
  view.setUint32(8, tree);
  view.setUint32(12, data);
  view.setUint32(16, names);
  view.setUint16(tree + 4, 2); // RCC Directory; Qt rcc.cpp::writeDataInfo.
  view.setUint32(tree + 6, 1);
  view.setUint32(tree + 10, 1);
  view.setUint16(names, 1);
  view.setUint32(names + 2, 97); // qt_hash("a") == its single UTF-16 code unit.
  view.setUint16(names + 6, 97);
  view.setUint32(data, content.length);
  bytes.set(content, data + 4);
  return { bytes, tree, names, data, nodeSize };
};

// GNOME gvdb-format.h and gresource.c: one bucket, one bloom word and two items.
export const minimalGResource = () => {
  const bytes = new Uint8Array(132);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("GVariant"));
  view.setUint32(16, 24, true);
  view.setUint32(20, 88, true);
  view.setUint32(24, 0x28000001, true); // Bloom shift 5, one bloom word.
  view.setUint32(28, 1, true);
  view.setUint32(32, 0xffffffff, true);
  // Hashes: djb_hash("/") and djb_hash("/a"), signed-byte arithmetic.
  view.setUint32(40, 177620, true);
  view.setUint32(44, 0xffffffff, true);
  view.setUint32(48, 88, true);
  view.setUint16(52, 1, true);
  bytes[54] = 76;
  view.setUint32(56, 92, true);
  view.setUint32(60, 96, true);
  view.setUint32(64, 5861557, true);
  view.setUint32(68, 0, true);
  view.setUint32(72, 89, true);
  view.setUint16(76, 1, true);
  bytes[78] = 118;
  view.setUint32(80, 96, true);
  view.setUint32(84, 118, true);
  bytes.set(new TextEncoder().encode("/a"), 88);
  view.setUint32(92, 1, true);
  view.setUint32(96, 6, true);
  bytes.set(new TextEncoder().encode("hello!\0\0(uuay)"), 104);
  return bytes;
};

export const gResourceBeforeTable = (): Uint8Array => {
  const original = minimalGResource();
  const bytes = new Uint8Array(192);
  bytes.set(original.subarray(0, 24));
  bytes.set(original.subarray(24, 88), 128);
  bytes.set(original.subarray(88, 90), 24);
  bytes.set(original.subarray(92, 96), 28);
  bytes.set(original.subarray(96, 118), 32);
  const view = new DataView(bytes.buffer);
  view.setUint32(16, 128, true);
  view.setUint32(20, 192, true);
  view.setUint32(152, 24, true);
  view.setUint32(160, 28, true);
  view.setUint32(164, 32, true);
  view.setUint32(176, 25, true);
  view.setUint32(184, 32, true);
  view.setUint32(188, 54, true);
  return bytes;
};

export const embeddedFile = (bytes: Uint8Array): MockFile => new MockFile(bytes);
