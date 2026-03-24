"use strict";

export type DerClass = "universal" | "application" | "context" | "private";

export const TAG_SEQUENCE = 0x10;
export const TAG_SET = 0x11;
export const TAG_OID = 0x06;
export const TAG_INTEGER = 0x02;
export const TAG_OCTET_STRING = 0x04;
export const TAG_UTF8_STRING = 0x0c;
export const TAG_PRINTABLE_STRING = 0x13;
export const TAG_T61_STRING = 0x14;
export const TAG_IA5_STRING = 0x16;
export const TAG_UTC_TIME = 0x17;
export const TAG_GENERALIZED_TIME = 0x18;
export const TAG_BMP_STRING = 0x1e;

const CLASS_NAMES: DerClass[] = ["universal", "application", "context", "private"];
const utf8Decoder = new TextDecoder("utf-8");

export interface DerElement {
  tag: number;
  cls: DerClass;
  constructed: boolean;
  length: number;
  header: number;
  start: number;
  end: number;
}

export const readDerElement = (bytes: Uint8Array, offset: number): DerElement | null => {
  if (offset >= bytes.length) return null;
  const first = bytes.at(offset);
  if (first === undefined) return null;
  const cls = CLASS_NAMES[(first & 0xc0) >> 6];
  const constructed = (first & 0x20) !== 0;
  const tag = first & 0x1f;
  if (tag === 0x1f || cls === undefined) return null;
  const lenByte = bytes.at(offset + 1);
  if (lenByte === undefined) return null;
  let length = 0;
  let header = 2;
  if (lenByte < 0x80) {
    length = lenByte;
  } else {
    const lenCount = lenByte & 0x7f;
    // DER definite lengths can use four octets here so 32-bit-sized payloads remain representable.
    if (lenCount === 0 || lenCount > 4 || offset + 2 + lenCount > bytes.length) return null;
    for (let index = 0; index < lenCount; index++) {
      const lenVal = bytes.at(offset + 2 + index);
      if (lenVal === undefined) return null;
      length = length * 256 + lenVal;
    }
    header += lenCount;
  }
  if (offset + header + length > bytes.length) return null;
  return { tag, cls, constructed, length, header, start: offset, end: offset + header + length };
};

const readBase128Value = (
  bytes: Uint8Array,
  offset: number
): { value: number; length: number } | null => {
  let value = 0;
  for (let index = offset; index < bytes.length; index += 1) {
    const byte = bytes.at(index);
    if (byte === undefined) return null;
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) return { value, length: index - offset + 1 };
  }
  return null;
};

export const readDerChildren = (bytes: Uint8Array, element: DerElement): DerElement[] => {
  const children: DerElement[] = [];
  let pos = element.start + element.header;
  while (pos < element.end) {
    const child = readDerElement(bytes, pos);
    if (!child || child.end > element.end || child.end <= pos) break;
    children.push(child);
    pos = child.end;
  }
  return children;
};

export const decodeOid = (bytes: Uint8Array, offset: number, length: number): string | null => {
  if (length <= 0 || offset + length > bytes.length) return null;
  const view = bytes.subarray(offset, offset + length);
  const first = readBase128Value(view, 0);
  if (!first) return null;
  const firstArc = first.value < 40 ? 0 : first.value < 80 ? 1 : 2;
  const secondArc = first.value < 40
    ? first.value
    : first.value < 80
      ? first.value - 40
      : first.value - 80;
  const parts = [firstArc, secondArc];
  for (let index = first.length; index < view.length;) {
    const arc = readBase128Value(view, index);
    if (!arc) return null;
    parts.push(arc.value);
    index += arc.length;
  }
  return parts.join(".");
};

export const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");

const decodeBmpString = (bytes: Uint8Array): string => {
  const chars: number[] = [];
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    chars.push((bytes[i]! << 8) | bytes[i + 1]!);
  }
  return String.fromCharCode(...chars);
};

export const decodeDerString = (bytes: Uint8Array, element: DerElement): string | undefined => {
  const raw = bytes.subarray(element.start + element.header, element.end);
  if (!raw.length) return undefined;
  const text =
    element.tag === TAG_UTF8_STRING
      ? utf8Decoder.decode(raw)
      : element.tag === TAG_PRINTABLE_STRING ||
          element.tag === TAG_IA5_STRING ||
          element.tag === TAG_T61_STRING
        ? String.fromCharCode(...raw)
        : element.tag === TAG_BMP_STRING
          ? decodeBmpString(raw)
          : utf8Decoder.decode(raw);
  return text.replace(/\0/g, "").trim() || undefined;
};

export const parseDerTime = (bytes: Uint8Array, element: DerElement): string | undefined => {
  const rawText = utf8Decoder.decode(
    bytes.subarray(element.start + element.header, element.end)
  ).trim();
  if (!rawText) return undefined;
  if (element.tag === TAG_UTC_TIME) {
    const match = rawText.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (match) {
      const yearPart = Number(match[1]);
      const year = yearPart < 50 ? 2000 + yearPart : 1900 + yearPart;
      const month = match[2];
      const day = match[3];
      const hour = match[4];
      const minute = match[5];
      const second = match[6];
      return `${year}-${month}-${day}T${hour}:${minute}:${second}Z`;
    }
  }
  if (element.tag === TAG_GENERALIZED_TIME) {
    const match = rawText.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (match) {
      const year = match[1];
      const month = match[2];
      const day = match[3];
      const hour = match[4];
      const minute = match[5];
      const second = match[6];
      return `${year}-${month}-${day}T${hour}:${minute}:${second}Z`;
    }
  }
  return rawText;
};

export const parseAlgorithmIdentifier = (
  bytes: Uint8Array,
  element: DerElement | null | undefined,
  warnings: string[],
  describeOid?: (oid: string) => string | undefined
): { oid?: string; name?: string } => {
  if (!element || element.tag !== TAG_SEQUENCE) return {};
  const oidEl = readDerElement(bytes, element.start + element.header);
  if (!oidEl || oidEl.tag !== TAG_OID) {
    warnings.push("AlgorithmIdentifier missing OID.");
    return {};
  }
  const oid = decodeOid(bytes, oidEl.start + oidEl.header, oidEl.length);
  if (!oid) return {};
  const mapped = describeOid?.(oid);
  if (mapped && mapped !== oid) return { oid, name: mapped };
  return { oid };
};
