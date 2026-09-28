"use strict";

import type { ResourceXmlTreeAttribute, ResourceXmlTreeNode } from "./types.js";

// MS-EVEN6 §2.2.12 defines the tokens and NameHash; WEVT stores names inline.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/c73573ae-1c90-43a2-a65f-ad7501155956
// https://github.com/omerbenamram/evtx/blob/master/src/binxml/name.rs
interface Cursor { bytes: Uint8Array; view: DataView; pos: number; end: number; issues: string[] }

const take = (cursor: Cursor, size: number): number | null => {
  if (size > cursor.end - cursor.pos) {
    cursor.issues.push("WEVT BinXML is truncated.");
    return null;
  }
  const start = cursor.pos;
  cursor.pos += size;
  return start;
};

const byte = (cursor: Cursor): number | null => {
  const offset = take(cursor, 1);
  return offset === null ? null : cursor.view.getUint8(offset);
};

const word = (cursor: Cursor): number | null => {
  const offset = take(cursor, 2);
  return offset === null ? null : cursor.view.getUint16(offset, true);
};

const dword = (cursor: Cursor): number | null => {
  const offset = take(cursor, 4);
  return offset === null ? null : cursor.view.getUint32(offset, true);
};

const unicode = (cursor: Cursor): string | null => {
  const count = word(cursor);
  if (count === null) return null;
  const offset = take(cursor, count * 2);
  return offset === null ? null : new TextDecoder("utf-16le")
    .decode(cursor.bytes.subarray(offset, cursor.pos));
};

const name = (cursor: Cursor): string | null => {
  const storedHash = word(cursor);
  const count = word(cursor);
  if (count === null) return null;
  const offset = take(cursor, count * 2 + 2);
  if (offset === null) return null;
  let hash = 0;
  for (let index = 0; index < count; index += 1) {
    hash = (Math.imul(hash, 65599) + cursor.view.getUint16(offset + index * 2, true)) & 0xffff;
  }
  if (cursor.view.getUint16(offset + count * 2, true) !== 0 || hash !== storedHash) {
    cursor.issues.push("WEVT BinXML inline name has an invalid NUL or hash.");
    return null;
  }
  return new TextDecoder("utf-16le").decode(cursor.bytes.subarray(offset, offset + count * 2));
};

const value = (cursor: Cursor): string | null => {
  const token = byte(cursor);
  if (token === null) return null;
  if (token === 0x0d || token === 0x0e) {
    const index = word(cursor);
    const type = byte(cursor);
    return index === null || type === null ? null : `{sub:${index}}`;
  }
  if (token === 0x05 || token === 0x45) {
    const type = byte(cursor);
    if (type !== 1) {
      cursor.issues.push("WEVT BinXML text value type is unsupported.");
      return null;
    }
    return unicode(cursor);
  }
  if (token === 0x07 || token === 0x47) return unicode(cursor);
  if (token === 0x08 || token === 0x48) {
    const code = word(cursor);
    return code === null ? null : String.fromCharCode(code);
  }
  if (token === 0x09 || token === 0x49) {
    const entity = name(cursor);
    return entity === null ? null : `&${entity};`;
  }
  cursor.issues.push(`WEVT BinXML token 0x${token.toString(16)} is unsupported.`);
  return null;
};

const attributes = (cursor: Cursor): ResourceXmlTreeAttribute[] | null => {
  const size = dword(cursor);
  if (size === null) return null;
  const end = cursor.pos + size;
  if (end > cursor.end) {
    cursor.issues.push("WEVT BinXML attribute list is truncated.");
    return null;
  }
  const result: ResourceXmlTreeAttribute[] = [];
  while (cursor.pos < end) {
    const token = byte(cursor);
    if (token !== 0x06 && token !== 0x46) {
      cursor.issues.push("WEVT BinXML attribute token is invalid.");
      return null;
    }
    const attributeName = name(cursor);
    if (attributeName === null) return null;
    const parts: string[] = [];
    while (cursor.pos < end && cursor.bytes[cursor.pos] !== 0x06 &&
      cursor.bytes[cursor.pos] !== 0x46) {
      const part = value(cursor);
      if (part === null) return null;
      parts.push(part);
    }
    result.push({ name: attributeName, value: parts.join("") });
  }
  return result;
};

const element = (cursor: Cursor, depth: number): ResourceXmlTreeNode | null => {
  if (depth > 32) {
    cursor.issues.push("WEVT BinXML nesting is too deep.");
    return null;
  }
  const token = byte(cursor);
  if (token !== 0x01 && token !== 0x41) {
    cursor.issues.push("WEVT BinXML element token is invalid.");
    return null;
  }
  word(cursor); // Template dependency ID does not change the XML tree.
  const size = dword(cursor);
  if (size === null) return null;
  const end = cursor.pos + size;
  if (end > cursor.end) {
    cursor.issues.push("WEVT BinXML element is truncated.");
    return null;
  }
  const tagName = name(cursor);
  if (tagName === null) return null;
  const attrs = token === 0x41 ? attributes(cursor) : [];
  if (attrs === null) return null;
  const close = byte(cursor);
  if (close !== 0x02 && close !== 0x03) {
    cursor.issues.push("WEVT BinXML start tag is not closed.");
    return null;
  }
  const children: ResourceXmlTreeNode[] = [];
  const text: string[] = [];
  while (close === 0x02 && cursor.pos < end && cursor.bytes[cursor.pos] !== 0x04) {
    const next = cursor.bytes[cursor.pos];
    if (next === 0x01 || next === 0x41) {
      const child = element(cursor, depth + 1);
      if (!child) return null;
      children.push(child);
    } else {
      const part = value(cursor);
      if (part === null) return null;
      text.push(part);
    }
  }
  if (close === 0x02 && byte(cursor) !== 0x04 || cursor.pos !== end) {
    cursor.issues.push("WEVT BinXML element end is invalid.");
    return null;
  }
  return { name: tagName, attributes: attrs, text: text.length ? text.join("") : null,
    children };
};

export const parseWevtBinXml = (
  bytes: Uint8Array, offset: number, end: number, issues: string[]
): ResourceXmlTreeNode | null => {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(end) ||
    end > bytes.length || end - offset < 4) {
    issues.push("WEVT BinXML range is invalid or truncated.");
    return null;
  }
  const cursor: Cursor = { bytes, view: new DataView(bytes.buffer, bytes.byteOffset, bytes.length),
    pos: offset, end, issues };
  if (byte(cursor) !== 0x0f || byte(cursor) !== 1 || byte(cursor) !== 1 || byte(cursor) !== 0) {
    issues.push("WEVT BinXML fragment header is invalid.");
    return null;
  }
  return element(cursor, 0);
};
