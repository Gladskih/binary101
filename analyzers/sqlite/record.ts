"use strict";

import type { SqliteRecord, SqliteRecordValue } from "./types.js";

type Varint = { value: bigint; length: number; truncated: boolean };

const readVarint = (view: DataView, offset: number): Varint => {
  let value = 0n;
  let length = 0;
  let truncated = true;
  for (let index = 0; index < 9 && offset + index < view.byteLength; index += 1) {
    const byteValue = view.getUint8(offset + index);
    length += 1;
    if (index === 8) {
      value = (value << 8n) | BigInt(byteValue);
      truncated = false;
      break;
    }
    value = (value << 7n) | BigInt(byteValue & 0x7f);
    if ((byteValue & 0x80) === 0) {
      truncated = false;
      break;
    }
  }
  return { value, length, truncated: truncated || length === 0 };
};

const safeNumber = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num)) {
    issues.push(`${label} exceeds JavaScript's safe integer range.`);
    return null;
  }
  return num;
};

const recordValueSize = (serialType: number): number | null => {
  if (serialType === 0) return 0;
  if (serialType === 1) return 1;
  if (serialType === 2) return 2;
  if (serialType === 3) return 3;
  if (serialType === 4) return 4;
  if (serialType === 5) return 6;
  if (serialType === 6) return 8;
  if (serialType === 7) return 8;
  if (serialType === 8) return 0;
  if (serialType === 9) return 0;
  if (serialType >= 12) {
    if (serialType % 2 === 0) return (serialType - 12) / 2;
    return (serialType - 13) / 2;
  }
  return null;
};

const storageClass = (serialType: number): string => {
  if (serialType === 0) return "NULL";
  if (serialType >= 1 && serialType <= 6) return "Integer";
  if (serialType === 7) return "Float";
  if (serialType === 8 || serialType === 9) return "Integer constant";
  if (serialType >= 12 && serialType % 2 === 0) return "BLOB";
  if (serialType >= 13 && serialType % 2 === 1) return "TEXT";
  return "Reserved";
};

const decodeText = (
  bytes: Uint8Array,
  encoding: string | null,
  issues: string[],
  context: string
): string => {
  const decoderName = encoding || "UTF-8";
  try {
    const decoder = new TextDecoder(decoderName);
    return decoder.decode(bytes);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    issues.push(`Failed to decode ${context} as ${decoderName}: ${reason}`);
    return "";
  }
};

const readSignedInteger = (view: DataView, offset: number, length: number): bigint => {
  let value = 0n;
  for (let index = 0; index < length; index += 1) {
    value = (value << 8n) | BigInt(view.getUint8(offset + index));
  }
  const bitLength = BigInt(length * 8);
  const signBit = 1n << (bitLength - 1n);
  const mask = (1n << bitLength) - 1n;
  const signed = value & mask;
  return (signed & signBit) !== 0n ? signed - (1n << bitLength) : signed;
};

const sliceRecordBytes = (
  view: DataView,
  dataOffset: number,
  bytesToUse: number
): ArrayBuffer | SharedArrayBuffer => {
  if (bytesToUse <= 0 || view.byteOffset + dataOffset >= view.buffer.byteLength) {
    return new ArrayBuffer(0);
  }
  const sliceLength = Math.min(
    bytesToUse,
    view.buffer.byteLength - (view.byteOffset + dataOffset)
  );
  return view.buffer.slice(
    view.byteOffset + dataOffset,
    view.byteOffset + dataOffset + sliceLength
  );
};

const decodeRecordText = (
  view: DataView,
  dataOffset: number,
  bytesToUse: number,
  encoding: string | null,
  issues: string[]
): string => {
  if (bytesToUse <= 0 || view.byteOffset + dataOffset >= view.buffer.byteLength) return "";
  const sliceLength = Math.min(
    bytesToUse,
    view.buffer.byteLength - (view.byteOffset + dataOffset)
  );
  return decodeText(
    new Uint8Array(view.buffer, view.byteOffset + dataOffset, Math.max(0, sliceLength)),
    encoding,
    issues,
    "record text"
  );
};

const decodeRecordValue = (
  view: DataView,
  dataOffset: number,
  serialType: number,
  expectedSize: number,
  bytesToUse: number,
  encoding: string | null,
  issues: string[]
): { value: string | number | bigint | ArrayBuffer | SharedArrayBuffer | null; description: string } => {
  if (serialType === 0) return { value: null, description: "NULL" };
  if (serialType === 7 && bytesToUse === 8) {
    return { value: view.getFloat64(dataOffset, false), description: "64-bit IEEE float" };
  }
  if (serialType === 8) return { value: 0, description: "Integer constant 0" };
  if (serialType === 9) return { value: 1, description: "Integer constant 1" };
  if (serialType >= 1 && serialType <= 6 && bytesToUse === expectedSize) {
    const signed = readSignedInteger(view, dataOffset, expectedSize);
    return {
      value: expectedSize <= 4 ? Number(signed) : signed,
      description: `${expectedSize * 8}-bit signed integer`
    };
  }
  if (serialType >= 12 && serialType % 2 === 0) {
    return { value: sliceRecordBytes(view, dataOffset, bytesToUse), description: "Raw BLOB payload" };
  }
  if (serialType >= 13 && serialType % 2 === 1) {
    return {
      value: decodeRecordText(view, dataOffset, bytesToUse, encoding, issues),
      description: `Text using ${encoding || "UTF-8"}`
    };
  }
  return { value: null, description: storageClass(serialType) };
};

const parseRecord = (
  view: DataView,
  payloadOffset: number,
  payloadSize: number,
  encoding: string | null,
  issues: string[],
  columnNames: string[]
): SqliteRecord => {
  const payloadLimit = Math.min(payloadSize, view.byteLength - payloadOffset);
  const headerVarint = readVarint(view, payloadOffset);
  const headerSizeNumber = safeNumber(headerVarint.value, "Record header size", issues);
  const headerSize = headerSizeNumber ?? payloadLimit;
  const headerEnd = payloadOffset + Math.min(headerSize, payloadLimit);
  const headerTruncated = headerVarint.truncated || headerSize > payloadLimit;

  const serialTypes: number[] = [];
  let cursor = payloadOffset + headerVarint.length;
  while (cursor < headerEnd) {
    const serial = readVarint(view, cursor);
    if (serial.length === 0) break;
    const code = safeNumber(serial.value, "Serial type", issues);
    if (code != null) serialTypes.push(code);
    cursor += serial.length;
    if (serial.truncated) break;
  }

  const values: SqliteRecordValue[] = [];
  let dataOffset = payloadOffset + headerSize;
  for (let index = 0; index < serialTypes.length; index += 1) {
    const serialType = serialTypes[index];
    if (serialType == null) {
      values.push({
        name: columnNames[index] ?? null,
        serialType: -1,
        storageClass: "Unknown",
        sizeBytes: null,
        value: null,
        description: "Serial type missing",
        truncated: true
      });
      continue;
    }
    const size = recordValueSize(serialType);
    const className = storageClass(serialType);
    const available = Math.max(0, payloadOffset + payloadLimit - dataOffset);
    const expectedSize = size ?? 0;
    const truncated = available < expectedSize;
    const bytesToUse = Math.min(available, expectedSize);
    const decoded = decodeRecordValue(
      view,
      dataOffset,
      serialType,
      expectedSize,
      bytesToUse,
      encoding,
      issues
    );
    values.push({
      name: columnNames[index] ?? null,
      serialType,
      storageClass: className,
      sizeBytes: size,
      value: decoded.value,
      description: decoded.description,
      truncated
    });
    dataOffset += expectedSize;
  }

  return { headerSize: headerSizeNumber, serialTypes, values, headerTruncated };
};

export { parseRecord, readVarint, safeNumber };
