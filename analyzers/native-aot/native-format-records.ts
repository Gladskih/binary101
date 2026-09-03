"use strict";

import type { NativeAotReflectionScope } from "./format.js";
import {
  NativeFormatError,
  type NativeFormatReader,
  type NativeFormatHandle
} from "./native-format-reader.js";

// IDs and field orders come from dotnet/runtime's generated NativeFormat reader.
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderCommonGen.cs
// https://github.com/dotnet/runtime/blob/main/src/coreclr/tools/Common/Internal/Metadata/NativeFormat/NativeFormatReaderGen.cs
const HANDLE = {
  customAttribute: 0x21,
  method: 0x28,
  namespace: 0x2f,
  qualifiedMethod: 0x36,
  scope: 0x38,
  string: 0x1a,
  typeDefinition: 0x3a,
  typeForwarder: 0x3b,
  typeReference: 0x3d,
  typeSpecification: 0x3e
} as const;

export const NATIVE_FORMAT_SCOPE_HANDLE = HANDLE.scope;
const MAX_COLLECTION_ITEMS = 100_000;
// Defensive per-record cap; NativeFormat itself has no smaller byte-collection limit.
const MAX_BYTE_COLLECTION = 0x10_0000;

class RecordCursor {
  offset: number;

  constructor(readonly reader: NativeFormatReader, offset: number) {
    this.offset = offset;
  }

  unsigned(): number {
    const decoded = this.reader.unsigned(this.offset);
    this.offset = decoded.nextOffset;
    return decoded.value;
  }

  handle(...types: number[]): NativeFormatHandle {
    const decoded = this.reader.handle(this.offset, types);
    this.offset = decoded.nextOffset;
    return decoded.value;
  }

  handles(...types: number[]): NativeFormatHandle[] {
    const decoded = this.reader.handles(this.offset, types, MAX_COLLECTION_ITEMS);
    this.offset = decoded.nextOffset;
    return decoded.value;
  }

  bytes(): void {
    this.offset = this.reader.bytes(this.offset, MAX_BYTE_COLLECTION).nextOffset;
  }
}

export interface NativeFormatScopeRecord {
  name: NativeFormatHandle;
  moduleName: NativeFormatHandle;
  rootNamespace: NativeFormatHandle;
  version: NativeAotReflectionScope["version"];
}

export interface NativeFormatNamespaceRecord {
  name: NativeFormatHandle;
  types: NativeFormatHandle[];
  children: NativeFormatHandle[];
}

export interface NativeFormatTypeRecord {
  name: NativeFormatHandle;
  nestedTypes: NativeFormatHandle[];
  methods: NativeFormatHandle[];
}

const readVersionPart = (cursor: RecordCursor): number => {
  const value = cursor.unsigned();
  if (value > 0xffff) throw new NativeFormatError(`Version component ${value} exceeds UInt16.`);
  return value;
};

export const parseNativeFormatScopeRecord = (
  reader: NativeFormatReader,
  handle: NativeFormatHandle
): NativeFormatScopeRecord => {
  const cursor = new RecordCursor(reader, handle.offset);
  cursor.unsigned();
  const name = cursor.handle(HANDLE.string);
  cursor.unsigned();
  const version = {
    major: readVersionPart(cursor),
    minor: readVersionPart(cursor),
    build: readVersionPart(cursor),
    revision: readVersionPart(cursor)
  };
  cursor.bytes();
  cursor.handle(HANDLE.string);
  const rootNamespace = cursor.handle(HANDLE.namespace);
  cursor.handle(HANDLE.qualifiedMethod);
  cursor.handle(HANDLE.typeDefinition);
  cursor.handles(HANDLE.customAttribute);
  const moduleName = cursor.handle(HANDLE.string);
  return { name, moduleName, rootNamespace, version };
};

export const parseNativeFormatNamespaceRecord = (
  reader: NativeFormatReader,
  handle: NativeFormatHandle
): NativeFormatNamespaceRecord => {
  const cursor = new RecordCursor(reader, handle.offset);
  cursor.handle(HANDLE.namespace, HANDLE.scope);
  const name = cursor.handle(HANDLE.string);
  const types = cursor.handles(HANDLE.typeDefinition);
  cursor.handles(HANDLE.typeForwarder);
  return { name, types, children: cursor.handles(HANDLE.namespace) };
};

export const parseNativeFormatTypeRecord = (
  reader: NativeFormatReader,
  handle: NativeFormatHandle
): NativeFormatTypeRecord => {
  const cursor = new RecordCursor(reader, handle.offset);
  cursor.unsigned();
  cursor.handle(HANDLE.typeDefinition, HANDLE.typeReference, HANDLE.typeSpecification);
  cursor.handle(HANDLE.namespace);
  const name = cursor.handle(HANDLE.string);
  cursor.unsigned();
  cursor.unsigned();
  cursor.handle(HANDLE.typeDefinition);
  const nestedTypes = cursor.handles(HANDLE.typeDefinition);
  const methods = cursor.handles(HANDLE.method);
  return { name, nestedTypes, methods };
};

export const parseNativeFormatMethodName = (
  reader: NativeFormatReader,
  handle: NativeFormatHandle
): string => {
  const cursor = new RecordCursor(reader, handle.offset);
  cursor.unsigned();
  cursor.unsigned();
  const name = cursor.handle(HANDLE.string);
  return reader.string(name);
};
