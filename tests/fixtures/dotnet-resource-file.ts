"use strict";

type ResourceEntrySpec = {
  name: string;
  value: number[];
};

const textEncoder = new TextEncoder();
// ResourceManager and ResourceReader constants come from dotnet/runtime ResourceReader/ResourceWriter:
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceWriter.cs
const RESOURCE_MANAGER_MAGIC = 0xbeefcace;
const RESOURCE_MANAGER_VERSION = 1;
const RUNTIME_RESOURCE_SET_VERSION = 2;
const RESOURCE_TYPE_CODE_STRING = 1;
const RESOURCE_MANAGER_FIXED_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT * 3;
const RUNTIME_RESOURCE_SET_FIXED_HEADER_SIZE = Uint32Array.BYTES_PER_ELEMENT * 3;
const RUNTIME_RESOURCE_SET_ALIGNMENT = Uint32Array.BYTES_PER_ELEMENT * 2;
const RUNTIME_RESOURCE_READER_TYPE = "System.Resources.ResourceReader";
const RUNTIME_RESOURCE_SET_TYPE = "System.Resources.RuntimeResourceSet";


const alignRuntimeTable = (value: number): number =>
  (value + RUNTIME_RESOURCE_SET_ALIGNMENT - 1) & ~(RUNTIME_RESOURCE_SET_ALIGNMENT - 1);

const writeSevenBitInt = (value: number): number[] => {
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining) byte |= 0x80;
    bytes.push(byte);
  } while (remaining);
  return bytes;
};

const binaryString = (value: string): number[] => {
  const bytes = textEncoder.encode(value);
  return [...writeSevenBitInt(bytes.length), ...bytes];
};

const utf16Name = (value: string): number[] => {
  const bytes = new Uint8Array(value.length * Uint16Array.BYTES_PER_ELEMENT);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < value.length; index += 1) {
    view.setUint16(index * Uint16Array.BYTES_PER_ELEMENT, value.charCodeAt(index), true);
  }
  return [...writeSevenBitInt(bytes.length), ...bytes];
};

export const stringResourceValue = (value: string): number[] => [
  ...writeSevenBitInt(RESOURCE_TYPE_CODE_STRING),
  ...binaryString(value)
];

const writeResourceSetHeader = (
  view: DataView,
  runtimeHeaderOffset: number,
  entryCount: number,
  typeCount: number,
  version: number
): void => {
  view.setUint32(runtimeHeaderOffset, version, true);
  view.setInt32(runtimeHeaderOffset + Uint32Array.BYTES_PER_ELEMENT, entryCount, true);
  view.setInt32(runtimeHeaderOffset + Uint32Array.BYTES_PER_ELEMENT * 2, typeCount, true);
};

export const makeDotNetResources = (
  entries: ResourceEntrySpec[], userTypes: string[] = [], version = RUNTIME_RESOURCE_SET_VERSION
): Uint8Array => {
  const readerType = binaryString(RUNTIME_RESOURCE_READER_TYPE);
  const setType = binaryString(RUNTIME_RESOURCE_SET_TYPE);
  const headerSize = readerType.length + setType.length;
  const runtimeHeaderOffset = RESOURCE_MANAGER_FIXED_HEADER_SIZE + headerSize;
  const typeNames = userTypes.flatMap(binaryString);
  const runtimeTableOffset = alignRuntimeTable(
    runtimeHeaderOffset + RUNTIME_RESOURCE_SET_FIXED_HEADER_SIZE + typeNames.length);
  const namePayloads = entries.map(entry => utf16Name(entry.name));
  const nameTableBytes = namePayloads.reduce(
    (size, name) => size + name.length + Uint32Array.BYTES_PER_ELEMENT,
    0
  );
  const dataSectionOffset =
    runtimeTableOffset + entries.length * Uint32Array.BYTES_PER_ELEMENT * 2 +
    Uint32Array.BYTES_PER_ELEMENT + nameTableBytes;
  const valueBytes = entries.reduce((size, entry) => size + entry.value.length, 0);
  const bytes = new Uint8Array(dataSectionOffset + valueBytes);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, RESOURCE_MANAGER_MAGIC, true);
  view.setUint32(Uint32Array.BYTES_PER_ELEMENT, RESOURCE_MANAGER_VERSION, true);
  view.setUint32(Uint32Array.BYTES_PER_ELEMENT * 2, headerSize, true);
  bytes.set(readerType, RESOURCE_MANAGER_FIXED_HEADER_SIZE);
  bytes.set(setType, RESOURCE_MANAGER_FIXED_HEADER_SIZE + readerType.length);
  writeResourceSetHeader(view, runtimeHeaderOffset, entries.length, userTypes.length, version);
  bytes.set(typeNames, runtimeHeaderOffset + RUNTIME_RESOURCE_SET_FIXED_HEADER_SIZE);
  let nameOffset = runtimeTableOffset + entries.length * Uint32Array.BYTES_PER_ELEMENT * 2 +
    Uint32Array.BYTES_PER_ELEMENT;
  let dataOffset = dataSectionOffset;
  view.setUint32(runtimeTableOffset + entries.length * Uint32Array.BYTES_PER_ELEMENT * 2, dataSectionOffset, true);
  entries.forEach((entry, index) => {
    view.setUint32(runtimeTableOffset + index * Uint32Array.BYTES_PER_ELEMENT, index, true);
    view.setUint32(
      runtimeTableOffset + (entries.length + index) * Uint32Array.BYTES_PER_ELEMENT,
      nameOffset - runtimeTableOffset - entries.length * Uint32Array.BYTES_PER_ELEMENT * 2 -
        Uint32Array.BYTES_PER_ELEMENT,
      true
    );
    bytes.set(namePayloads[index] ?? [], nameOffset);
    nameOffset += namePayloads[index]?.length ?? 0;
    view.setUint32(nameOffset, dataOffset - dataSectionOffset, true);
    nameOffset += Uint32Array.BYTES_PER_ELEMENT;
    bytes.set(entry.value, dataOffset);
    dataOffset += entry.value.length;
  });
  return bytes;
};

export const runtimeHeaderOffset = (): number =>
  RESOURCE_MANAGER_FIXED_HEADER_SIZE +
  binaryString(RUNTIME_RESOURCE_READER_TYPE).length +
  binaryString(RUNTIME_RESOURCE_SET_TYPE).length;

export const runtimeTableOffset = (): number =>
  alignRuntimeTable(runtimeHeaderOffset() + RUNTIME_RESOURCE_SET_FIXED_HEADER_SIZE);
