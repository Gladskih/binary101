import type { DModuleInfo, DRuntimeImage } from "../../analyzers/d-runtime/types.js";

// Test-only wire definitions, independent of production constants and pinned to:
// https://github.com/dlang/dmd/blob/v2.112.0/druntime/src/object.d#L2302-L2421
export const D_TEST_ABI = {
  pointer32Bytes: 4 as const,
  pointer64Bytes: 8 as const,
  headerBytes: 8, // Two uint fields: _flags and _index.
  flagsOffset: 0,
  indexOffset: 4,
  flags: {
    constructorStarted: 0x1, constructorDone: 0x2,
    standalone: 0x4, tlsConstructor: 0x8, tlsDestructor: 0x10,
    sharedConstructor: 0x20, sharedDestructor: 0x40, getMembers: 0x80,
    independentConstructor: 0x100, unitTest: 0x200,
    importedModules: 0x400, localClasses: 0x800, name: 0x1000
  }
};

// Independent I/O expectation, per the existing PE reader's browser measurements.
// This is a read batch size, not a maximum metadata size.
export const D_TEST_IO = { readWindowBytes: 64 * 1024 };

// Incidental addresses and storage are generated centrally, not used as ABI oracles.
export const D_TEST_MEMORY = {
  moduleAddress: 0x1000n, codeAddress: 0x2000n, classAddress: 0x1080n,
  unmappedAddress: 0x9000n, regionBytes: 256
};

export const writeDTestPointer = (
  view: DataView, offset: number, value: bigint, pointerSize: 4 | 8
): void => {
  if (pointerSize === D_TEST_ABI.pointer64Bytes) view.setBigUint64(offset, value, true);
  else view.setUint32(offset, Number(value), true);
};

export const createDTestModule = (): DModuleInfo => ({
  address: D_TEST_MEMORY.moduleAddress,
  flags: D_TEST_ABI.flags.name | D_TEST_ABI.flags.importedModules |
    D_TEST_ABI.flags.localClasses | D_TEST_ABI.flags.tlsConstructor | D_TEST_ABI.flags.unitTest,
  index: 0,
  name: "sample.module",
  callbacks: [
    { kind: "TLS constructor", address: D_TEST_MEMORY.codeAddress },
    { kind: "Unit test", address: D_TEST_MEMORY.codeAddress + BigInt(D_TEST_ABI.pointer64Bytes * 2) }
  ],
  importedModules: [D_TEST_MEMORY.moduleAddress],
  localClasses: [D_TEST_MEMORY.classAddress]
});

export const createDDisplayModule = (): DModuleInfo => {
  const module = createDTestModule();
  return { ...module,
    index: module.callbacks.length + module.importedModules.length + module.localClasses.length,
    importedModules: [...module.importedModules, ...module.localClasses],
    localClasses: [...module.localClasses, ...module.importedModules, ...module.localClasses] };
};

const writeReferenceField = (view: DataView, offset: number, values: bigint[],
  pointerSize: 4 | 8) => {
  writeDTestPointer(view, offset, BigInt(values.length), pointerSize);
  values.forEach((address, index) =>
    writeDTestPointer(view, offset + (index + 1) * pointerSize, address, pointerSize));
  return offset + (values.length + 1) * pointerSize;
};

const encodeModule = (view: DataView, pointerSize: 4 | 8, record: DModuleInfo) => {
  view.setUint32(D_TEST_ABI.flagsOffset, record.flags, true);
  view.setUint32(D_TEST_ABI.indexOffset, record.index, true);
  record.callbacks.forEach((callback, index) =>
    writeDTestPointer(view, D_TEST_ABI.headerBytes + index * pointerSize, callback.address, pointerSize));
  const imports = D_TEST_ABI.headerBytes + record.callbacks.length * pointerSize;
  const classes = record.flags & D_TEST_ABI.flags.importedModules
    ? writeReferenceField(view, imports, record.importedModules, pointerSize) : imports;
  const name = record.flags & D_TEST_ABI.flags.localClasses
    ? writeReferenceField(view, classes, record.localClasses, pointerSize) : classes;
  new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
    .set(new TextEncoder().encode(`${record.name}\0`), name);
  return { imports, classes, name };
};

const createTestImage = (bytes: Uint8Array, address: bigint, pointerSize: 4 | 8): DRuntimeImage => ({
  pointerSize, littleEndian: true,
  isMapped: (location, size) => location >= address &&
    location + BigInt(size) <= address + BigInt(bytes.length),
  read: async (location, size) => {
    const offset = Number(location - address);
    if (offset < 0 || offset >= bytes.length) return null;
    return new DataView(bytes.buffer, bytes.byteOffset + offset,
      Math.min(size, bytes.length - offset));
  },
  isExecutable: location => location >= D_TEST_MEMORY.codeAddress &&
    location < D_TEST_MEMORY.codeAddress + BigInt(D_TEST_MEMORY.regionBytes)
});

export const createDModuleFixture = (pointerSize: 4 | 8 = D_TEST_ABI.pointer64Bytes,
  record = createDTestModule(), bytes = new Uint8Array(D_TEST_MEMORY.regionBytes)) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const offsets = encodeModule(view, pointerSize, record);
  const writePointer = (offset: number, value: bigint): void =>
    writeDTestPointer(view, offset, value, pointerSize);
  return {
    record, bytes, image: createTestImage(bytes, record.address, pointerSize),
    fieldAddress: (field: keyof typeof offsets) => record.address + BigInt(offsets[field]),
    write: {
      flags: (flags: number) => view.setUint32(D_TEST_ABI.flagsOffset, flags, true),
      callback: (index: number, address: bigint) =>
        writePointer(D_TEST_ABI.headerBytes + index * pointerSize, address),
      importCount: (count: bigint) => writePointer(offsets.imports, count),
      importedModule: (index: number, address: bigint) =>
        writePointer(offsets.imports + (index + 1) * pointerSize, address),
      classCount: (count: bigint) => writePointer(offsets.classes, count),
      localClass: (index: number, address: bigint) =>
        writePointer(offsets.classes + (index + 1) * pointerSize, address),
      name: (name: string) => bytes.set(new TextEncoder().encode(`${name}\0`), offsets.name),
      // 0xff is forbidden by UTF-8: https://www.rfc-editor.org/rfc/rfc3629#section-4
      invalidUtf8Name: () => bytes.set(Uint8Array.of(0xff, 0), offsets.name),
      truncatedUtf8Name: (prefix: string) => {
        const encoded = new TextEncoder().encode(prefix);
        bytes.set(encoded, offsets.name);
        // 0xc2 requires a continuation byte: RFC 3629 section 4's UTF8-2 production.
        bytes.set(Uint8Array.of(0xc2, 0), offsets.name + encoded.length);
      },
      unterminatedName: () => bytes.fill("A".charCodeAt(0), offsets.name)
    }
  };
};

export const createStandaloneDModuleFixture = (pointerSize: 4 | 8 = D_TEST_ABI.pointer64Bytes) =>
  createDModuleFixture(pointerSize, { ...createDTestModule(),
    flags: D_TEST_ABI.flags.name | D_TEST_ABI.flags.standalone, name: "minimal",
    callbacks: [], importedModules: [], localClasses: [] });

export const createAllDCallbacksFixture = () => createDModuleFixture(D_TEST_ABI.pointer64Bytes, {
  ...createDTestModule(), name: "callbacks", importedModules: [], localClasses: [],
  flags: D_TEST_ABI.flags.name | D_TEST_ABI.flags.tlsConstructor | D_TEST_ABI.flags.tlsDestructor |
    D_TEST_ABI.flags.sharedConstructor | D_TEST_ABI.flags.sharedDestructor | D_TEST_ABI.flags.getMembers |
    D_TEST_ABI.flags.independentConstructor | D_TEST_ABI.flags.unitTest,
  callbacks: ["TLS constructor", "TLS destructor", "Shared constructor", "Shared destructor",
    "Get members", "Independent constructor", "Unit test"].map((kind, index) => ({ kind,
    address: D_TEST_MEMORY.codeAddress + BigInt(index * D_TEST_ABI.pointer64Bytes) }))
});

export const createDPointerArrayFixture = (values: bigint[]) => {
  const bytes = new Uint8Array((values.length + 1) * D_TEST_ABI.pointer64Bytes);
  const view = new DataView(bytes.buffer);
  writeReferenceField(view, 0, values, D_TEST_ABI.pointer64Bytes);
  return { values, address: D_TEST_MEMORY.moduleAddress,
    image: createTestImage(bytes, D_TEST_MEMORY.moduleAddress, D_TEST_ABI.pointer64Bytes),
    writeCount: (count: bigint) => view.setBigUint64(0, count, true) };
};

export const createBigEndianDModuleFixture = (pointerSize: 4 | 8) => {
  const fixture = createDModuleFixture(pointerSize);
  const view = new DataView(fixture.bytes.buffer);
  fixture.image.littleEndian = false;
  view.setUint32(D_TEST_ABI.flagsOffset, fixture.record.flags);
  view.setUint32(D_TEST_ABI.indexOffset, fixture.record.index);
  for (let offset = D_TEST_ABI.headerBytes;
    offset < Number(fixture.fieldAddress("name") - fixture.record.address); offset += pointerSize) {
    fixture.bytes.subarray(offset, offset + pointerSize).reverse();
  }
  return fixture;
};

export const truncateDModuleHeader = (fixture: ReturnType<typeof createDModuleFixture>): void => {
  fixture.image.read = async () => new DataView(new ArrayBuffer(D_TEST_ABI.headerBytes - 1));
};

export const truncateDModuleFields = (fixture: ReturnType<typeof createDModuleFixture>): void => {
  fixture.image.read = async (address, size) => address === fixture.record.address
    ? new DataView(fixture.bytes.buffer, fixture.bytes.byteOffset, size) : null;
};

export const createOutOfBoundsDArrayFixture = () => {
  const fixture = createDPointerArrayFixture([]);
  fixture.writeCount(BigInt(D_TEST_IO.readWindowBytes / fixture.image.pointerSize));
  const read = fixture.image.read;
  fixture.image.read = async (address, size) => {
    if (address !== fixture.address) throw new Error("Must not read an unmapped array payload");
    return read(address, size);
  };
  return fixture;
};

export const createMultiWindowDArrayFixture = (
  length = D_TEST_IO.readWindowBytes / D_TEST_ABI.pointer64Bytes + 1
) => createDPointerArrayFixture(Array.from({
  length
}, () => D_TEST_MEMORY.moduleAddress));

export const createLongDNameFixture = (name = "A".repeat(D_TEST_IO.readWindowBytes - 1) + "Ж") => {
  return createDModuleFixture(D_TEST_ABI.pointer64Bytes, { ...createDTestModule(), name,
    flags: D_TEST_ABI.flags.name | D_TEST_ABI.flags.standalone,
    callbacks: [], importedModules: [], localClasses: [] },
  new Uint8Array(D_TEST_ABI.headerBytes + new TextEncoder().encode(name).length + 1));
};

export const createInvalidDArrayFixture = () => {
  const values = Array<bigint>(D_TEST_IO.readWindowBytes / D_TEST_ABI.pointer64Bytes + 1)
    .fill(D_TEST_MEMORY.moduleAddress);
  values[0] = D_TEST_MEMORY.moduleAddress + BigInt((values.length + 1) * D_TEST_ABI.pointer64Bytes);
  const fixture = createDPointerArrayFixture(values);
  const read = fixture.image.read;
  fixture.image.read = async (address, size) => {
    if (address >= fixture.address + BigInt(D_TEST_IO.readWindowBytes + D_TEST_ABI.pointer64Bytes)) {
      throw new Error("Must stop reading after the first invalid reference");
    }
    return read(address, size);
  };
  return fixture;
};
