// ModuleInfo._flags and ModuleInfo.addrOf define this variable-sized ABI record.
// https://github.com/dlang/dmd/blob/v2.112.0/druntime/src/object.d#L2302-L2421
export const D_MODULE_FLAGS = {
  constructorStarted: 0x1,
  constructorDone: 0x2,
  standalone: 0x4,
  tlsConstructor: 0x8,
  tlsDestructor: 0x10,
  sharedConstructor: 0x20,
  sharedDestructor: 0x40,
  getMembers: 0x80,
  independentConstructor: 0x100,
  unitTest: 0x200,
  importedModules: 0x400,
  localClasses: 0x800,
  name: 0x1000
} as const;

export const D_MODULE_INFO_LAYOUT = {
  headerBytes: Uint32Array.BYTES_PER_ELEMENT * 2, // _flags followed by _index.
  flagsOffset: 0,
  indexOffset: Uint32Array.BYTES_PER_ELEMENT,
  knownFlagMask: Object.values(D_MODULE_FLAGS).reduce((mask, flag) => mask | flag, 0),
  callbacks: [
    { flag: D_MODULE_FLAGS.tlsConstructor, kind: "TLS constructor" },
    { flag: D_MODULE_FLAGS.tlsDestructor, kind: "TLS destructor" },
    { flag: D_MODULE_FLAGS.sharedConstructor, kind: "Shared constructor" },
    { flag: D_MODULE_FLAGS.sharedDestructor, kind: "Shared destructor" },
    { flag: D_MODULE_FLAGS.getMembers, kind: "Get members" },
    { flag: D_MODULE_FLAGS.independentConstructor, kind: "Independent constructor" },
    { flag: D_MODULE_FLAGS.unitTest, kind: "Unit test" }
  ]
} as const;
