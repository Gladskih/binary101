"use strict";

export const createMinimalJavaClassBytes = (): Uint8Array => {
  const bytes = new Uint8Array(10);
  const view = new DataView(bytes.buffer);
  // JVMS 4.1: ClassFile starts with magic, minor_version, major_version, and
  // constant_pool_count. The Mach-O ambiguity guard only needs these fields.
  view.setUint32(0, 0xcafebabe, false);
  view.setUint16(4, 0, false);
  view.setUint16(6, 52, false);
  view.setUint16(8, 1, false);
  return bytes;
};
