"use strict";

// CAFEBABE is shared by Mach-O universal binaries and Java class files. The
// class-file version checks below come from JVMS 4.1:
// https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.1
const isLikelyJavaClassFile = (dv: DataView, fileSize = dv.byteLength): boolean => {
  if (fileSize < 8 || dv.byteLength < 8) return false;
  if (dv.getUint32(0, false) !== 0xcafebabe) return false;
  const minor = dv.getUint16(4, false);
  const major = dv.getUint16(6, false);
  if (major < 45) return false;
  if (major >= 56 && minor !== 0 && minor !== 0xffff) return false;
  if (fileSize >= 10 && dv.byteLength >= 10 && dv.getUint16(8, false) === 0) return false;
  return true;
};

const probeMachO = (dv: DataView, fileSize = dv.byteLength): string | null => {
  if (dv.byteLength < 4 || fileSize < 4) return null;
  const magic = dv.getUint32(0, false);
  if (magic === 0xfeedface || magic === 0xcefaedfe) return "Mach-O 32-bit";
  if (magic === 0xfeedfacf || magic === 0xcffaedfe) return "Mach-O 64-bit";
  // Apple's fat.h defines fat_header / fat_arch as always big-endian on disk,
  // so FAT_CIGAM* are swapped constants, not standalone file signatures:
  // https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h
  if (magic !== 0xcafebabe && magic !== 0xcafebabf) return null;
  if (fileSize < 8 || dv.byteLength < 8) return null;
  if (isLikelyJavaClassFile(dv, fileSize)) return null;
  return "Mach-O universal (Fat)";
};

export { probeMachO };
