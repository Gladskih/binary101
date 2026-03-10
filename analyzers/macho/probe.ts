"use strict";

const FAT_HEADER_SIZE = 8;
const FAT_ARCH_SIZE = 20;

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

const fatSlice32LooksPlausible = (
  dv: DataView,
  fileSize: number,
  sliceCount: number
): boolean => {
  if (dv.byteLength < FAT_HEADER_SIZE + FAT_ARCH_SIZE) return false;
  const sliceOffset = BigInt(dv.getUint32(16, false));
  const sliceSize = BigInt(dv.getUint32(20, false));
  const tableSize = BigInt(FAT_HEADER_SIZE + sliceCount * FAT_ARCH_SIZE);
  const bigFileSize = BigInt(fileSize);
  return (
    sliceSize > 0n &&
    sliceOffset >= tableSize &&
    sliceOffset <= bigFileSize &&
    sliceSize <= bigFileSize - sliceOffset
  );
};

const probeFat32MachO = (dv: DataView, fileSize: number): string | null => {
  if (fileSize < FAT_HEADER_SIZE || dv.byteLength < FAT_HEADER_SIZE) {
    return "Mach-O universal (Fat, truncated)";
  }
  const sliceCount = dv.getUint32(4, false);
  if (fileSize < FAT_HEADER_SIZE + sliceCount * FAT_ARCH_SIZE) {
    if (isLikelyJavaClassFile(dv, fileSize)) return null;
    return "Mach-O universal (Fat, truncated)";
  }
  if (fatSlice32LooksPlausible(dv, fileSize, sliceCount)) {
    return "Mach-O universal (Fat)";
  }
  if (isLikelyJavaClassFile(dv, fileSize)) return null;
  return "Mach-O universal (Fat)";
};

const probeFat64MachO = (dv: DataView, fileSize: number): string | null => {
  if (fileSize < FAT_HEADER_SIZE || dv.byteLength < FAT_HEADER_SIZE) {
    return "Mach-O universal (Fat, truncated)";
  }
  const sliceCount = dv.getUint32(4, false);
  // mach-o/fat.h: each fat_arch_64 record is 32 bytes.
  if (fileSize < FAT_HEADER_SIZE + sliceCount * 32) {
    return "Mach-O universal (Fat, truncated)";
  }
  return "Mach-O universal (Fat)";
};

const probeMachO = (dv: DataView, fileSize = dv.byteLength): string | null => {
  if (dv.byteLength < 4 || fileSize < 4) return null;
  const magic = dv.getUint32(0, false);
  if (magic === 0xfeedface || magic === 0xcefaedfe) return "Mach-O 32-bit";
  if (magic === 0xfeedfacf || magic === 0xcffaedfe) return "Mach-O 64-bit";
  // Apple's fat.h defines fat_header / fat_arch as always big-endian on disk,
  // so FAT_CIGAM* are swapped constants, not standalone file signatures:
  // https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h
  if (magic === 0xcafebabe) return probeFat32MachO(dv, fileSize);
  if (magic === 0xcafebabf) return probeFat64MachO(dv, fileSize);
  return null;
};

export { probeMachO };
