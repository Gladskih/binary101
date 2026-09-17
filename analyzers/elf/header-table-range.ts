// gABI 2: header tables use an offset, entry stride and entry count.
// https://gabi.xinuos.com/elf/02-eheader.html
const headerTableCount = (fileSize: number, offset: number, stride: number,
  count: number, label: string, issues: string[]): number => {
  if (offset >= fileSize) {
    issues.push(`${label} table falls outside the file.`);
    return 0;
  }
  const available = Math.floor((fileSize - offset) / stride);
  if (count > available) issues.push(`${label} table is truncated.`);
  return Math.min(count, available);
};

export const locateElfHeaderTable = (fileSize: number, offset: bigint, count: number,
  stride: number, minimumSize: number, label: string, issues: string[]) => {
  if (!offset || !count) return null;
  if (stride < minimumSize) {
    issues.push(`${label} entry size (${stride}) is smaller than minimum (${minimumSize}).`);
    return null;
  }
  const start = Number(offset);
  if (!Number.isSafeInteger(start) || start < 0) {
    issues.push(`${label} offset is too large or negative.`);
    return null;
  }
  return { offset: start, count: headerTableCount(fileSize, start, stride, count, label, issues) };
};
