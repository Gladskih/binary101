/** Windows GUID: little-endian Data1/2/3 followed by eight bytes in stored order.
 * https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
 * Shared by RSDS and lfTypeServer2 (Microsoft cvinfo.h).
 */
export const readCodeViewGuid = (view: DataView, offset: number): string => {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > view.byteLength - 16) {
    throw new RangeError("CodeView GUID bounds exceeded.");
  }
  const tail = Array.from({ length: 8 }, (_, index) => view.getUint8(offset + 8 + index)
    .toString(16).padStart(2, "0"));
  return `${view.getUint32(offset, true).toString(16).padStart(8, "0")}-` +
    `${view.getUint16(offset + 4, true).toString(16).padStart(4, "0")}-` +
    `${view.getUint16(offset + 6, true).toString(16).padStart(4, "0")}-` +
    `${tail.slice(0, 2).join("")}-${tail.slice(2).join("")}`;
};
