import type { RegistryValue } from "./registry-types.js";
import { registryParameters } from "./registry-parameters.js";

const unresolved = (tag: string, source: string): RegistryValue =>
  ({ type: "unresolved", tag, source });

const parseDword = (source: string, issues: string[]): RegistryValue => {
  // ATL calls VarUI4FromStr (OLE Automation), not strtoul. Only unambiguous unsigned
  // decimal integers are interpreted locally; locale-specific coercions remain unresolved.
  // https://github.com/adzm/atlmfc/blob/master/include/statreg.h (AddValue)
  // REG_DWORD is unsigned 32-bit: maximum = 2^32 - 1 = 0xffffffff.
  // https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
  if (registryParameters(source, []).length) return unresolved("d", source);
  if (/^\+?\d+$/u.test(source.trim()) && Number(source) <= 0xffff_ffff) {
    return { type: "REG_DWORD", data: Number(source) };
  }
  issues.push("ATL RGS: DWORD is out of range or requires OLE/locale-specific coercion.");
  return unresolved("d", source);
};

const parseBinary = (source: string, issues: string[]): RegistryValue => {
  if (registryParameters(source, []).length) return unresolved("b", source);
  // ATL consumes pairs of hex digits without separators; odd lengths are rejected.
  // https://github.com/adzm/atlmfc/blob/master/include/statreg.h (AddValue, ChToByte)
  // Hex radix = 2^4 = 16; an 8-bit byte needs 8/4 = 2 digits (hence length % 2).
  // https://www.rfc-editor.org/rfc/rfc4648.html#section-8
  if (source.length % 2 || !/^[\da-f]*$/iu.test(source)) {
    issues.push("ATL RGS: binary value must contain complete hexadecimal byte pairs.");
    return unresolved("b", source);
  }
  return { type: "REG_BINARY", data: Uint8Array.from(
    source.match(/../gu) ?? [], pair => Number.parseInt(pair, 16)) };
};

const parseMultiString = (source: string, issues: string[]): RegistryValue => {
  // SetMultiStringValue measures the sequence up to its first empty string.
  // https://github.com/adzm/atlmfc/blob/master/include/atlbase.h
  const parts = source.split("\\0");
  const end = parts.indexOf("");
  if (end >= 0 && parts.slice(end + 1).some(part => part.length)) {
    issues.push("ATL RGS: MULTI_SZ data after its first empty string is not stored.");
  }
  return { type: "REG_MULTI_SZ", data: end < 0 ? parts : parts.slice(0, end) };
};

export const parseRegistryValue = (
  tag: string, source: string, issues: string[]
): RegistryValue => {
  switch (tag.toLowerCase()) {
    case "s": return { type: "REG_SZ", data: source };
    case "d": return parseDword(source, issues);
    // ATL replaces literal \0 pairs with NULs and appends a double NUL.
    case "m": return parseMultiString(source, issues);
    case "b": return parseBinary(source, issues);
    default:
      issues.push(`ATL RGS: unsupported registry value type '${tag}'.`);
      return unresolved(tag, source);
  }
};
