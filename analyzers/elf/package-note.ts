// UAPI.8 uses a NUL-terminated UTF-8 JSON object with NUL padding.
// https://uapi-group.org/specifications/specs/package_metadata_for_executable_files/
export const decodeElfPackageNote = (bytes: Uint8Array, issues: string[]): string | null => {
  const end = bytes.indexOf(0);
  if (end <= 0 || bytes.subarray(end).some(byte => byte !== 0)) {
    issues.push("FDO package metadata requires JSON text followed by a NUL terminator and zero padding.");
    return null;
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, end));
    const value: unknown = JSON.parse(text);
    if (value !== null && typeof value === "object" && !Array.isArray(value)) return text;
  } catch {
    // Invalid UTF-8 and JSON have the same format-level diagnostic.
  }
  issues.push("FDO package metadata is not a valid UTF-8 JSON object.");
  return null;
};
