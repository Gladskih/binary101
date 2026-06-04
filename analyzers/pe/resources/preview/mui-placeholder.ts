"use strict";

// Observed Windows SystemResources .mun marker for resource entries whose actual
// language-neutral payload lives in the paired image. Only callers with a valid
// MUI resource configuration should treat this byte pattern as non-anomalous.
export const isAsciiPlaceholderPayload = (data: Uint8Array): boolean => {
  const placeholderBytes = new TextEncoder().encode("placeholder");
  return data.length >= placeholderBytes.length &&
    placeholderBytes.every((byte, index) => data[index] === byte) &&
    data.subarray(placeholderBytes.length).every(byte => byte === 0);
};
