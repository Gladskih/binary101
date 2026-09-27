import assert from "node:assert/strict";
import type { ResourcePreviewResult } from "../../analyzers/pe/resources/preview/types.js";

export const assertResourcePrefixWarnings = (
  bytes: Uint8Array, decode: (prefix: Uint8Array) => ResourcePreviewResult | null
): void => {
  for (let length = 0; length < bytes.length; length += 1) {
    assert.ok(decode(bytes.subarray(0, length))?.issues?.length, `Truncated at byte ${length}`);
  }
};
