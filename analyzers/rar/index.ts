// @ts-nocheck
"use strict";

import { SIGNATURE_V5 } from "./constants.js";
import { detectRarVersionBytes } from "./utils.js";
import { parseRar4 } from "./rar4.js";
import { parseRar5 } from "./rar5.js";

export { hasRarSignature } from "./utils.js";

export async function parseRar(file) {
  const signatureBytes = new Uint8Array(await file.slice(0, SIGNATURE_V5.length).arrayBuffer());
  const version = detectRarVersionBytes(signatureBytes);
  if (version === 4) return parseRar4(file);
  if (version === 5) return parseRar5(file);
  return { isRar: false, version: null, entries: [], issues: ["Not a RAR archive."] };
}
