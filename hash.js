"use strict";

import { bufToHex } from "./utils.js";

export async function computeHashForFile(file, algo) {
  const buf = await file.arrayBuffer();
  const h = await crypto.subtle.digest(algo, buf);
  return bufToHex(h);
}

export async function copyToClipboard(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
}

