"use strict";

import { bufferToHex } from "./utils.js";

export async function computeHashForFile(file, algorithmName) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest(algorithmName, buffer);
  return bufferToHex(hashBuffer);
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
