"use strict";

import { bufferToHex } from "../binary-utils.js";

type HashControls = {
  valueElement: HTMLElement;
  buttonElement: HTMLButtonElement;
  copyButtonElement: HTMLButtonElement;
};

const resetHashDisplay = (sha256: HashControls, sha512: HashControls): void => {
  sha256.valueElement.textContent = "";
  sha512.valueElement.textContent = "";
  sha256.copyButtonElement.hidden = true;
  sha512.copyButtonElement.hidden = true;
  sha256.buttonElement.hidden = false;
  sha512.buttonElement.hidden = false;
  sha256.buttonElement.disabled = false;
  sha512.buttonElement.disabled = false;
  sha256.buttonElement.textContent = "Compute SHA-256";
  sha512.buttonElement.textContent = "Compute SHA-512";
};

const computeAndDisplayHash = async (
  algorithmName: AlgorithmIdentifier,
  file: File | null,
  { valueElement, buttonElement, copyButtonElement }: HashControls
): Promise<void> => {
  if (!file) {
    valueElement.textContent = "No file selected.";
    return;
  }
  buttonElement.disabled = true;
  buttonElement.textContent = "Working...";
  try {
    valueElement.textContent = bufferToHex(
      await crypto.subtle.digest(algorithmName, await file.arrayBuffer())
    );
    copyButtonElement.hidden = false;
    buttonElement.hidden = true;
  } catch (error) {
    const namePart = error instanceof Error && error.name ? `${error.name}: ` : "";
    valueElement.textContent = `Hash failed: ${namePart}${String(error)}`;
    buttonElement.disabled = false;
    buttonElement.textContent = "Retry";
    copyButtonElement.hidden = true;
  }
};

const copyHashToClipboard = async (
  valueElement: HTMLElement
): Promise<"copied" | "failed"> => {
  const text = valueElement.textContent || "";
  try {
    await navigator.clipboard.writeText(text);
    return "copied";
  } catch {
    return "failed";
  }
};

export type { HashControls };
export { computeAndDisplayHash, copyHashToClipboard, resetHashDisplay };
