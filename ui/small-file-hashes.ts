import { computeAndDisplayHash, type HashAlgorithmControls } from "./hash-controls.js";

// UI policy: all eight hashes took 20–42ms for 64 KiB in fresh Chrome contexts,
// including 4x CPU throttling. This is a conservative local measurement, not a device guarantee.
const AUTOMATIC_HASH_SIZE_LIMIT = 64 * 1024;

const supportsAutomaticHashes = (size: number): boolean =>
  Number.isSafeInteger(size) && size >= 0 && size <= AUTOMATIC_HASH_SIZE_LIMIT;

const reportAutomaticFailure = (
  pending: readonly HashAlgorithmControls[], status: HTMLElement, error: unknown
): void => {
  for (const control of pending) {
    control.buttonElement.disabled = false;
    control.buttonElement.textContent = "Retry";
  }
  status.dataset["state"] = "failed";
  status.textContent = `Automatic hashes failed: ${error instanceof Error ? error.message : String(error)}`;
};

export const computeSmallFileHashes = async (
  file: File, controls: readonly HashAlgorithmControls[], isCurrent: () => boolean, status: HTMLElement
): Promise<void> => {
  if (!supportsAutomaticHashes(file.size)) return;
  const pending = controls.filter(control => !control.valueElement.textContent && !control.buttonElement.disabled);
  if (!pending.length || !isCurrent()) return;
  for (const control of pending) {
    control.buttonElement.disabled = true;
    control.buttonElement.textContent = "Working...";
  }
  try {
    // Read the original file once; individual algorithms share this bounded memory snapshot.
    const bytes = await file.arrayBuffer();
    if (!isCurrent()) return;
    if (bytes.byteLength !== file.size) throw new Error("Incomplete file read.");
    const snapshot = new File([bytes], file.name, { type: file.type });
    await Promise.all(pending.map(control => computeAndDisplayHash(
      control.algorithm, snapshot, control, isCurrent)));
  } catch (error) {
    if (!isCurrent()) return;
    reportAutomaticFailure(pending, status, error);
  }
};
