"use strict";

import { md5, sha1 } from "@noble/hashes/legacy";
import { sha224, sha256 } from "@noble/hashes/sha256";
import { sha384, sha512, sha512_224, sha512_256 } from "@noble/hashes/sha512";
import type { CHash } from "@noble/hashes/utils";
import { bufferToHex } from "../binary-utils.js";

type HashAlgorithmId =
  "md5" | "sha1" | "sha224" | "sha256" | "sha384" | "sha512" |
  "sha512224" | "sha512256";

type NativeHashAlgorithmOption = {
  id: HashAlgorithmId;
  label: string;
  nativeAlgorithm: AlgorithmIdentifier;
};

type FallbackHashId = HashAlgorithmId;

type FallbackHashAlgorithmOption = {
  id: FallbackHashId;
  label: string;
};

type HashAlgorithmOption = NativeHashAlgorithmOption | FallbackHashAlgorithmOption;

type HashControls = {
  label: string;
  valueElement: HTMLElement;
  buttonElement: HTMLButtonElement;
  copyButtonElement: HTMLButtonElement;
  nativeHashBadgeElement?: HTMLButtonElement | undefined;
};

type FileDigest = {
  value: Uint8Array;
  usedNativeFallback: boolean;
};

const HASH_ALGORITHMS: readonly HashAlgorithmOption[] = [
  { id: "md5", label: "MD5" },
  { id: "sha1", label: "SHA-1", nativeAlgorithm: "SHA-1" },
  { id: "sha224", label: "SHA-224" },
  { id: "sha256", label: "SHA-256", nativeAlgorithm: "SHA-256" },
  { id: "sha384", label: "SHA-384", nativeAlgorithm: "SHA-384" },
  { id: "sha512", label: "SHA-512", nativeAlgorithm: "SHA-512" },
  { id: "sha512224", label: "SHA-512/224" },
  { id: "sha512256", label: "SHA-512/256" }
] as const;

const FALLBACK_HASHES: Readonly<Record<FallbackHashId, CHash>> = {
  md5,
  sha1,
  sha224,
  sha256,
  sha384,
  sha512,
  sha512224: sha512_224,
  sha512256: sha512_256
};

const resetHashDisplay = (...controls: HashControls[]): void => {
  for (const control of controls) {
    control.valueElement.textContent = "";
    control.copyButtonElement.hidden = true;
    if (control.nativeHashBadgeElement) {
      control.nativeHashBadgeElement.textContent = "🍃";
      control.nativeHashBadgeElement.setAttribute(
        "aria-label",
        "Show hashing method: native browser crypto is tried first."
      );
    }
    control.buttonElement.hidden = false;
    control.buttonElement.disabled = false;
    control.buttonElement.textContent = `Compute ${control.label}`;
  }
};

const computeFallbackFileDigest = async (
  digest: CHash,
  file: File
): Promise<Uint8Array> => {
  const hash = digest.create();
  const reader = file.stream().getReader();
  try {
    let result = await reader.read();
    while (!result.done) {
      hash.update(result.value);
      result = await reader.read();
    }
    return hash.digest();
  } finally {
    reader.releaseLock();
  }
};

const computeNativeFileDigest = async (
  nativeAlgorithm: AlgorithmIdentifier,
  file: File
): Promise<Uint8Array> => new Uint8Array(
  await crypto.subtle.digest(nativeAlgorithm, await file.arrayBuffer())
);

// Measured on 2026-06-20 in Chrome 149 on Windows: File.arrayBuffer() accepted
// 2,145,386,496 bytes (0x7fe00000, 2046 MiB) and rejected one byte more.
// SHA-256 at that size did not complete before the DevTools protocol timed out.
// See Chromium issue 40055619: https://issues.chromium.org/issues/40055619
// Do not turn this observation into a size oracle; only the actual read error opts in.
const isNativeReadFailure = (error: unknown): boolean =>
  error instanceof DOMException && error.name === "NotReadableError";

const getWorkerDigest = (value: unknown): Uint8Array | null => {
  if (!value || typeof value !== "object") return null;
  const result = value as { digest?: unknown };
  return result.digest instanceof ArrayBuffer ? new Uint8Array(result.digest) : null;
};

const getWorkerError = (value: unknown): string => {
  if (!value || typeof value !== "object") return "Fallback hash failed.";
  const result = value as { error?: unknown };
  return typeof result.error === "string" ? result.error : "Fallback hash failed.";
};

const computeWorkerFallbackDigest = (
  algorithmId: FallbackHashId,
  file: File
): Promise<Uint8Array> => new Promise((resolve, reject) => {
  const worker = new Worker(
    new URL("./hash-fallback-worker.ts", import.meta.url),
    { type: "module" }
  );
  worker.addEventListener("error", () => {
    worker.terminate();
    reject(new Error("Fallback hash worker failed."));
  }, { once: true });
  worker.addEventListener("message", event => {
    worker.terminate();
    const digest = getWorkerDigest(event.data);
    if (digest) {
      resolve(digest);
      return;
    }
    reject(new Error(getWorkerError(event.data)));
  }, { once: true });
  worker.postMessage({ algorithmId, file });
});

const computeFallbackDigest = (
  algorithmId: FallbackHashId,
  file: File
): Promise<Uint8Array> =>
  typeof Worker === "undefined"
    ? computeFallbackFileDigest(FALLBACK_HASHES[algorithmId], file)
    : computeWorkerFallbackDigest(algorithmId, file);

const computeNativeDigestWithFallback = async (
  algorithm: NativeHashAlgorithmOption,
  file: File
): Promise<FileDigest> => {
  try {
    return {
      value: await computeNativeFileDigest(algorithm.nativeAlgorithm, file),
      usedNativeFallback: false
    };
  } catch (error) {
    if (!isNativeReadFailure(error)) throw error;
    return { value: await computeFallbackDigest(algorithm.id, file), usedNativeFallback: true };
  }
};

const computeFileDigest = async (
  algorithm: HashAlgorithmOption,
  file: File
): Promise<FileDigest> => "nativeAlgorithm" in algorithm
  ? computeNativeDigestWithFallback(algorithm, file)
  : { value: await computeFallbackDigest(algorithm.id, file), usedNativeFallback: false };

const computeAndDisplayHash = async (
  algorithm: HashAlgorithmOption,
  file: File | null,
  { valueElement, buttonElement, copyButtonElement, nativeHashBadgeElement }: HashControls,
  canDisplayResult: () => boolean = (): boolean => true
): Promise<void> => {
  if (!file) {
    valueElement.textContent = "No file selected.";
    return;
  }
  buttonElement.disabled = true;
  buttonElement.textContent = "Working...";
  try {
    const digest = await computeFileDigest(algorithm, file);
    if (!canDisplayResult()) return;
    valueElement.textContent = bufferToHex(digest.value);
    if (nativeHashBadgeElement && digest.usedNativeFallback) {
      nativeHashBadgeElement.textContent = "🍃↪";
      nativeHashBadgeElement.setAttribute(
        "aria-label",
        "Show hashing method: native browser crypto could not read the file."
      );
    }
    copyButtonElement.hidden = false;
    buttonElement.hidden = true;
  } catch (error) {
    if (!canDisplayResult()) return;
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

export type { HashAlgorithmOption, HashControls };
export { HASH_ALGORITHMS, computeAndDisplayHash, copyHashToClipboard, resetHashDisplay };
