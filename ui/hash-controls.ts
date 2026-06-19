"use strict";

import { md5 } from "@noble/hashes/legacy";
import { sha224 } from "@noble/hashes/sha256";
import { sha512_224, sha512_256 } from "@noble/hashes/sha512";
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

type FallbackHashAlgorithmOption = {
  id: HashAlgorithmId;
  label: string;
  digest: CHash;
};

type HashAlgorithmOption = NativeHashAlgorithmOption | FallbackHashAlgorithmOption;

type HashControls = {
  label: string;
  valueElement: HTMLElement;
  buttonElement: HTMLButtonElement;
  copyButtonElement: HTMLButtonElement;
};

const HASH_ALGORITHMS: readonly HashAlgorithmOption[] = [
  { id: "md5", label: "MD5", digest: md5 },
  { id: "sha1", label: "SHA-1", nativeAlgorithm: "SHA-1" },
  { id: "sha224", label: "SHA-224", digest: sha224 },
  { id: "sha256", label: "SHA-256", nativeAlgorithm: "SHA-256" },
  { id: "sha384", label: "SHA-384", nativeAlgorithm: "SHA-384" },
  { id: "sha512", label: "SHA-512", nativeAlgorithm: "SHA-512" },
  { id: "sha512224", label: "SHA-512/224", digest: sha512_224 },
  { id: "sha512256", label: "SHA-512/256", digest: sha512_256 }
] as const;

const resetHashDisplay = (...controls: HashControls[]): void => {
  for (const control of controls) {
    control.valueElement.textContent = "";
    control.copyButtonElement.hidden = true;
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

const computeFileDigest = (algorithm: HashAlgorithmOption, file: File): Promise<Uint8Array> =>
  "nativeAlgorithm" in algorithm
    ? computeNativeFileDigest(algorithm.nativeAlgorithm, file)
    : computeFallbackFileDigest(algorithm.digest, file);

const computeAndDisplayHash = async (
  algorithm: HashAlgorithmOption,
  file: File | null,
  { valueElement, buttonElement, copyButtonElement }: HashControls,
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
    valueElement.textContent = bufferToHex(digest);
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
