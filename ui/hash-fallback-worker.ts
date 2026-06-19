"use strict";

import { md5 } from "@noble/hashes/legacy";
import { sha224 } from "@noble/hashes/sha256";
import { sha512_224, sha512_256 } from "@noble/hashes/sha512";
import type { CHash } from "@noble/hashes/utils";

type FallbackHashId = "md5" | "sha224" | "sha512224" | "sha512256";

type HashWorkerRequest = {
  algorithmId: FallbackHashId;
  file: File;
};

type HashWorkerResponse = { digest: ArrayBuffer } | { error: string };

type HashWorkerScope = {
  addEventListener: (type: "message", listener: (event: MessageEvent<unknown>) => void) => void;
  postMessage: (value: HashWorkerResponse) => void;
};

const FALLBACK_HASHES: Readonly<Record<FallbackHashId, CHash>> = {
  md5,
  sha224,
  sha512224: sha512_224,
  sha512256: sha512_256
};

const isFallbackHashId = (value: unknown): value is FallbackHashId =>
  typeof value === "string" && Object.hasOwn(FALLBACK_HASHES, value);

const isWorkerRequest = (value: unknown): value is HashWorkerRequest => {
  if (!value || typeof value !== "object") return false;
  const request = value as Partial<HashWorkerRequest>;
  return request.file instanceof File && isFallbackHashId(request.algorithmId);
};

const computeDigest = async ({ algorithmId, file }: HashWorkerRequest): Promise<Uint8Array> => {
  const hash = FALLBACK_HASHES[algorithmId].create();
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

const handleHashWorkerMessage = async (value: unknown): Promise<HashWorkerResponse> => {
  if (!isWorkerRequest(value)) return { error: "Invalid fallback hash request." };
  try {
    return { digest: (await computeDigest(value)).buffer as ArrayBuffer };
  } catch (error) {
    return { error: String(error) };
  }
};

const attachHashWorkerListener = (scope: HashWorkerScope): void => {
  scope.addEventListener("message", event => {
    void handleHashWorkerMessage(event.data).then(response => scope.postMessage(response));
  });
};

if (typeof self !== "undefined") {
  attachHashWorkerListener(self as unknown as HashWorkerScope);
}

export { attachHashWorkerListener, handleHashWorkerMessage };
