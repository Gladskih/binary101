"use strict";

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { extractZipEntry } from "./zip-entry.js";
import { WINAPI_METADATA_CACHE_DIR, WINAPI_METADATA_PACKAGE } from "./config.js";

const packageIdForUrl = WINAPI_METADATA_PACKAGE.name.toLowerCase();

const packageFileName = (): string =>
  `${packageIdForUrl}.${WINAPI_METADATA_PACKAGE.version}.nupkg`;

const packageUrl = (): string =>
  `${WINAPI_METADATA_PACKAGE.flatContainerBaseUrl}/${packageIdForUrl}/` +
  `${WINAPI_METADATA_PACKAGE.version}/${packageFileName()}`;

const packageCachePath = (): string =>
  join(WINAPI_METADATA_CACHE_DIR, packageFileName());

const readCachedPackage = async (): Promise<Uint8Array | null> => {
  try {
    return await readFile(packageCachePath());
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return null;
    throw error;
  }
};

const downloadPackage = async (): Promise<Uint8Array> => {
  const response = await fetch(packageUrl());
  if (!response.ok) {
    throw new Error(`NuGet package download failed with HTTP ${response.status}.`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  await mkdir(WINAPI_METADATA_CACHE_DIR, { recursive: true });
  await writeFile(packageCachePath(), bytes);
  return bytes;
};

export const readWinmdFromNugetPackage = async (): Promise<Uint8Array> => {
  const packageBytes = await readCachedPackage() ?? await downloadPackage();
  return extractZipEntry(packageBytes, WINAPI_METADATA_PACKAGE.winmdPath);
};
