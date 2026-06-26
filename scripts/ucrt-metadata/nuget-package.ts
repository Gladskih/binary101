"use strict";

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { extractZipEntry, listZipEntries } from "../winapi-metadata/zip-entry.js";
import { UCRT_METADATA_CACHE_DIR, UCRT_METADATA_PACKAGES } from "./config.js";

interface NugetPackageRef {
  name: string;
  version: string;
}

const packageIdForUrl = (packageName: string): string => packageName.toLowerCase();

const packageFileName = (packageRef: NugetPackageRef): string =>
  `${packageIdForUrl(packageRef.name)}.${packageRef.version}.nupkg`;

const packageUrl = (packageRef: NugetPackageRef): string =>
  `${UCRT_METADATA_PACKAGES.flatContainerBaseUrl}/${packageIdForUrl(packageRef.name)}/` +
  `${packageRef.version}/${packageFileName(packageRef)}`;

const packageCachePath = (packageRef: NugetPackageRef): string =>
  join(UCRT_METADATA_CACHE_DIR, packageFileName(packageRef));

const readCachedPackage = async (packageRef: NugetPackageRef): Promise<Uint8Array | null> => {
  try {
    return await readFile(packageCachePath(packageRef));
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return null;
    throw error;
  }
};

const downloadPackage = async (packageRef: NugetPackageRef): Promise<Uint8Array> => {
  const response = await fetch(packageUrl(packageRef));
  if (!response.ok) {
    throw new Error(`${packageRef.name} download failed with HTTP ${response.status}.`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  await mkdir(UCRT_METADATA_CACHE_DIR, { recursive: true });
  await writeFile(packageCachePath(packageRef), bytes);
  return bytes;
};

const readPackage = async (packageRef: NugetPackageRef): Promise<Uint8Array> =>
  await readCachedPackage(packageRef) ?? await downloadPackage(packageRef);

export const readUcrtHeaderPackage = async (): Promise<Uint8Array> =>
  readPackage(UCRT_METADATA_PACKAGES.headers);

export const readUcrtImportLibrary = async (): Promise<Uint8Array> =>
  extractZipEntry(
    await readPackage(UCRT_METADATA_PACKAGES.importLibrary),
    UCRT_METADATA_PACKAGES.importLibrary.path
  );

export const listUcrtHeaderEntries = (packageBytes: Uint8Array): string[] =>
  listZipEntries(packageBytes).filter(entry =>
    entry.startsWith(`${UCRT_METADATA_PACKAGES.headers.ucrtHeaderRoot}/`) ||
    entry.startsWith(`${UCRT_METADATA_PACKAGES.headers.sharedHeaderRoot}/`));

export const extractUcrtPackageEntry = (
  packageBytes: Uint8Array,
  entryName: string
): Uint8Array => extractZipEntry(packageBytes, entryName);
