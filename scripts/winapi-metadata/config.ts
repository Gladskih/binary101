"use strict";

export const WINAPI_METADATA_PACKAGE = {
  name: "Microsoft.Windows.SDK.Win32Metadata",
  version: "71.0.14-preview",
  winmdPath: "Windows.Win32.winmd",
  flatContainerBaseUrl: "https://api.nuget.org/v3-flatcontainer"
} as const;

export const WINAPI_METADATA_OUTPUT_DIR = "public/winapi-metadata";

export const WINAPI_METADATA_CACHE_DIR = "node_modules/.cache/binary101-winapi-metadata";
