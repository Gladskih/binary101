"use strict";

export const UCRT_METADATA_PACKAGE_VERSION = "10.0.28000.1839";

export const UCRT_METADATA_PACKAGES = {
  headers: {
    name: "Microsoft.Windows.SDK.CPP",
    version: UCRT_METADATA_PACKAGE_VERSION,
    headerRoot: "c/Include/10.0.28000.0",
    ucrtHeaderRoot: "c/Include/10.0.28000.0/ucrt",
    sharedHeaderRoot: "c/Include/10.0.28000.0/shared"
  },
  importLibrary: {
    name: "Microsoft.Windows.SDK.CPP.x64",
    version: UCRT_METADATA_PACKAGE_VERSION,
    architecture: "x64",
    path: "c/ucrt/x64/ucrt.lib"
  },
  flatContainerBaseUrl: "https://api.nuget.org/v3-flatcontainer"
} as const;

export const UCRT_METADATA_OUTPUT_DIR = "public/ucrt-metadata";

export const UCRT_METADATA_CACHE_DIR = "node_modules/.cache/binary101-ucrt-metadata";
