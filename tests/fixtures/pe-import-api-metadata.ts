"use strict";

import type { WinapiMetadataEntry } from "../../winapi-metadata-schema.js";
import type { UcrtMetadataEntry } from "../../ucrt-metadata-schema.js";

export const createWinapiImportMetadataEntry = (
  module: string,
  entrypoint: string,
  namespace = "Windows.Win32.System.Threading"
): WinapiMetadataEntry => ({
  sourceKind: "winapi",
  id: `MethodDef:${module}:${entrypoint}`,
  module,
  entrypoint,
  namespace,
  api: entrypoint,
  signature: `void ${entrypoint}(u4 milliseconds)`,
  returnType: "void",
  rawReturnType: "void",
  parameters: [{
    name: "milliseconds",
    type: "u4",
    rawType: "u4",
    direction: "in",
    x86StackBytes: 4
  }],
  callingConvention: "winapi",
  variadic: false,
  noReturn: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: ["windows5.1.2600"]
});

export const createUcrtImportMetadataEntry = (module: string, entrypoint: string): UcrtMetadataEntry => ({
  sourceKind: "ucrt",
  id: `UCRT:${module}:${entrypoint}`,
  module,
  entrypoint,
  namespace: "UCRT.stdio",
  api: entrypoint,
  signature: `int ${entrypoint}(const char * format, ...)`,
  returnType: "int",
  rawReturnType: "int",
  parameters: [{
    name: "format",
    type: "const char *",
    rawType: "const char *",
    direction: "in",
    x86StackBytes: 4
  }],
  callingConvention: "cdecl",
  variadic: true,
  noReturn: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: []
});
