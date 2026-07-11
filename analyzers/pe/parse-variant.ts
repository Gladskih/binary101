"use strict";

import {
  parseDynamicRelocationsFromLoadConfig32,
  parseDynamicRelocationsFromLoadConfig64
} from "./dynamic-relocations/index.js";
import { parseTlsDirectory32, parseTlsDirectory64 } from "./directories/tls.js";
import { parseDelayImports32, parseDelayImports64 } from "./imports/delay.js";
import { parseImportDirectory32, parseImportDirectory64 } from "./imports/index.js";
import { createLoadConfigEnricher } from "./load-config/enrich.js";
import { parseLoadConfigDirectory32, parseLoadConfigDirectory64 } from "./load-config/index.js";
import { readSafeSehHandlerTable } from "./load-config/tables.js";
import {
  PE32_POINTER_BYTES,
  PE32_PLUS_POINTER_BYTES
} from "./load-config/reference-reader.js";
import { IMAGE_FILE_MACHINE_I386 } from "../coff/machine.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "./optional-header/magic.js";

export type PeVariantParsers = {
  parseAndEnrichLoadConfig: ReturnType<typeof createLoadConfigEnricher>;
  parseImportDirectory: typeof parseImportDirectory32;
  parseTlsDirectory: typeof parseTlsDirectory32;
  parseDelayImports: typeof parseDelayImports32;
};

export const selectPeVariantParsers = (
  optionalHeaderMagic: number,
  canonicalMachine: number
): PeVariantParsers =>
  optionalHeaderMagic === PE32_PLUS_OPTIONAL_HEADER_MAGIC
    ? {
        parseAndEnrichLoadConfig: createLoadConfigEnricher(
          parseLoadConfigDirectory64,
          parseDynamicRelocationsFromLoadConfig64,
          null,
          PE32_PLUS_POINTER_BYTES
        ),
        parseImportDirectory: parseImportDirectory64,
        parseTlsDirectory: parseTlsDirectory64,
        parseDelayImports: parseDelayImports64
      }
    : {
        parseAndEnrichLoadConfig: createLoadConfigEnricher(
          parseLoadConfigDirectory32,
          parseDynamicRelocationsFromLoadConfig32,
          // Microsoft PE format: SafeSEH applies only to IMAGE_FILE_MACHINE_I386 PE32 images.
          canonicalMachine === IMAGE_FILE_MACHINE_I386 ? readSafeSehHandlerTable : null,
          PE32_POINTER_BYTES
        ),
        parseImportDirectory: parseImportDirectory32,
        parseTlsDirectory: parseTlsDirectory32,
        parseDelayImports: parseDelayImports32
      };
