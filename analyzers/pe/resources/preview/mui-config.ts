"use strict";

import {
  parseMuiResourceConfigurationDetailed,
  type MuiResourceConfigurationParseResult
} from "../mui-config.js";
import type { ResourcePreviewResult } from "./types.js";

export const createMuiConfigPreview = (
  result: MuiResourceConfigurationParseResult
): ResourcePreviewResult => ({
  ...(result.configuration
    ? {
        preview: {
          previewKind: "muiConfig",
          muiConfig: result.configuration
        }
      }
    : {}),
  ...(result.issues.length ? { issues: result.issues } : {})
});

export const addMuiConfigPreview = (
  data: Uint8Array,
  typeName: string
): ResourcePreviewResult | null =>
  typeName === "MUI"
    ? createMuiConfigPreview(parseMuiResourceConfigurationDetailed(data))
    : null;
