"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { createElfDisassemblyController } from "./elf-disassembly.js";
import {
  refreshElfInstructionSetsPanel,
  refreshPeEntrypointDisassemblyPanel,
  refreshPeInstructionSetsPanel,
  refreshPeOverlayPanel
} from "./analysis-panel-refresh.js";
import { createPeDisassemblyController } from "./pe-disassembly.js";
import { createPeEntrypointDisassemblyController } from "./pe-entrypoint-disassembly.js";
import { createPeOverlayScanActions } from "./pe-overlay-scan.js";

export const createAnalysisPanelActions = (
  getCurrentFile: () => File | null,
  getCurrentParseResult: () => ParseForUiResult,
  setStatusMessage: (message: string | null | undefined) => void
) => ({
  peDisassembly: createPeDisassemblyController({
    getCurrentFile,
    getCurrentParseResult,
    renderPanel: refreshPeInstructionSetsPanel
  }),
  peEntrypointDisassembly: createPeEntrypointDisassemblyController({
    getCurrentFile,
    getCurrentParseResult,
    renderPanel: refreshPeEntrypointDisassemblyPanel
  }),
  peOverlayScan: createPeOverlayScanActions({
    getCurrentFile,
    getCurrentParseResult,
    renderPanel: refreshPeOverlayPanel,
    setStatusMessage
  }),
  elfDisassembly: createElfDisassemblyController({
    getCurrentFile,
    getCurrentParseResult,
    renderPanel: refreshElfInstructionSetsPanel
  })
});
