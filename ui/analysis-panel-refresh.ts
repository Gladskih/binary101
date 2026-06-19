"use strict";

import type { ElfParseResult } from "../analyzers/elf/types.js";
import type { PeParseResult, PeWindowsParseResult } from "../analyzers/pe/index.js";
import {
  ELF_INSTRUCTION_SETS_PANEL_ID,
  renderInstructionSetsPanel as renderElfInstructionSetsPanel
} from "../renderers/elf/disassembly.js";
import {
  PE_INSTRUCTION_SETS_PANEL_ID,
  renderInstructionSetsPanel as renderPeInstructionSetsPanel
} from "../renderers/pe/disassembly.js";
import {
  PE_ENTRYPOINT_DISASSEMBLY_PANEL_ID,
  renderEntrypointDisassemblyPanel
} from "../renderers/pe/entrypoint-disassembly.js";
import { PE_OVERLAY_PANEL_ID, renderOverlayPanel } from "../renderers/pe/overlay.js";
import { enhanceAccessibleTooltips } from "./accessible-tooltips.js";
import { captureOpenDetails, restoreOpenDetails } from "./details-open-state.js";
import { enhanceSortableTables } from "./sortable-tables.js";

const replaceAnalysisPanel = (panelId: string, markup: string): void => {
  const panel = document.getElementById(panelId);
  if (!(panel instanceof HTMLElement)) return;
  const openDetails = captureOpenDetails(panel);
  panel.outerHTML = markup;
  const updatedPanel = document.getElementById(panelId);
  if (!(updatedPanel instanceof HTMLElement)) return;
  enhanceSortableTables(updatedPanel);
  enhanceAccessibleTooltips(updatedPanel);
  restoreOpenDetails(updatedPanel, openDetails, () => {});
};

export const refreshPeInstructionSetsPanel = (pe: PeWindowsParseResult): void =>
  replaceAnalysisPanel(PE_INSTRUCTION_SETS_PANEL_ID, renderPeInstructionSetsPanel(pe));

export const refreshPeEntrypointDisassemblyPanel = (pe: PeWindowsParseResult): void =>
  replaceAnalysisPanel(PE_ENTRYPOINT_DISASSEMBLY_PANEL_ID, renderEntrypointDisassemblyPanel(pe));

export const refreshPeOverlayPanel = (pe: PeParseResult): void =>
  replaceAnalysisPanel(PE_OVERLAY_PANEL_ID, renderOverlayPanel(pe));

export const refreshElfInstructionSetsPanel = (elf: ElfParseResult): void =>
  replaceAnalysisPanel(ELF_INSTRUCTION_SETS_PANEL_ID, renderElfInstructionSetsPanel(elf));
