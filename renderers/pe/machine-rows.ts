"use strict";

import { hex } from "../../binary-utils.js";
import { renderDefinitionRow, renderOptionChips } from "../../html-utils.js";
import { IMAGE_FILE_MACHINE_TYPES } from "../../analyzers/coff/machine.js";
import {
  decodePeMachine,
  getReadyToRunOsOverride,
  READY_TO_RUN_OS_OVERRIDE_OPTIONS
} from "../../analyzers/pe/machine.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

export const renderMachineRows = (pe: PeParseResult, out: string[]): void => {
  const decoded = decodePeMachine(pe.coff.Machine);
  out.push(renderDefinitionRow(
    "Machine",
    renderOptionChips(decoded.machine, IMAGE_FILE_MACHINE_TYPES),
    "Target CPU architecture after decoding any .NET ReadyToRun OS override."
  ));
  const override = getReadyToRunOsOverride(pe.coff.Machine);
  if (override == null) return;
  out.push(renderDefinitionRow(
    "Raw Machine",
    hex(pe.coff.Machine, 4),
    "Raw IMAGE_FILE_HEADER.Machine value stored in the file."
  ));
  out.push(renderDefinitionRow(
    "R2R OS override",
    renderOptionChips(override, READY_TO_RUN_OS_OVERRIDE_OPTIONS),
    ".NET ReadyToRun encodes the target OS as Machine XOR OS override."
  ));
};
