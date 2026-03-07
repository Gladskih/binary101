"use strict";

import {
  formatBuildToolVersion,
  formatPackedVersion,
  formatSourceVersion
} from "../../analyzers/macho/format.js";
import { buildToolName, platformName, versionMinTargetName } from "../../analyzers/macho/load-command-info.js";

const buildPlatformLabel = (platform: number): string => platformName(platform) || `platform 0x${platform.toString(16)}`;
const buildToolLabel = (tool: number): string => buildToolName(tool) || `0x${tool.toString(16)}`;
const buildToolVersionText = (value: number): string => formatBuildToolVersion(value);
const packedVersionText = (value: number): string => formatPackedVersion(value);
const sourceVersionText = (value: bigint): string => formatSourceVersion(value);
const versionMinLabel = (command: number): string => versionMinTargetName(command);

export {
  buildPlatformLabel,
  buildToolLabel,
  buildToolVersionText,
  packedVersionText,
  sourceVersionText,
  versionMinLabel
};
