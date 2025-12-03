"use strict";

import type { Mp3ParseResult, Mp3SuccessResult } from "./mp3/types.js";

const isValidatedMp3 = (
  mp3: Mp3ParseResult | null | undefined
): mp3 is Mp3SuccessResult =>
  Boolean(mp3?.isMp3 === true && mp3?.mpeg?.firstFrame && mp3?.mpeg.secondFrameValidated === true);

const isShortMp3WithoutSecond = (
  mp3: Mp3ParseResult | null | undefined
): mp3 is Mp3SuccessResult => {
  if (
    !mp3 ||
    mp3.isMp3 !== true ||
    !mp3.mpeg?.firstFrame ||
    mp3.mpeg.secondFrameValidated !== false
  ) {
    return false;
  }
  const warnings = mp3.warnings;
  if (!Array.isArray(warnings) || warnings.length !== 1) return false;
  const [onlyWarning] = warnings;
  return typeof onlyWarning === "string" && onlyWarning.indexOf("cannot be validated (file too small)") !== -1;
};

const buildMp3Label = (mp3: Mp3ParseResult | null | undefined): string | null => {
  if (!mp3?.mpeg?.firstFrame) return null;
  if (!isValidatedMp3(mp3) && !isShortMp3WithoutSecond(mp3)) return null;
  const info = mp3.mpeg.firstFrame;
  const parts: string[] = [];
  if (info.versionLabel) parts.push(info.versionLabel);
  if (info.layerLabel) parts.push(info.layerLabel);
  if (info.bitrateKbps) parts.push(`${info.bitrateKbps} kbps`);
  if (info.sampleRate) parts.push(`${info.sampleRate} Hz`);
  if (info.channelMode) parts.push(info.channelMode);
  return parts.length ? parts.join(", ") : "MPEG audio stream (MP3)";
};

export { buildMp3Label, isShortMp3WithoutSecond, isValidatedMp3 };
