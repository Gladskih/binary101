import type { SwfParseResult } from "../swf/types.js";
import { parseSwfRange } from "../swf/index.js";
import { createFileRangeReader } from "../file-range-reader.js";

// Footer/header evidence; publish as a payload only after isValidatedProjectorMovie succeeds.
export interface FlashProjector {
  start: number;
  end: number;
  swf: SwfParseResult;
  bodyReadError?: string;
}

const readProjectorRange = async (
  file: File, minimumOffset: number
): Promise<{ start: number; end: number } | null> => {
  const end = file.size - 8;
  const footer = await createFileRangeReader(file, end, 8).read(0, 8);
  // Windows Projector EOF convention; never scan for copies of this marker in arbitrary data.
  // https://github.com/laenion/dump_projector/blob/master/dump_projector.c
  if (footer.byteLength !== 8 || footer.getUint32(0, true) !== 0xfa123456) return null;
  const start = end - footer.getUint32(4, true);
  return start < minimumOffset || start >= end ? null : { start, end };
};

const hasMovie = (swf: SwfParseResult): boolean =>
  swf.movie != null && swf.movie.frameCount > 0 && swf.movie.frameRate > 0 &&
  swf.movie.xMax > swf.movie.xMin && swf.movie.yMax > swf.movie.yMin;

export const isValidatedProjectorMovie = (swf: SwfParseResult): boolean =>
  !swf.issues.length && hasMovie(swf) && swf.tagEnd === swf.fileLength;

const inspectProjector = async (file: File, minimumOffset: number): Promise<FlashProjector | null> => {
  const range = await readProjectorRange(file, minimumOffset);
  if (!range) return null;
  const swf = await parseSwfRange(file, range.start, range.end);
  if (!swf || swf.issues.length) return null;
  if (swf.signature === "ZWS") return { ...range, swf };
  if (!hasMovie(swf)) return null;
  if (swf.signature === "FWS" && !isValidatedProjectorMovie(swf)) return null;
  return { ...range, swf };
};

export const analyzeFlashProjector = async (
  file: File, minimumOffset: number
): Promise<FlashProjector | null> => {
  // Minimum FWS: fixed header (8), RECT (2), frame fields (4), End (2), plus Projector footer (8).
  // Adobe SWF v19, chapter 2: https://open-flash.github.io/mirrors/swf-spec-19.pdf
  if (!Number.isSafeInteger(minimumOffset) || minimumOffset < 0 || file.size - minimumOffset < 24) return null;
  return inspectProjector(file, minimumOffset).catch(() => null);
};
