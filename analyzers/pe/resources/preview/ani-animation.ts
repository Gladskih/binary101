import { hasPngSignature, readIconImageSpec, wrapAsIco } from "./icon.js";
import { makeDataUrl } from "./data-url.js";

export interface ResourceAnimation {
  frames: Array<{ url: string; hotspot?: { x: number; y: number } }>;
  sequence: number[];
  rates: number[];
  flags: number;
  defaultJiffies: number;
  declaredFrames: number;
  declaredSteps: number;
}

const imageRange = (view: DataView, offset: number, count: number): boolean => {
  const size = view.getUint32(offset + 8, true);
  const start = view.getUint32(offset + 12, true);
  return size > 0 && start >= 6 + count * 16 && start <= view.byteLength && size <= view.byteLength - start;
};

const validDirectory = (view: DataView, count: number): boolean =>
  view.getUint16(0, true) === 0 && [1, 2].includes(view.getUint16(2, true)) &&
  count > 0 && count <= (view.byteLength - 6) / 16;

const selectedFrameImage = (view: DataView, issues: string[]): number | null => {
  const count = view.getUint16(4, true);
  if (!validDirectory(view, count)) {
    issues.push("ANI frame has an invalid ICO/CUR directory."); return null;
  }
  let selected = 6;
  for (let index = 0; index < count; index += 1) {
    const offset = 6 + index * 16;
    if (!imageRange(view, offset, count)) {
      issues.push("ANI frame image range is invalid."); return null;
    }
    if ((view.getUint8(offset) || 256) > (view.getUint8(selected) || 256)) selected = offset;
  }
  return selected;
};

const frameImageUrl = (image: Uint8Array, view: DataView, offset: number): string => {
  if (hasPngSignature(image)) return makeDataUrl("image/png", image);
  const spec = readIconImageSpec(image, true);
  if (!spec) return "";
  return makeDataUrl("image/x-icon", wrapAsIco(image, view.getUint8(offset) || 256,
    view.getUint8(offset + 1) || 256, view.getUint8(offset + 2), 1, spec.bitCount));
};

const framePreview = (data: Uint8Array, issues: string[]): ResourceAnimation["frames"][number] | null => {
  if (data.length < 6) { issues.push("ANI frame directory is truncated."); return null; }
  const view = new DataView(data.buffer, data.byteOffset, data.length);
  const selected = selectedFrameImage(view, issues);
  if (selected === null) return null;
  const cursor = view.getUint16(2, true) === 2;
  const start = view.getUint32(selected + 12, true);
  const image = data.subarray(start, start + view.getUint32(selected + 8, true));
  const url = frameImageUrl(image, view, selected);
  if (!url) issues.push("ANI frame image is not a supported PNG or DIB.");
  return { url, ...(cursor ? { hotspot: { x: view.getUint16(selected + 4, true),
    y: view.getUint16(selected + 6, true) } } : {}) };
};

const readAnimationHeader = (view: DataView, animation: ResourceAnimation, issues: string[]): void => {
  if (view.byteLength < 36) { issues.push("ANI header is truncated."); return; }
  if (view.getUint32(0, true) !== 36) issues.push("ANI header structure size is invalid.");
  animation.declaredFrames = view.getUint32(4, true);
  animation.declaredSteps = view.getUint32(8, true);
  animation.defaultJiffies = view.getUint32(28, true);
  // AF_ICON=1, AF_SEQUENCE=2; Wine user32 cursoricon.c ANI loader.
  // https://gitlab.winehq.org/wine/wine/-/blob/master/dlls/user32/cursoricon.c
  animation.flags = view.getUint32(32, true);
  if (!(animation.flags & 1)) issues.push("ANI raw bitmap frames are unsupported.");
};

type ChunkRange = { offset: number; end: number; list: string };
const fourcc = (data: Uint8Array, offset: number): string =>
  String.fromCharCode(...data.subarray(offset, offset + 4));

const readTable = (view: DataView, values: number[], issues: string[]): void => {
  for (let at = 0; at + 4 <= view.byteLength; at += 4) values.push(view.getUint32(at, true));
  if (view.byteLength % 4) issues.push("ANI timing/sequence table has an incomplete DWORD.");
};

const readChunk = (data: Uint8Array, frame: ChunkRange, issues: string[]) => {
  const offset = frame.offset;
  if (frame.end - offset < 8) { issues.push("ANI chunk header is truncated."); return null; }
  const size = new DataView(data.buffer, data.byteOffset + offset, 8).getUint32(4, true);
  const start = offset + 8;
  if (size > frame.end - start) { issues.push(`ANI ${fourcc(data, offset)} chunk is truncated.`); return null; }
  frame.offset = start + size + size % 2;
  if (frame.offset > frame.end) issues.push("ANI chunk padding is truncated.");
  return { id: fourcc(data, offset), start, size };
};

const decodeAnimationChunk = (data: Uint8Array, chunk: { id: string; start: number; size: number },
  list: string, animation: ResourceAnimation, issues: string[]): number => {
  const { id, start, size } = chunk;
  const view = new DataView(data.buffer, data.byteOffset + start, size);
  if (id === "anih") { readAnimationHeader(view, animation, issues); return 1; }
    else if (id === "rate") readTable(view, animation.rates, issues);
    else if (id === "seq ") readTable(view, animation.sequence, issues);
    else if (id === "icon" && list === "fram") {
      // Preserve source frame numbering even when one frame cannot be displayed.
      animation.frames.push(framePreview(data.subarray(start, start + size), issues) ?? { url: "" });
    }
  return 0;
};

const readAnimationChunks = (data: Uint8Array, end: number, animation: ResourceAnimation, issues: string[]): void => {
  const stack: ChunkRange[] = [{ offset: 12, end, list: "ACON" }];
  let headers = 0;
  while (stack.length) {
    const frame = stack[stack.length - 1]!;
    if (frame.offset >= frame.end) { stack.pop(); continue; }
    const chunk = readChunk(data, frame, issues);
    if (!chunk) break;
    const { id, start, size } = chunk;
    if (id === "LIST") {
      if (size < 4) { issues.push("ANI LIST type is truncated."); break; }
      stack.push({ offset: start + 4, end: start + size, list: fourcc(data, start) });
    } else headers += decodeAnimationChunk(data, chunk, frame.list, animation, issues);
  }
  if (!headers) issues.push("ANI has no animation header.");
  if (headers > 1) issues.push("ANI has multiple animation headers.");
};

const checkAnimation = (animation: ResourceAnimation, issues: string[]): void => {
  if (animation.declaredFrames !== animation.frames.length) issues.push("ANI frame count differs from its frame list.");
  if (animation.sequence.some(index => index >= animation.frames.length)) issues.push("ANI sequence references a missing frame.");
  if (animation.flags & 2) {
    if (animation.sequence.length !== animation.declaredSteps) issues.push("ANI sequence length differs from its declared step count.");
  } else if (animation.sequence.length) issues.push("ANI sequence is unused because AF_SEQUENCE is absent.");
  if (animation.rates.length && animation.rates.length !== animation.declaredSteps) {
    issues.push("ANI rate length differs from its declared step count.");
  }
};

export const parseAniAnimation = (data: Uint8Array, issues: string[]): ResourceAnimation | null => {
  if (data.length < 12 || fourcc(data, 0) !== "RIFF" || fourcc(data, 8) !== "ACON") return null;
  const animation: ResourceAnimation = { frames: [], sequence: [], rates: [], flags: 0,
    defaultJiffies: 0, declaredFrames: 0, declaredSteps: 0 };
  const declaredEnd = new DataView(data.buffer, data.byteOffset, data.length).getUint32(4, true) + 8;
  if (declaredEnd !== data.length) issues.push("ANI RIFF size differs from its resource size.");
  readAnimationChunks(data, Math.min(data.length, declaredEnd), animation, issues);
  checkAnimation(animation, issues);
  return animation;
};
