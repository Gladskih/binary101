import { addDrawingNode, metafileColor, selectDrawingObject, restoreDrawingState } from "./metafile-drawing.js";
import type { MetafileDrawing } from "./metafile-drawing.js";

// EMR_* values and layouts are from the Windows SDK wingdi.h and MS-EMF section 2.3.
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/wingdi.h
const rectangle = (view: DataView, drawing: MetafileDrawing, type: number): void => {
  const left = view.getInt32(8, true), top = view.getInt32(12, true);
  const width = view.getInt32(16, true) - left, height = view.getInt32(20, true) - top;
  if (width < 0 || height < 0) { drawing.issues.push("EMF shape has reversed bounds."); return; }
  if (type === 43) addDrawingNode(drawing, "rect", { x: left, y: top, width, height });
  else addDrawingNode(drawing, "ellipse", { cx: left + width / 2, cy: top + height / 2,
    rx: width / 2, ry: height / 2 });
};

const points = (view: DataView, drawing: MetafileDrawing, type: number): void => {
  const count = view.getUint32(24, true);
  const stride = type >= 85 ? 4 : 8;
  if (count > (view.byteLength - 28) / stride) { drawing.issues.push("EMF point array is truncated."); return; }
  const coordinates: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const offset = 28 + index * stride;
    coordinates.push(stride === 4 ? `${view.getInt16(offset, true)},${view.getInt16(offset + 2, true)}`
      : `${view.getInt32(offset, true)},${view.getInt32(offset + 4, true)}`);
  }
  addDrawingNode(drawing, type === 3 || type === 86 ? "polygon" : "polyline",
    { points: coordinates.join(" "), ...(type === 3 || type === 86 ? {} : { fill: "none" }) });
};

const outputText = (view: DataView, drawing: MetafileDrawing): void => {
  const count = view.getUint32(44, true), offset = view.getUint32(48, true);
  const options = view.getUint32(52, true);
  if (options & 0x10) { drawing.issues.push("EMF glyph-index text is not rendered."); return; }
  if (options) drawing.issues.push("EMF text clipping, background and layout options are approximated.");
  if (count === 0) return;
  if (offset < 76 || offset > view.byteLength || count > (view.byteLength - offset) / 2) {
    drawing.issues.push("EMF text range is invalid."); return;
  }
  addDrawingNode(drawing, "text", { x: view.getInt32(36, true), y: view.getInt32(40, true) },
    new TextDecoder("utf-16le").decode(new Uint8Array(view.buffer, view.byteOffset + offset, count * 2)));
};

type RecordDecoder = (view: DataView, drawing: MetafileDrawing) => void;
const pair = (view: DataView): [number, number] => [view.getInt32(8, true), view.getInt32(12, true)];
const line: RecordDecoder = (view, drawing) => {
  const point = pair(view);
  addDrawingNode(drawing, "line", { x1: drawing.current.position[0], y1: drawing.current.position[1],
    x2: point[0], y2: point[1], fill: "none" });
  drawing.current.position = point;
};
const brush: RecordDecoder = (view, drawing) => {
  const style = view.getUint32(12, true);
  if (style > 1) drawing.issues.push("EMF patterned brush is approximated as a solid color.");
  drawing.objects.set(view.getUint32(8, true), { kind: "brush", style,
    color: metafileColor(view.getUint32(16, true)) });
};
const world: RecordDecoder = (view, drawing) => {
  const matrix = Array.from({ length: 6 }, (_, index) => view.getFloat32(8 + index * 4, true));
  if (matrix.every(Number.isFinite)) drawing.current.world = matrix;
  else drawing.issues.push("EMF world transform is not finite.");
};
const decoders = new Map<number, { minimum: number; draw: RecordDecoder }>([
  [1, { minimum: 88, draw: () => {} }], [14, { minimum: 20, draw: () => {} }],
  ...[3, 4, 86, 87].map(type => [type, { minimum: 28,
    draw: (view, drawing) => points(view, drawing, type) }] as [number, {minimum: number; draw: RecordDecoder}]),
  ...[42, 43].map(type => [type, { minimum: 24,
    draw: (view, drawing) => rectangle(view, drawing, type) }] as [number, {minimum: number; draw: RecordDecoder}]),
  [9, { minimum: 16, draw: (view, drawing) => { drawing.current.windowExtent = pair(view); } }],
  [10, { minimum: 16, draw: (view, drawing) => { drawing.current.windowOrigin = pair(view); } }],
  [11, { minimum: 16, draw: (view, drawing) => { drawing.current.viewportExtent = pair(view); } }],
  [12, { minimum: 16, draw: (view, drawing) => { drawing.current.viewportOrigin = pair(view); } }],
  [17, { minimum: 12, draw: (view, drawing) => { drawing.current.mapMode = view.getInt32(8, true); } }],
  [24, { minimum: 12, draw: (view, drawing) => {
    drawing.current.textColor = metafileColor(view.getUint32(8, true)); } }],
  [27, { minimum: 16, draw: (view, drawing) => { drawing.current.position = pair(view); } }],
  [33, { minimum: 8, draw: (_view, drawing) => { drawing.saved.push({ ...drawing.current }); } }],
  [34, { minimum: 12, draw: (view, drawing) => restoreDrawingState(drawing, view.getInt32(8, true)) }],
  [35, { minimum: 32, draw: world }],
  [37, { minimum: 12, draw: (view, drawing) => selectDrawingObject(drawing, view.getUint32(8, true)) }],
  [38, { minimum: 28, draw: (view, drawing) => {
    drawing.objects.set(view.getUint32(8, true), { kind: "pen", style: view.getUint32(12, true) & 15,
      width: view.getInt32(16, true), color: metafileColor(view.getUint32(24, true)) }); } }],
  [39, { minimum: 24, draw: brush }],
  [40, { minimum: 12, draw: (view, drawing) => { drawing.objects.delete(view.getUint32(8, true)); } }],
  [54, { minimum: 16, draw: line }],
  [82, { minimum: 104, draw: (view, drawing) => {
    drawing.objects.set(view.getUint32(8, true), { kind: "font", height: view.getInt32(12, true),
      weight: view.getInt32(28, true), family: new TextDecoder("utf-16le").decode(
        new Uint8Array(view.buffer, view.byteOffset + 40, 64)).split("\0")[0] || "sans-serif" }); } }],
  [84, { minimum: 76, draw: outputText }]
]);

export const renderEmfRecord = (view: DataView, drawing: MetafileDrawing): void => {
  if (view.byteLength < 8) { drawing.issues.push("EMF record header is truncated."); return; }
  const type = view.getUint32(0, true);
  const decoder = decoders.get(type);
  if (!decoder) { drawing.omitted.add(type); return; }
  if (view.byteLength < decoder.minimum) { drawing.issues.push(`EMF record ${type} is truncated.`); return; }
  decoder.draw(view, drawing);
};
