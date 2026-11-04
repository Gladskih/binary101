import { addDrawingNode, metafileColor, selectDrawingObject, restoreDrawingState } from "./metafile-drawing.js";
import type { MetafileDrawing, DrawingObject } from "./metafile-drawing.js";

const addObject = (drawing: MetafileDrawing, object: DrawingObject): void => {
  // WMF allocates the first free object-table slot (MS-WMF 2.1.4 Object Table).
  let handle = drawing.nextHandle;
  if (drawing.freeHandles.size) {
    handle = Math.min(...drawing.freeHandles); drawing.freeHandles.delete(handle);
  } else drawing.nextHandle += 1;
  if (handle > 0x7fff) { drawing.issues.push("WMF object table exceeds selectable handles."); return; }
  drawing.objects.set(handle, object);
};

const rectangle = (view: DataView, drawing: MetafileDrawing, type: number): void => {
  const bottom = view.getInt16(6, true), right = view.getInt16(8, true);
  const top = view.getInt16(10, true), left = view.getInt16(12, true);
  if (right < left || bottom < top) { drawing.issues.push("WMF shape has reversed bounds."); return; }
  if (type === 0x041b) addDrawingNode(drawing, "rect", { x: left, y: top,
    width: right - left, height: bottom - top });
  else addDrawingNode(drawing, "ellipse", { cx: (left + right) / 2, cy: (top + bottom) / 2,
    rx: (right - left) / 2, ry: (bottom - top) / 2 });
};

const points = (view: DataView, drawing: MetafileDrawing, type: number): void => {
  const count = view.getUint16(6, true);
  if (count > (view.byteLength - 8) / 4) { drawing.issues.push("WMF point array is truncated."); return; }
  const coordinates: string[] = [];
  for (let index = 0; index < count; index += 1) {
    coordinates.push(`${view.getInt16(8 + index * 4, true)},${view.getInt16(10 + index * 4, true)}`);
  }
  addDrawingNode(drawing, type === 0x0324 ? "polygon" : "polyline", { points: coordinates.join(" "),
    ...(type === 0x0324 ? {} : { fill: "none" }) });
};

const outputText = (view: DataView, drawing: MetafileDrawing): void => {
  const count = view.getUint16(6, true);
  const end = 8 + count + count % 2;
  if (end + 4 > view.byteLength) { drawing.issues.push("WMF text is truncated."); return; }
  addDrawingNode(drawing, "text", { x: view.getInt16(end + 2, true), y: view.getInt16(end, true) },
    new TextDecoder("windows-1252").decode(new Uint8Array(view.buffer, view.byteOffset + 8, count)));
  drawing.issues.push("WMF ANSI text uses a Windows-1252 approximation.");
};

type RecordDecoder = (view: DataView, drawing: MetafileDrawing) => void;
const pair = (view: DataView): [number, number] => [view.getInt16(8, true), view.getInt16(6, true)];
const line: RecordDecoder = (view, drawing) => {
  const point = pair(view);
  addDrawingNode(drawing, "line", { x1: drawing.current.position[0], y1: drawing.current.position[1],
    x2: point[0], y2: point[1], fill: "none" }); drawing.current.position = point;
};
const brush: RecordDecoder = (view, drawing) => {
  const style = view.getUint16(6, true);
  if (style > 1) drawing.issues.push("WMF patterned brush is approximated as a solid color.");
  addObject(drawing, { kind: "brush", style, color: metafileColor(view.getUint32(8, true)) });
};
const decoders = new Map<number, { minimum: number; draw: RecordDecoder }>([
  [0, { minimum: 6, draw: () => {} }],
  ...[0x0324, 0x0325].map(type => [type, { minimum: 8,
    draw: (view, drawing) => points(view, drawing, type) }] as [number, {minimum: number; draw: RecordDecoder}]),
  ...[0x0418, 0x041b].map(type => [type, { minimum: 14,
    draw: (view, drawing) => rectangle(view, drawing, type) }] as [number, {minimum: number; draw: RecordDecoder}]),
  [0x001e, { minimum: 6, draw: (_view, drawing) => { drawing.saved.push({ ...drawing.current }); } }],
  [0x0103, { minimum: 8, draw: (view, drawing) => { drawing.current.mapMode = view.getInt16(6, true); } }],
  [0x0127, { minimum: 8, draw: (view, drawing) => restoreDrawingState(drawing, view.getInt16(6, true)) }],
  [0x012d, { minimum: 8, draw: (view, drawing) => {
    const handle = view.getUint16(6, true);
    selectDrawingObject(drawing, handle & 0x8000 ? 0x80000000 + (handle & 0x7fff) : handle); } }],
  [0x01f0, { minimum: 8, draw: (view, drawing) => {
    const handle = view.getUint16(6, true);
    if (drawing.objects.delete(handle)) drawing.freeHandles.add(handle); } }],
  [0x0209, { minimum: 10, draw: (view, drawing) => {
    drawing.current.textColor = metafileColor(view.getUint32(6, true)); } }],
  [0x02fa, { minimum: 16, draw: (view, drawing) => {
    addObject(drawing, { kind: "pen", style: view.getUint16(6, true),
      width: view.getInt16(8, true), color: metafileColor(view.getUint32(12, true)) }); } }],
  [0x02fc, { minimum: 14, draw: brush }],
  [0x020b, { minimum: 10, draw: (view, drawing) => { drawing.current.windowOrigin = pair(view); } }],
  [0x020c, { minimum: 10, draw: (view, drawing) => { drawing.current.windowExtent = pair(view); } }],
  [0x020d, { minimum: 10, draw: (view, drawing) => { drawing.current.viewportOrigin = pair(view); } }],
  [0x020e, { minimum: 10, draw: (view, drawing) => { drawing.current.viewportExtent = pair(view); } }],
  [0x0214, { minimum: 10, draw: (view, drawing) => { drawing.current.position = pair(view); } }],
  [0x0213, { minimum: 10, draw: line }], [0x0521, { minimum: 8, draw: outputText }]
]);

export const renderWmfRecord = (view: DataView, drawing: MetafileDrawing): void => {
  if (view.byteLength < 6) { drawing.issues.push("WMF record header is truncated."); return; }
  const type = view.getUint16(4, true);
  const decoder = decoders.get(type);
  if (!decoder) { drawing.omitted.add(type); return; }
  if (view.byteLength < decoder.minimum) { drawing.issues.push(`WMF record ${type} is truncated.`); return; }
  decoder.draw(view, drawing);
};
