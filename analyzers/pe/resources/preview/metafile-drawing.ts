import type { ResourceVectorNode } from "./vector-types.js";

export type DrawingObject = { kind: "pen"; color: string; width: number; style: number }
  | { kind: "brush"; color: string; style: number }
  | { kind: "font"; family: string; height: number; weight: number };
export interface DrawingState {
  pen: Extract<DrawingObject, { kind: "pen" }>;
  brush: Extract<DrawingObject, { kind: "brush" }>;
  font: Extract<DrawingObject, { kind: "font" }>;
  mapMode: number;
  position: [number, number];
  textColor: string;
  windowOrigin: [number, number];
  windowExtent: [number, number];
  viewportOrigin: [number, number];
  viewportExtent: [number, number];
  world: number[];
}
export interface MetafileDrawing {
  current: DrawingState;
  saved: DrawingState[];
  objects: Map<number, DrawingObject>;
  nextHandle: number;
  freeHandles: Set<number>;
  nodes: ResourceVectorNode[];
  omitted: Set<number>;
  issues: string[];
}

export const createMetafileDrawing = (issues: string[]): MetafileDrawing => ({
  current: { pen: { kind: "pen", color: "#000000", width: 1, style: 0 },
    brush: { kind: "brush", color: "#ffffff", style: 0 },
    font: { kind: "font", family: "sans-serif", height: 12, weight: 400 },
    mapMode: 1, position: [0, 0], textColor: "#000000", windowOrigin: [0, 0], windowExtent: [1, 1],
    viewportOrigin: [0, 0], viewportExtent: [1, 1], world: [1, 0, 0, 1, 0, 0] },
  saved: [], objects: new Map(), nextHandle: 0, freeHandles: new Set(), nodes: [], omitted: new Set(), issues
});

export const metafileColor = (color: number): string =>
  `#${[color & 255, (color >>> 8) & 255, (color >>> 16) & 255]
    .map(value => value.toString(16).padStart(2, "0")).join("")}`;

const selectStockObject = (drawing: MetafileDrawing, stock: number): void => {
    if (stock <= 5) drawing.current.brush = { kind: "brush",
      color: ["#ffffff", "#c0c0c0", "#808080", "#404040", "#000000", "none"][stock]!,
      style: stock === 5 ? 1 : 0 };
    else if (stock >= 6 && stock <= 8) drawing.current.pen = { kind: "pen", width: 1,
      color: stock === 6 ? "#ffffff" : "#000000", style: stock === 8 ? 5 : 0 };
    else drawing.issues.push(`Metafile stock object ${stock} is not rendered.`);
};

export const selectDrawingObject = (drawing: MetafileDrawing, handle: number): void => {
  if ((handle & 0x80000000) !== 0) { selectStockObject(drawing, handle & 0x7fffffff); return; }
  const object = drawing.objects.get(handle);
  if (!object) { drawing.issues.push(`Metafile selects unknown object ${handle}.`); return; }
  if (object.kind === "pen") drawing.current.pen = object;
  else if (object.kind === "brush") drawing.current.brush = object;
  else drawing.current.font = object;
};

export const restoreDrawingState = (drawing: MetafileDrawing, level: number): void => {
  const index = level < 0 ? drawing.saved.length + level : level - 1;
  if (index < 0 || index >= drawing.saved.length) {
    drawing.issues.push(`Metafile restores unknown DC level ${level}.`); return;
  }
  drawing.current = drawing.saved[index]!;
  drawing.saved.length = index;
};

const drawingAttributes = (state: DrawingState, tag: string, values: Record<string, string | number>) => {
  const attributes: Record<string, string | number> = { fill: tag === "text" ? state.textColor :
    state.brush.style === 1 ? "none" : state.brush.color,
  stroke: tag === "text" || state.pen.style === 5 ? "none" : state.pen.color,
  "stroke-width": Math.max(1, Math.abs(state.pen.width)), ...values };
  if (state.pen.style > 0 && state.pen.style < 5) {
    attributes["stroke-dasharray"] = ["", "6 3", "1 2", "6 2 1 2", "6 2 1 2 1 2"][state.pen.style]!;
  }
  if (tag === "text") Object.assign(attributes, { "font-family": state.font.family,
    "font-size": Math.abs(state.font.height) || 12, "font-weight": state.font.weight });

  return attributes;
};

export const addDrawingNode = (
  drawing: MetafileDrawing, tag: string, values: Record<string, string | number>, text: string | null = null
): void => {
  const state = drawing.current;
  if (![1, 7, 8].includes(state.mapMode)) {
    drawing.issues.push(`Metafile fixed-unit mapping mode ${state.mapMode} is not rendered.`); return;
  }
  if (state.mapMode === 7) drawing.issues.push("Metafile isotropic mapping is approximated with its saved extents.");
  const scaleX = state.mapMode === 1 ? 1 : state.viewportExtent[0] / state.windowExtent[0];
  const scaleY = state.mapMode === 1 ? 1 : state.viewportExtent[1] / state.windowExtent[1];
  if (!Number.isFinite(scaleX) || !Number.isFinite(scaleY)) {
    drawing.issues.push("Metafile has zero window extents; a drawing operation was omitted."); return;
  }
  const transform = `matrix(${scaleX} 0 0 ${scaleY} ` +
    `${state.viewportOrigin[0] - state.windowOrigin[0] * scaleX} ` +
    `${state.viewportOrigin[1] - state.windowOrigin[1] * scaleY}) matrix(${state.world.join(" ")})`;
  const attributes = drawingAttributes(state, tag, { transform, ...values });
  drawing.nodes.push({ tag, attributes: Object.entries(attributes).map(([name, value]) =>
    ({ name, value: String(value) })), text, children: [] });
};
