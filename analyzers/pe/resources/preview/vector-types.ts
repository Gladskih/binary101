export interface ResourceVectorNode {
  tag: string;
  attributes: Array<{ name: string; value: string }>;
  text: string | null;
  children: ResourceVectorNode[];
}

export interface ResourceVector {
  format: "SVG" | "EMF" | "WMF";
  bounds: { x: number; y: number; width: number; height: number };
  nodes: ResourceVectorNode[];
  records?: Array<{ type: number; offset: number; size: number }>;
}
