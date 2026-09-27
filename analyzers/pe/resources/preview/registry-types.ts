export type RegistryValue =
  | { type: "REG_SZ"; data: string }
  | { type: "REG_DWORD"; data: number }
  | { type: "REG_MULTI_SZ"; data: string[] }
  | { type: "REG_BINARY"; data: Uint8Array }
  | { type: "unresolved"; tag: string; source: string };

export interface RegistryNode {
  name: string;
  directive: "key" | "NoRemove" | "ForceRemove" | "Delete" | "val";
  line: number;
  column: number;
  value: RegistryValue | null;
  children: RegistryNode[];
}

export interface RegistryScript {
  roots: RegistryNode[];
}

export interface RegistryToken {
  text: string;
  quoted: boolean;
  line: number;
  column: number;
}

