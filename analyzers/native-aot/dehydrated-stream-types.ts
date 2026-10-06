export type NativeAotHydratedRun = { rva: number; size: number } & (
  { kind: "zero" } | { kind: "copy"; sourceRva: number } |
  { kind: "pointer" | "relative"; target: number });
