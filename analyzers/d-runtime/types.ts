export interface DRuntimeImage {
  pointerSize: 4 | 8;
  littleEndian: boolean;
  read: (address: bigint, size: number) => Promise<DataView | null>;
  isExecutable: (address: bigint) => boolean;
  isMapped: (address: bigint, size: number) => boolean;
}

export interface DModuleInfo {
  address: bigint;
  flags: number;
  index: number;
  name: string;
  callbacks: Array<{ kind: string; address: bigint }>;
  importedModules: bigint[];
  localClasses: bigint[];
}

export interface DRuntimeMetadata {
  modules: DModuleInfo[];
  warnings: string[];
}
