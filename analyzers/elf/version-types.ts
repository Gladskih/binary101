export interface ElfVersionDefinition {
  index: number;
  flags: number;
  hash: number;
  names: string[];
}

export interface ElfVersionRequirement {
  file: string;
  versions: Array<{ index: number; flags: number; hash: number; name: string }>;
}

export interface ElfSymbolVersions {
  definitions: ElfVersionDefinition[];
  requirements: ElfVersionRequirement[];
  symbols: number[];
  issues: string[];
}
