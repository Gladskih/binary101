// Binary layouts: Wine dlls/oleaut32/typelib.h and typelib.c (MSFT_* / SLTG_*).
// https://github.com/wine-mirror/wine/tree/master/dlls/oleaut32
export interface TypeLibraryValue {
  type: number;
  value: string | number | null;
}

export interface TypeLibraryCustomData {
  guid: string | null;
  value: TypeLibraryValue | null;
}

export interface TypeLibraryParameter {
  name: string | null;
  type: string;
  flags: number;
  defaultValue: TypeLibraryValue | null;
  customData: TypeLibraryCustomData[];
}

export interface TypeLibraryMember {
  name: string | null;
  id: number;
  type: string;
  flags: number;
  kind: number;
  documentation: string | null;
  helpContext: number | null;
  helpStringContext: number | null;
  customData: TypeLibraryCustomData[];
}

export interface TypeLibraryFunction extends TypeLibraryMember {
  invocation: number;
  callingConvention: number;
  vtableOffset: number;
  optionalParameters: number;
  entry: string | number | null;
  parameters: TypeLibraryParameter[];
}

export interface TypeLibraryVariable extends TypeLibraryMember {
  value: TypeLibraryValue | null;
  instanceOffset: number | null;
}

export interface TypeLibraryInterface {
  reference: number;
  flags: number;
  customData: TypeLibraryCustomData[];
}

export interface TypeLibraryType {
  reference: number;
  name: string | null;
  guid: string | null;
  kind: number;
  flags: number;
  version: number;
  size: number;
  alignment: number;
  vtableSize: number;
  documentation: string | null;
  helpContext: number;
  helpStringContext: number | null;
  alias: string | null;
  dll: string | null;
  interfaces: TypeLibraryInterface[];
  functions: TypeLibraryFunction[];
  variables: TypeLibraryVariable[];
  customData: TypeLibraryCustomData[];
}

export interface TypeLibraryImport {
  offset: number;
  name: string;
  guid: string | null;
  lcid: number;
  version: number;
}

export interface TypeLibraryImportedType {
  offset: number;
  flags: number | null;
  libraryOffset: number;
  identifier: string | number | null;
}

export interface TypeLibraryAnalysis {
  name: string | null;
  guid: string | null;
  documentation: string | null;
  helpFile: string | null;
  helpStringDll: string | null;
  helpContext: number;
  helpStringContext: number | null;
  customData: TypeLibraryCustomData[];
  imports: TypeLibraryImport[];
  importedTypes: TypeLibraryImportedType[];
  types: TypeLibraryType[];
}
