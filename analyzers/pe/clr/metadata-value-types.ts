"use strict";

import type { PeClrCustomAttributeNamedArgument } from "./types.js";

export interface PeClrConstantValue {
  kind: "constant";
  value: string | number | boolean | null | number[];
  issues?: string[];
}

export interface PeClrMarshallingDescriptor {
  kind: "marshal";
  nativeType: string;
  parameters: Record<string, string | number | null>;
  issues?: string[];
}

export type PeClrPermissionSet = {
  kind: "security";
  encoding: "xml";
  xml: string;
  issues?: string[];
} | {
  kind: "security";
  encoding: "binary";
  attributes: { typeName: string | null; namedArguments: PeClrCustomAttributeNamedArgument[]; issues?: string[] }[];
  issues?: string[];
};
