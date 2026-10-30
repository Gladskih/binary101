export interface Td32NumericValue { leaf?: number; value?: string; }

/** Stored Borland field-list subrecord values; `type` is its leaf word. */
export interface Td32TypeField {
  type: number;
  targetType?: number;
  attributes?: number;
  nameIndex?: number;
  browserOffset?: number;
  offset?: Td32NumericValue;
  value?: Td32NumericValue;
  count?: number;
  pointerType?: number;
  virtualBaseIndex?: Td32NumericValue;
}

export interface Td32TypeMethod {
  attributes: number;
  methodType: number;
  browserOffset: number;
  vtableOffset?: number;
}
