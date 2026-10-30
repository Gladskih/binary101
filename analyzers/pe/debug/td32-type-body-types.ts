/** Stored TD32 body fields; type/name/index remain on the enclosing record. */
export interface Td32TypeBody {
  attributes?: number;
  targetType?: number;
  memberAttributes?: number;
  classType?: number;
  count?: number;
  fieldList?: number;
  // The two published decoders disagree on the meanings of these byte slots.
  relation12?: number;
  relation16?: number;
  relation20?: number;
  relation14?: number;
  byteSize?: { leaf?: number; value?: string };
  underlyingType?: number;
  returnType?: number;
  callingConvention?: number;
  functionAttributes?: number;
  parameterCount?: number;
  argumentList?: number;
  thisType?: number;
  thisAdjustment?: number;
  argumentTypes?: number[];
  bitLength?: number;
  bitPosition?: number;
}
