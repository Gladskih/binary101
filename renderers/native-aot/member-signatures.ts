import type { NativeAotReflectionField, NativeAotReflectionMethod } from
  "../../analyzers/native-aot/format.js";

export const nativeAotMethodSignature = (method: NativeAotReflectionMethod): string => {
  const signature = method.signature;
  if (!signature) return method.name;
  const generic = signature.genericParameterCount
    ? `<${method.genericParameters?.map(parameter => parameter.name).join(", ") ||
      `arity=${signature.genericParameterCount}`}>` : "";
  const varargs = signature.varArgParameters.length
    ? `${signature.parameters.length ? ", " : ""}..., ${signature.varArgParameters.join(", ")}` : "";
  return `${signature.returnType} ${method.name}${generic}(` +
    `${signature.parameters.join(", ")}${varargs})`;
};

export const nativeAotFieldSignature = (field: NativeAotReflectionField): string =>
  field.type ? `${field.type} ${field.name}` : field.name;
