import type { NativeAotConstant } from "../../analyzers/native-aot/native-format-constant-nodes.js";

/** Arrays stay available in parsed data; the overview describes their type and size. */
export const nativeAotConstantText = (constant: NativeAotConstant): string => {
  if (constant.value === null) return "null";
  if (Array.isArray(constant.value)) return `${constant.type} (${constant.value.length} elements)`;
  if (constant.type === "string" || constant.type === "char") return JSON.stringify(constant.value);
  if (constant.type === "Type") return `typeof(${constant.value})`;
  return `${Object.is(constant.value, -0) ? "-0" : String(constant.value)} (${constant.type})`;
};
