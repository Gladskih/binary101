import { featureDefinitions, type FeatureExpression } from "llvm-aarch64-disasm";

const expressionFeatures = (expression: FeatureExpression): string[] => {
  if (typeof expression === "boolean") return [];
  if ("feature" in expression) return [expression.feature];
  if ("not" in expression) return expressionFeatures(expression.not);
  return ("all_of" in expression ? expression.all_of : expression.any_of).flatMap(expressionFeatures);
};

// Descriptions cover every feature exported by the pinned LLVM metadata, not a curated subset.
// https://github.com/Gladskih/llvm-aarch64-disasm/blob/main/docs/metadata.md
export const describeAarch64Features = (expressions: readonly FeatureExpression[]): string => {
  const features = [...new Set(expressions.flatMap(expressionFeatures))];
  return features.length ? features.map(id => {
    const definition = featureDefinitions[id];
    const description = definition?.description.replace(/^Enable /, "") ?? "No description available";
    return features.length === 1 ? description : `${definition?.armName ?? id}: ${description}`;
  }).join("; ") : "LLVM opcode assembler gates; grouped Arm labels are preserved.";
};
