import { featureDefinitions, type FeatureExpression, type FeatureRequirements } from "llvm-aarch64-disasm";
import type { ElfInstructionSetUsage } from "../elf/disassembly-types.js";
import { describeAarch64Features } from "./feature-descriptions.js";

// Preserve Boolean gates and grouped Arm labels exactly; never turn OR into AND.
// https://github.com/Gladskih/llvm-aarch64-disasm/blob/main/docs/metadata.md
export const formatAarch64FeatureExpression = (expression: FeatureExpression): string => {
  if (typeof expression === "boolean") return String(expression);
  if ("feature" in expression) {
    return featureDefinitions[expression.feature]?.armName ?? expression.feature;
  }
  if ("not" in expression) return `not (${formatAarch64FeatureExpression(expression.not)})`;
  if ("all_of" in expression) {
    return `(${expression.all_of.map(formatAarch64FeatureExpression).join(" and ")})`;
  }
  return `(${expression.any_of.map(formatAarch64FeatureExpression).join(" or ")})`;
};

export const recordAarch64Requirements = (
  requirements: FeatureRequirements,
  usage: Map<string, ElfInstructionSetUsage>
): void => {
  const id = requirements.known ? JSON.stringify(requirements.predicates) : "unknown";
  const previous = usage.get(id);
  if (previous) {
    previous.instructionCount += 1;
    return;
  }
  usage.set(id, {
    id,
    ...(requirements.known ? { aarch64Predicates: requirements.predicates } : {}),
    label: requirements.known ? formatPredicates(requirements) : "Unknown requirements",
    description: requirements.known
      ? describeAarch64Features(requirements.predicates.map(predicate => predicate.expression))
      : "LLVM has no extracted feature record for this opcode.",
    instructionCount: 1
  });
};

const formatPredicates = (requirements: FeatureRequirements): string =>
  requirements.predicates.length
    ? requirements.predicates.map(predicate => formatAarch64FeatureExpression(predicate.expression)).join(" and ")
    : "No recorded LLVM feature gate";
