import type { DwarfCfaRule, DwarfCfiExpression, DwarfCfiRegisterRule } from "../../analyzers/dwarf/cfi-state-types.js";
import { dwarfExpressionText } from "./expressions.js";

const expressionText = (expression: DwarfCfiExpression): string =>
  typeof expression === "string" ? expression : dwarfExpressionText(expression);
const offsetText = (offset: bigint): string => `${offset < 0n ? "−" : "+"} ${offset < 0n ? -offset : offset} bytes`;

export const dwarfCfaRuleText = (rule: DwarfCfaRule): string => {
  if (!rule) return "Unspecified frame address";
  return "expression" in rule ? expressionText(rule.expression)
    : `register ${rule.register} ${offsetText(rule.offset)}`;
};

export const dwarfRegisterRuleText = (rule: DwarfCfiRegisterRule): string => {
  if ("offset" in rule) return `${rule.kind === "offset" ? "memory at" : "value of"} frame address ${offsetText(rule.offset)}`;
  if ("expression" in rule) return `${rule.kind === "expression" ? "memory at" : "value of"} ${expressionText(rule.expression)}`;
  if ("register" in rule) return `value of register ${rule.register}`;
  return rule.kind === "same_value" ? "unchanged value" : "unavailable value";
};
