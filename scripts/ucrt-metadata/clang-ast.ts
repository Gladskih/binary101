"use strict";

export interface ClangFunctionParameter {
  name: string | null;
  type: string;
}

export interface ClangFunctionDecl {
  name: string;
  returnType: string;
  rawType: string;
  parameters: ClangFunctionParameter[];
  callingConvention: string;
  variadic: boolean;
  score: number;
}

type ClangAstNode = {
  kind?: string;
  name?: string;
  type?: {
    qualType?: string;
    desugaredQualType?: string;
  };
  inner?: ClangAstNode[];
  isImplicit?: boolean;
  variadic?: boolean;
};

const CDECL_ATTRIBUTE = "__attribute__((cdecl))";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isClangAstNode = (value: unknown): value is ClangAstNode =>
  isRecord(value);

const nodeChildren = (node: ClangAstNode): ClangAstNode[] =>
  Array.isArray(node.inner) ? node.inner.filter(isClangAstNode) : [];

const functionTypeText = (node: ClangAstNode): string =>
  node.type?.desugaredQualType ?? node.type?.qualType ?? "";

const matchingParenIndex = (value: string, open: number): number => {
  let depth = 0;
  for (let index = open; index < value.length; index += 1) {
    const char = value[index];
    if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
};

const splitFunctionType = (type: string): { returnType: string; parameterText: string } => {
  const open = type.indexOf("(");
  const close = open >= 0 ? matchingParenIndex(type, open) : -1;
  if (open < 0 || close < open) return { returnType: type.trim(), parameterText: "" };
  return {
    returnType: type.slice(0, open).replace(CDECL_ATTRIBUTE, "").trim(),
    parameterText: type.slice(open + 1, close).trim()
  };
};

const splitTopLevelCommas = (text: string): string[] => {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === "(" || char === "[" || char === "<") depth += 1;
    else if (char === ")" || char === "]" || char === ">") depth = Math.max(0, depth - 1);
    else if (char === "," && depth === 0) {
      parts.push(text.slice(start, index).trim());
      start = index + 1;
    }
  }
  const tail = text.slice(start).trim();
  if (tail) parts.push(tail);
  return parts;
};

const fallbackParameters = (parameterText: string): ClangFunctionParameter[] => {
  if (!parameterText || parameterText === "void") return [];
  return splitTopLevelCommas(parameterText)
    .filter(type => type !== "...")
    .map(type => ({ name: null, type }));
};

const parameterFromNode = (node: ClangAstNode): ClangFunctionParameter | null => {
  const type = node.type?.qualType;
  if (!type) return null;
  return { name: node.name ?? null, type };
};

const functionParameters = (
  node: ClangAstNode,
  parameterText: string
): ClangFunctionParameter[] => {
  const parameters = nodeChildren(node)
    .filter(child => child.kind === "ParmVarDecl")
    .map(parameterFromNode)
    .filter((parameter): parameter is ClangFunctionParameter => parameter != null);
  return parameters.length ? parameters : fallbackParameters(parameterText);
};

const functionScore = (
  node: ClangAstNode,
  parameters: ClangFunctionParameter[]
): number =>
  (node.isImplicit ? 0 : 4) +
  parameters.filter(parameter => parameter.name).length;

const isVariadicFunction = (node: ClangAstNode, parameterText: string): boolean =>
  node.variadic === true || parameterText.split(",").some(part => part.trim() === "...");

const parseFunctionNode = (node: ClangAstNode): ClangFunctionDecl | null => {
  if (node.kind !== "FunctionDecl" || !node.name) return null;
  const rawType = node.type?.qualType ?? "";
  const split = splitFunctionType(functionTypeText(node));
  const parameters = functionParameters(node, split.parameterText);
  return {
    name: node.name,
    returnType: split.returnType,
    rawType,
    parameters,
    callingConvention: rawType.includes(CDECL_ATTRIBUTE) ? "cdecl" : "default",
    variadic: isVariadicFunction(node, split.parameterText),
    score: functionScore(node, parameters)
  };
};

const collectFunctionNodes = (node: ClangAstNode): ClangAstNode[] => [
  ...(node.kind === "FunctionDecl" ? [node] : []),
  ...nodeChildren(node).flatMap(collectFunctionNodes)
];

export const parseClangFunctions = (
  astJson: string,
  exportNames: ReadonlySet<string>
): Map<string, ClangFunctionDecl> => {
  const parsed = JSON.parse(astJson) as unknown;
  if (!isClangAstNode(parsed)) return new Map();
  const functions = new Map<string, ClangFunctionDecl>();
  for (const node of collectFunctionNodes(parsed)) {
    const decl = parseFunctionNode(node);
    if (!decl || !exportNames.has(decl.name)) continue;
    const existing = functions.get(decl.name);
    if (!existing || decl.score >= existing.score) functions.set(decl.name, decl);
  }
  return functions;
};
