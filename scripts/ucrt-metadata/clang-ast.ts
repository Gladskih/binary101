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

const CDECL_ATTRIBUTE = "__attribute__((cdecl))";

const quotedParts = (line: string): string[] =>
  [...line.matchAll(/'([^']+)'/g)].map(match => match[1] ?? "");

const astNodeIndent = (line: string, kind: string): number =>
  line.indexOf(kind);

const anyAstNodeIndent = (line: string): number => {
  const match = line.match(/^([| `-]*)([A-Za-z].*)/);
  return match ? match[1]?.length ?? -1 : -1;
};

const functionNameFromLine = (line: string): string | null => {
  const parts = quotedParts(line);
  if (!parts.length) return null;
  const beforeType = line.slice(0, line.indexOf(`'${parts[0]}'`)).trim();
  const name = beforeType.match(/([A-Za-z_][A-Za-z0-9_]*)$/)?.[1];
  return name ?? null;
};

const parameterFromLine = (line: string): ClangFunctionParameter | null => {
  const parts = quotedParts(line);
  const type = parts.at(-1);
  if (!type) return null;
  const beforeType = line.slice(0, line.indexOf(`'${parts[0]}'`)).trim();
  const name = beforeType.match(/([A-Za-z_][A-Za-z0-9_]*)$/)?.[1] ?? null;
  return { name, type };
};

const splitFunctionType = (type: string): { returnType: string; parameterText: string } => {
  const normalized = type.replace(` ${CDECL_ATTRIBUTE}`, "");
  const open = normalized.indexOf("(");
  const close = normalized.lastIndexOf(")");
  if (open < 0 || close < open) return { returnType: normalized, parameterText: "" };
  return {
    returnType: normalized.slice(0, open).trim(),
    parameterText: normalized.slice(open + 1, close).trim()
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

const functionScore = (line: string, parameters: ClangFunctionParameter[]): number =>
  (line.includes(" implicit ") ? 0 : 4) +
  (line.includes("<invalid sloc>") ? 0 : 2) +
  parameters.filter(parameter => parameter.name).length;

const parseFunctionDeclAt = (
  lines: string[],
  index: number
): ClangFunctionDecl | null => {
  const line = lines[index] ?? "";
  const name = functionNameFromLine(line);
  const types = quotedParts(line);
  if (!name || !types.length) return null;
  const rawType = types[0] ?? "";
  const canonicalType = types.at(-1) ?? rawType;
  const indent = astNodeIndent(line, "FunctionDecl");
  const parameters: ClangFunctionParameter[] = [];
  for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
    const child = lines[cursor] ?? "";
    const childParmIndent = astNodeIndent(child, "ParmVarDecl");
    const childKindIndent = anyAstNodeIndent(child);
    if (childKindIndent >= 0 && childKindIndent <= indent) break;
    if (childParmIndent > indent) {
      const parameter = parameterFromLine(child);
      if (parameter) parameters.push(parameter);
    }
  }
  const split = splitFunctionType(canonicalType);
  const variadic = split.parameterText.split(",").some(part => part.trim() === "...");
  const fixedParameters = parameters.length ? parameters : fallbackParameters(split.parameterText);
  return {
    name,
    returnType: split.returnType,
    rawType,
    parameters: fixedParameters,
    callingConvention: rawType.includes(CDECL_ATTRIBUTE) ? "cdecl" : "default",
    variadic,
    score: functionScore(line, fixedParameters)
  };
};

export const parseClangFunctions = (
  astText: string,
  exportNames: ReadonlySet<string>
): Map<string, ClangFunctionDecl> => {
  const functions = new Map<string, ClangFunctionDecl>();
  const lines = astText.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (!line.includes("FunctionDecl")) continue;
    const decl = parseFunctionDeclAt(lines, index);
    if (!decl || !exportNames.has(decl.name)) continue;
    const existing = functions.get(decl.name);
    if (!existing || decl.score >= existing.score) functions.set(decl.name, decl);
  }
  return functions;
};
