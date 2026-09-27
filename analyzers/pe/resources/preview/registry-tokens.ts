import type { RegistryToken } from "./registry-types.js";

// ATL tokenization is whitespace-delimited; GUID braces belong to an unquoted token.
// Apostrophes are escaped by doubling; backslashes are literal. No comment syntax exists.
// CRegParser::NextToken / IsSpace:
// https://github.com/adzm/atlmfc/blob/master/include/statreg.h
const tokenPattern = /[ \t\r\n]+|'(?:''|[^'])*'(?!')|'(?:''|[^'])*$|[^ \t\r\n]+/gu;

const advancePosition = (text: string, line: number, column: number): [number, number] => {
  const lines = text.split(/\r\n|\r|\n/u);
  return lines.length === 1
    ? [line, column + text.length]
    : [line + lines.length - 1, lines[lines.length - 1]!.length + 1];
};

const readToken = (
  source: string, line: number, column: number, issues: string[]
): RegistryToken => {
  const quoted = source.startsWith("'");
  const closed = quoted && /^'(?:''|[^'])*'$/u.test(source);
  if (quoted && !closed) issues.push(`ATL RGS ${line}:${column}: unterminated quote.`);
  const text = quoted
    ? source.slice(1, closed ? -1 : undefined).replaceAll("''", "'")
    : source;
  // NextToken rejects newLength + 1 >= MAX_VALUE (4096): maximum = 4096 - 1 - 1 = 4094.
  // The +1 reserves NUL; the strict comparison leaves another slot unused.
  // https://github.com/adzm/atlmfc/blob/master/include/statreg.h (MAX_VALUE, NextToken)
  if (text.length > 4094) issues.push(`ATL RGS ${line}:${column}: token exceeds ATL's 4K limit.`);
  if (/^(?:;|\/\/|\/\*)/u.test(text)) {
    issues.push(`ATL RGS ${line}:${column}: ATL does not support comments; token retained.`);
  }
  return { text, quoted, line, column };
};

export const tokenizeRegistry = (text: string, issues: string[]): RegistryToken[] => {
  const tokens: RegistryToken[] = [];
  let line = 1;
  let column = 1;
  for (const match of text.matchAll(tokenPattern)) {
    const source = match[0];
    if (!/^[ \t\r\n]/u.test(source)) tokens.push(readToken(source, line, column, issues));
    [line, column] = advancePosition(source, line, column);
  }
  return tokens;
};
