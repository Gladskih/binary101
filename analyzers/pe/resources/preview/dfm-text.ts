import type { DfmComponent } from "./dfm.js";
import type { DfmProperty, DfmValue } from "./dfm-values.js";
import type { ResourcePreviewResult } from "./types.js";

interface Token { kind: "word" | "string" | "symbol"; value: string; offset: number; end: number }

// Text form of Delphi/FPC component streams: Pascal strings, #character codes,
// sets, lists, collections and hexadecimal binary properties. No RTTI/code execution.
// https://docwiki.embarcadero.com/RADStudio/en/Text_DFM_or_Text_FMX
class FormTextReader {
  offset = 0;
  private pending: Token | null | undefined;
  constructor(readonly text: string) {}
  peek(): Token | null {
    if (this.pending === undefined) this.pending = this.read();
    return this.pending;
  }
  putBack(token: Token): void { this.pending = token; }
  read(): Token | null {
    if (this.pending !== undefined) {
      const token = this.pending; this.pending = undefined; return token;
    }
    while (/\s/u.test(this.text[this.offset] ?? "")) this.offset += 1;
    if (this.offset >= this.text.length) return null;
    const offset = this.offset;
    if (this.text[this.offset] === "'") {
      const value = this.string(); return { kind: "string", value, offset, end: this.offset };
    }
    if (/[\w.$#-]/u.test(this.text[this.offset]!)) {
      this.offset += 1;
      while (/[\w.$+-]/u.test(this.text[this.offset] ?? "")) this.offset += 1;
      return { kind: "word", value: this.text.slice(offset, this.offset), offset, end: this.offset };
    }
    this.offset += 1;
    return { kind: "symbol", value: this.text[offset]!, offset, end: this.offset };
  }
  string(): string {
    this.offset += 1;
    const parts: string[] = [];
    let start = this.offset;
    while (this.offset < this.text.length) {
      if (this.text[this.offset] === "\n" || this.text[this.offset] === "\r") {
        throw new Error(`DFM quoted string at ${start - 1} is unterminated.`);
      }
      if (this.text[this.offset++] !== "'") continue;
      parts.push(this.text.slice(start, this.offset - 1));
      if (this.text[this.offset] !== "'") return parts.join("");
      parts.push("'"); this.offset += 1; start = this.offset;
    }
    throw new Error(`DFM quoted string at ${start - 1} is unterminated.`);
  }
  require(value?: string): Token {
    const token = this.read();
    if (!token || (value !== undefined && token.value !== value)) {
      throw new Error(`DFM expected ${value ?? "a value"} at character ${this.offset}.`);
    }
    return token;
  }
}

const character = (value: string): string => {
  const number = value.startsWith("#$") ? Number.parseInt(value.slice(2), 16) : Number(value.slice(1));
  if (!Number.isInteger(number) || number < 0 || number > 0x10ffff) throw new Error("DFM character code is invalid.");
  return String.fromCodePoint(number);
};

const isStringToken = (token: Token): boolean => token.kind === "string" || token.value.startsWith("#");
const stringToken = (token: Token): string => token.kind === "string" ? token.value : character(token.value);

const stringScalar = (reader: FormTextReader, token: Token): DfmValue => {
    const parts = [stringToken(token)];
    let end = token.end;
    let concatenation = false;
    // TParser.HandleString joins contiguous literals/#codes; whitespace separates list items.
    // https://github.com/fpc/FPCSource/blob/main/rtl/objpas/classes/parser.inc
    while (reader.peek()) {
      const next = reader.peek()!;
      if (next.value === "+") { reader.require("+"); concatenation = true; continue; }
      if (!isStringToken(next) ||
        (!concatenation && next.offset !== end)) break;
      reader.require(); parts.push(stringToken(next));
      end = next.end; concatenation = false;
    }
    if (concatenation) throw new Error("DFM string concatenation lacks its next string.");
    return { kind: "string", value: parts.join("") };
};

const setScalar = (reader: FormTextReader): DfmValue => {
    const values: string[] = [];
    while (reader.peek()?.value !== "]") {
      const item = reader.require();
      if (item.kind !== "word") throw new Error("DFM set item is invalid.");
      values.push(item.value);
      if (reader.peek()?.value === ",") reader.require(",");
    }
    reader.require("]"); return { kind: "set", values };
};

const binaryScalar = (reader: FormTextReader): DfmValue => {
    const chunks: string[] = [];
    while (reader.peek()?.value !== "}") chunks.push(reader.require().value);
    reader.require("}");
    const hex = chunks.join("");
    if (hex.length % 2 || !/^[\da-f]*$/iu.test(hex)) throw new Error("DFM binary property is not hexadecimal bytes.");
    return { kind: "binary", data: Uint8Array.from(hex.match(/../gu) ?? [], value => Number.parseInt(value, 16)) };
};

const numberScalar = (value: string): DfmValue | null => {
  if (/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/iu.test(value) || /^\$[\da-f]+$/iu.test(value)) {
    return { kind: "number", value: value.startsWith("$") ? BigInt(`0x${value.slice(1)}`).toString() : value };
  }
  return null;
};

const scalar = (reader: FormTextReader, token: Token): DfmValue => {
  if (isStringToken(token)) return stringScalar(reader, token);
  if (token.value === "True" || token.value === "False") return { kind: "boolean", value: token.value === "True" };
  if (token.value.toLowerCase() === "nil") return { kind: "null" };
  const numeric = numberScalar(token.value);
  if (numeric) return numeric;
  if (token.value === "[") return setScalar(reader);
  if (token.value === "{") return binaryScalar(reader);
  if (token.kind !== "word") throw new Error(`DFM property value at ${token.offset} is unsupported.`);
  return { kind: "identifier", value: token.value };
};

type ValueTask = { kind: "value"; assign: (value: DfmValue) => void }
  | { kind: "list"; values: DfmValue[] }
  | { kind: "collection"; items: DfmProperty[][] }
  | { kind: "properties"; properties: DfmProperty[] };

const assignTextValue = (reader: FormTextReader, task: Extract<ValueTask, {kind: "value"}>,
  token: Token, stack: ValueTask[]): void => {
  if (token.value === "(") {
      const values: DfmValue[] = [];
      task.assign({ kind: "list", values }); stack.push({ kind: "list", values });
    } else if (token.value === "<") {
      const items: DfmProperty[][] = [];
      task.assign({ kind: "collection", items }); stack.push({ kind: "collection", items });
    } else task.assign(scalar(reader, token));
};

const readValue = (reader: FormTextReader): DfmValue => {
  let result: DfmValue = { kind: "null" };
  const stack: ValueTask[] = [{ kind: "value", assign: value => { result = value; } }];
  while (stack.length) {
    const task = stack.pop()!;
    const token = reader.require();
    if (task.kind === "list") {
      if (token.value === ")") continue;
      reader.putBack(token);
      stack.push(task, { kind: "value", assign: value => { task.values.push(value); } });
    } else if (task.kind === "collection") {
      if (token.value === ">") continue;
      if (token.value !== "item") throw new Error("DFM collection expects an item.");
      const properties: DfmProperty[] = [];
      task.items.push(properties); stack.push(task, { kind: "properties", properties });
    } else if (task.kind === "properties") {
      if (token.value === "end") continue;
      reader.require("=");
      stack.push(task, { kind: "value", assign: value => { task.properties.push({ name: token.value, value }); } });
    } else assignTextValue(reader, task, token, stack);
  }
  return result;
};

const component = (reader: FormTextReader): DfmComponent => {
  const kind = reader.require().value;
  const name = reader.require().value;
  reader.require(":");
  const className = reader.require().value;
  let childPosition: string | undefined;
  if (reader.peek()?.value === "[") {
    reader.require("["); childPosition = reader.require().value; reader.require("]");
  }
  return { name, className, flags: kind === "inherited" ? 1 : kind === "inline" ? 4 : 0,
    ...(childPosition === undefined ? {} : { childPosition }), properties: [], children: [] };
};

const readTextComponents = (reader: FormTextReader, root: DfmComponent): void => {
    const stack = [root];
    while (stack.length) {
      const next = reader.peek();
      if (!next) throw new Error("DFM component lacks its end marker.");
      if (["object", "inherited", "inline"].includes(next.value)) {
        const child = component(reader); stack[stack.length - 1]!.children.push(child); stack.push(child);
      } else if (next.value === "end") { reader.require("end"); stack.pop(); }
      else {
        const name = reader.require().value;
        reader.require("="); stack[stack.length - 1]!.properties.push({ name, value: readValue(reader) });
      }
    }
};

export const addTextDfmPreview = (text: string): ResourcePreviewResult | null => {
  if (!/^\s*(?:object|inherited|inline)\s+[\w.]+\s*:\s*[\w.]+/u.test(text)) return null;
  const reader = new FormTextReader(text);
  const issues: string[] = [];
  let root: DfmComponent | undefined;
  try {
    root = component(reader);
    readTextComponents(reader, root);
    if (reader.peek()) issues.push("DFM contains text after its root component.");
  } catch (error) { issues.push(error instanceof Error ? error.message : String(error)); }
  return { preview: { previewKind: "dfm", ...(root ? { dfm: root } : {}) },
    ...(issues.length ? { issues } : {}) };
};
