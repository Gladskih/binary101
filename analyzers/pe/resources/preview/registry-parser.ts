import type { RegistryNode, RegistryScript, RegistryToken, RegistryValue } from "./registry-types.js";
import { tokenizeRegistry } from "./registry-tokens.js";
import { parseRegistryValue } from "./registry-values.js";

// Root aliases and case-insensitive keywords follow CRegParser::HKeyFromString.
// https://learn.microsoft.com/en-us/cpp/atl/understanding-parse-trees
export const registryRootName = (name: string): string | null => {
  const names: Record<string, string> = {
    HKCR: "HKEY_CLASSES_ROOT", HKCU: "HKEY_CURRENT_USER", HKLM: "HKEY_LOCAL_MACHINE",
    HKU: "HKEY_USERS", HKPD: "HKEY_PERFORMANCE_DATA", HKDD: "HKEY_DYN_DATA",
    HKCC: "HKEY_CURRENT_CONFIG"
  };
  const upper = name.toUpperCase();
  return Object.hasOwn(names, upper) ? names[upper]!
    : Object.values(names).includes(upper) ? upper : null;
};

const directiveName = (name: string): RegistryNode["directive"] => {
  switch (name.toLowerCase()) {
    case "noremove": return "NoRemove";
    case "forceremove": return "ForceRemove";
    case "delete": return "Delete";
    case "val": return "val";
    default: return "key";
  }
};

// Mutation is confined to this cursor and the AST being built, to process tokens once.
class RegistryParser {
  private index = 0;
  constructor(private readonly tokens: RegistryToken[], private readonly issues: string[]) {}

  private peek(): RegistryToken | undefined { return this.tokens[this.index]; }

  private take(): RegistryToken | undefined {
    const token = this.peek();
    if (token) this.index += 1;
    return token;
  }

  private at(text: string): boolean {
    return this.peek()?.text === text && this.peek()?.quoted === false;
  }

  private warn(token: Pick<RegistryToken, "line" | "column">, message: string): void {
    this.issues.push(`ATL RGS ${token.line}:${token.column}: ${message}`);
  }

  private word(): RegistryToken | undefined {
    if (this.at("{") || this.at("}") || this.at("=")) return undefined;
    return this.take();
  }

  private assignment(token: RegistryToken): RegistryValue | null {
    if (!this.at("=")) return null;
    this.take();
    const tag = this.word();
    const source = tag ? this.word() : undefined;
    if (!tag || !source) {
      this.warn(token, "missing assignment type or data.");
      return null;
    }
    return parseRegistryValue(tag.text, source.text, this.issues);
  }

  private node(): RegistryNode | null {
    const token = this.word();
    if (!token) return null;
    const directive = directiveName(token.text);
    const name = directive === "key" ? token : this.word();
    if (!name) { this.warn(token, "missing key or value name."); return null; }
    if (name.quoted && ["{", "}", "="].includes(name.text)) {
      // ATL discards quote metadata; these names can be interpreted as control tokens.
      this.warn(name, "quoted structural token is retained only for recovery.");
    }
    const value = this.assignment(token);
    const node = { name: name.text, directive, line: token.line, column: token.column, value, children: [] };
    this.validateNode(node);
    return node;
  }

  private validateNode(node: RegistryNode): void {
    if (node.directive === "val") {
      if (!node.value) this.warn(node, "named value requires an assignment.");
      return;
    }
    if (!node.name) this.warn(node, "empty key name.");
    if (node.name.includes("\\")) {
      this.warn(node, "compound key names are rejected by ATL; use nested keys.");
    }
    if (node.directive === "Delete" && node.value) {
      this.warn(node, "Delete assignment is ignored in Register mode.");
    }
  }

  private children(parent: RegistryNode, stack: RegistryNode[]): void {
    if (!this.at("{")) return;
    this.take();
    if (parent.directive === "val" || parent.directive === "Delete") {
      this.warn(parent, `${parent.directive} cannot contain a registration subtree.`);
    }
    stack.push(parent);
  }

  private unexpected(): void {
    const token = this.take();
    if (token) this.warn(token, `unexpected token '${token.text}'.`);
  }

  parse(): RegistryScript {
    const roots: RegistryNode[] = [];
    const stack: RegistryNode[] = [];
    while (this.peek()) {
      if (stack.length && this.at("}")) {
        this.take();
        stack.pop();
        continue;
      }
      const node = this.node();
      if (!node) { this.unexpected(); continue; }
      const parent = stack.at(-1);
      (parent ? parent.children : roots).push(node);
      if (!parent) this.validateRoot(node);
      this.children(node, stack);
    }
    for (const parent of stack) this.warn(parent, "unclosed key block.");
    if (!roots.length) this.issues.push("ATL RGS: script is empty or has no root hives.");
    return { roots };
  }

  private validateRoot(root: RegistryNode): void {
    if (!registryRootName(root.name) || root.directive !== "key") {
      this.warn(root, "expected a registry root hive.");
    }
    if (root.value) this.warn(root, "root hive cannot have an assignment.");
    if (!this.at("{")) this.warn(root, "missing root opening brace.");
  }
}

export const parseRegistryScript = (text: string, issues: string[]): RegistryScript =>
  new RegistryParser(tokenizeRegistry(text, issues), issues).parse();
