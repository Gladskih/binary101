import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfAttributeCursorAt, ElfAttributeScope, ElfAttributeVendor,
  ElfBuildAttribute } from "./attribute-types.js";
import { readElfBuildAttribute } from "./attribute-values.js";

const scopeIndices = async (cursor: DwarfCursor): Promise<bigint[]> => {
  const indices: bigint[] = [];
  while (!cursor.failed) {
    const index = await cursor.uleb();
    if (index == null || index === 0n) return indices;
    indices.push(index);
    if (indices.length === 100000) cursor.fail("Attribute index limit reached");
  }
  return indices;
};

const readScope = async (
  cursor: DwarfCursor, cursorAt: ElfAttributeCursorAt, vendor: string
): Promise<ElfAttributeScope | null> => {
  const start = cursor.position;
  const tag = await cursor.uleb();
  const length = await cursor.uint32();
  if (tag == null || length == null) return null;
  if (length < cursor.position - start || start + length > cursor.end) {
    cursor.fail("Invalid attribute scope length");
    return null;
  }
  const scope = cursorAt(cursor.position, start + length);
  cursor.position = start + length;
  if (tag < 1n || tag > 3n) {
    scope.notice(`Unsupported attribute scope ${tag}`);
    return { tag, indices: [], attributes: [] };
  }
  const indices = tag === 1n ? [] : await scopeIndices(scope);
  return { tag, indices, attributes: await readAttributes(scope, vendor) };
};

const readAttributes = async (scope: DwarfCursor, vendor: string): Promise<ElfBuildAttribute[]> => {
  const attributes: ElfBuildAttribute[] = [];
  while (scope.position < scope.end && !scope.failed) {
    const attribute = await readElfBuildAttribute(scope, vendor);
    if (!attribute) break;
    attributes.push(attribute);
    if (attributes.length === 100000) scope.fail("Attribute count limit reached");
  }
  return attributes;
};

// Vendor and scope lengths include their own headers. ARM AAELF32 / RISC-V psABI.
export const readElfAttributeVendor = async (
  cursor: DwarfCursor, cursorAt: ElfAttributeCursorAt
): Promise<ElfAttributeVendor | null> => {
  const start = cursor.position;
  const length = await cursor.uint32();
  if (length == null) return null;
  if (length < 5 || start + length > cursor.end) {
    cursor.fail("Invalid attribute vendor length");
    return null;
  }
  const vendor = cursorAt(cursor.position, start + length);
  cursor.position = start + length;
  const name = await vendor.cstring();
  if (name == null) return null;
  const result: ElfAttributeVendor = { name, scopes: [] };
  if (name !== "aeabi" && name !== "riscv") {
    vendor.notice(`Unsupported attribute vendor ${name}`);
    return result;
  }
  result.scopes = await readScopes(vendor, cursorAt, name);
  return result;
};

const readScopes = async (
  vendor: DwarfCursor, cursorAt: ElfAttributeCursorAt, name: string
): Promise<ElfAttributeScope[]> => {
  const scopes: ElfAttributeScope[] = [];
  while (vendor.position < vendor.end && !vendor.failed) {
    const scope = await readScope(vendor, cursorAt, name);
    if (!scope) break;
    scopes.push(scope);
    if (scopes.length === 100000) vendor.fail("Attribute scope limit reached");
  }
  return scopes;
};
