import type { RegistryNode, RegistryScript } from "./registry-types.js";
import { registryRootName } from "./registry-parser.js";
import { registryParameters } from "./registry-parameters.js";

export interface RegistryLocation {
  node: RegistryNode;
  path: string[];
}

export function* registryLocations(script: RegistryScript): Generator<RegistryLocation> {
  for (const root of script.roots) {
    const path = [registryRootName(root.name) ?? root.name];
    const stack = [{ nodes: root.children, index: 0, depth: path.length }];
    while (stack.length) {
      const frame = stack[stack.length - 1]!;
      const node = frame.nodes[frame.index++];
      path.length = frame.depth;
      if (!node) { stack.pop(); continue; }
      if (node.directive !== "val") path.push(node.name);
      yield { node, path: [...path] };
      if (node.children.length) stack.push({ nodes: node.children, index: 0, depth: path.length });
    }
  }
}

const classesPath = (path: string[]): string[] | null => {
  // Strip 1 component for HKCR, or 3 for hive/Software/Classes; retain the COM-relative path.
  // https://learn.microsoft.com/en-us/windows/win32/sysinfo/merged-view-of-hkey-classes-root
  const upper = path.map(part => part.toUpperCase());
  if (upper[0] === "HKEY_CLASSES_ROOT") return upper.slice(1);
  if ((upper[0] === "HKEY_CURRENT_USER" || upper[0] === "HKEY_LOCAL_MACHINE") &&
      upper[1] === "SOFTWARE" && upper[2] === "CLASSES") return upper.slice(3);
  return null;
};

const classRoles = new Map<string, string>([
  // COM registry schema: https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm
  ["INPROCSERVER32", "In-process COM server"], ["LOCALSERVER32", "Out-of-process COM server"],
  ["INPROCHANDLER32", "In-process COM handler"], ["PROGID", "Versioned ProgID"],
  ["VERSIONINDEPENDENTPROGID", "Version-independent ProgID"], ["TYPELIB", "Type library reference"],
  ["VERSION", "Type library version"], ["APPID", "COM AppID reference"],
  ["TREATAS", "COM class redirection"], ["AUTOCONVERTTO", "COM class conversion"]
]);

const interfaceRoles = new Map<string, string>([
  // https://learn.microsoft.com/en-us/windows/win32/com/interface-key
  ["PROXYSTUBCLSID32", "Interface proxy/stub CLSID"], ["PROXYSTUBCLSID", "Interface proxy/stub CLSID"],
  ["TYPELIB", "Type library reference"], ["NUMMETHODS", "Interface method count"],
  ["BASEINTERFACE", "Base interface IID"]
]);

const namedRole = (path: string[], name: string): string | null => {
  // AppID/<application> and CLSID/<class> have 2 components; InprocServer32 adds the third.
  // "val" declarations do not add a path component (see registryLocations).
  // https://learn.microsoft.com/en-us/windows/win32/com/appid-key
  // https://learn.microsoft.com/en-us/windows/win32/com/inprocserver32
  if (path[0] === "APPID" && path.length === 2) return "COM application setting";
  if (path[0] !== "CLSID") return null;
  if (path.length === 2 && name === "APPID") return "COM AppID reference";
  if (path.length === 3 && path[2] === "INPROCSERVER32" && name === "THREADINGMODEL") {
    return "COM threading model";
  }
  return null;
};

const interfaceRole = (parts: string[]): string | null => {
  // Interface/<IID> has 2 components; each recognized setting adds one (index 2).
  // https://learn.microsoft.com/en-us/windows/win32/com/interface-key
  if (parts.length === 2) return "COM interface (IID)";
  return parts.length === 3 ? interfaceRoles.get(parts[2]!) ?? null : null;
};

const typeLibraryRole = (parts: string[]): string | null => {
  // TypeLib/<LIBID> has 2 components; version and its descendants have at least 3.
  // https://learn.microsoft.com/en-us/previous-versions/windows/desktop/automat/registering-a-type-library
  if (parts.length === 2) return "COM type library (LIBID)";
  return parts.length >= 3 ? "Type library registration" : null;
};

const classRole = (parts: string[]): string | null => {
  // CLSID/<class> has 2 components, a class setting has 3 (index 2), and
  // CLSID/<class>/Implemented Categories/<CATID> has 4; these are schema depths, not caps.
  // https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm
  // https://learn.microsoft.com/en-us/windows/win32/com/component-categories-manager-implementation
  if (parts.length === 2) return "COM class (CLSID)";
  if (parts.length === 3) return classRoles.get(parts[2]!) ?? null;
  if (parts[2] === "IMPLEMENTED CATEGORIES" && parts.length === 4) {
    return "Implemented COM category (CATID)";
  }
  return null;
};

const progIdRole = (parts: string[], node: RegistryNode): string | null => {
  // <ProgID> has 1 component; its CLSID/CurVer subkey adds one (index 1).
  // https://learn.microsoft.com/en-us/windows/win32/com/-progid--key
  // https://learn.microsoft.com/en-us/windows/win32/com/-version-independent-progid--key
  if (parts.length === 2 && parts[1] === "CLSID") return "ProgID class reference";
  if (parts.length === 2 && parts[1] === "CURVER") return "Current ProgID version";
  if (parts.length === 1 && node.children.some(child => child.name.toUpperCase() === "CLSID")) {
    return "COM programmatic identifier (ProgID)";
  }
  return null;
};

export const registryComRole = ({ node, path }: RegistryLocation): string | null => {
  const parts = classesPath(path);
  if (!parts) return null;
  if (node.directive === "val") return namedRole(parts, node.name.toUpperCase());
  switch (parts[0]) {
    case "CLSID": return classRole(parts);
    case "INTERFACE": return interfaceRole(parts);
    case "TYPELIB": return typeLibraryRole(parts);
    case "APPID": return parts.length === 2 ? "COM application (AppID)" : null;
    default: return progIdRole(parts, node);
  }
};

const checkGuid = (text: string, node: RegistryNode, issues: string[]): void => {
  if (registryParameters(text, []).length) return;
  // StringFromGUID2 representation: braced 8-4-4-4-12 hexadecimal digits.
  // GUID fields: Data1 = 32/4 digits, Data2/Data3 = 16/4 each,
  // Data4's first 2 bytes = 2*8/4 digits, remaining 6 bytes = 6*8/4 digits.
  // https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
  // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-stringfromguid2
  if (!/^\{[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}\}$/iu.test(text)) {
    issues.push(`ATL RGS ${node.line}:${node.column}: invalid COM GUID '${text}'.`);
  }
};

const validateComValue = (role: string, node: RegistryNode, issues: string[]): void => {
  if (node.value?.type !== "REG_SZ") return;
  if (/reference|proxy\/stub|redirection|conversion|Base interface/u.test(role)) {
    checkGuid(node.value.data, node, issues);
  }
  // Empty means no configured model; the four nonempty values are Microsoft's documented set.
  // https://learn.microsoft.com/en-us/windows/win32/com/inprocserver32
  if (role === "COM threading model" && !registryParameters(node.value.data, []).length &&
      !["", "Apartment", "Free", "Both", "Neutral"].includes(node.value.data)) {
    issues.push(`ATL RGS ${node.line}:${node.column}: unrecognized COM threading model.`);
  }
};

export const validateRegistryCom = (script: RegistryScript, issues: string[]): void => {
  for (const location of registryLocations(script)) {
    const role = registryComRole(location);
    if (!role) continue;
    if (/\((?:CLSID|IID|LIBID|CATID)\)$/u.test(role)) {
      checkGuid(location.node.name, location.node, issues);
    }
    validateComValue(role, location.node, issues);
  }
};
