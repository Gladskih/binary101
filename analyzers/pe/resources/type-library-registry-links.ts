"use strict";

import { registryComRole, registryLocations } from "./preview/registry-analysis.js";
import type { PeResources } from "./index.js";

export interface TypeLibraryRegistrationLink {
  kind: "LIBID" | "CLSID" | "IID";
  guid: string;
  library: string;
  name: string;
  registryResource: string;
}

type RegistrationTarget = Pick<TypeLibraryRegistrationLink, "kind" | "guid" | "library" | "name">;

const guidKey = (value: string | null): string | null => {
  if (!value) return null;
  // GUID textual form follows StringFromGUID2; braces are optional for type library GUIDs.
  // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-stringfromguid2
  if (value.startsWith("{") !== value.endsWith("}")) return null;
  const inner = value.startsWith("{") ? value.slice(1, -1) : value;
  return /^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/iu.test(inner)
    ? inner.toLowerCase() : null;
};

const addTarget = (
  targets: Map<string, RegistrationTarget[]>, kind: RegistrationTarget["kind"],
  guid: string | null, library: string, name: string
): void => {
  const normalized = guidKey(guid);
  if (!normalized) return;
  const key = `${kind}:${normalized}`;
  targets.set(key, [...(targets.get(key) ?? []), { kind, guid: normalized, library, name }]);
};

const libraryTargets = (resources: PeResources): Map<string, RegistrationTarget[]> => {
  const targets = new Map<string, RegistrationTarget[]>();
  for (const group of resources.detail) {
    if (group.typeName !== "TYPELIB") continue;
    for (const entry of group.entries) for (const lang of entry.langs) {
      const analysis = lang.typeLibrary?.analysis;
      if (!analysis) continue;
      const library = analysis.name ?? entry.name ?? String(entry.id ?? "?");
      addTarget(targets, "LIBID", analysis.guid, library, library);
      for (const type of analysis.types) {
        // TYPEKIND: 3 = interface, 4 = dispinterface, 5 = coclass.
        // https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ne-oaidl-typekind
        if (type.kind === 5) addTarget(targets, "CLSID", type.guid, library, type.name ?? "?");
        if (type.kind === 3 || type.kind === 4) {
          addTarget(targets, "IID", type.guid, library, type.name ?? "?");
        }
      }
    }
  }
  return targets;
};

const registrationKind = (role: string | null): RegistrationTarget["kind"] | null => {
  if (role === "COM type library (LIBID)") return "LIBID";
  if (role === "COM class (CLSID)") return "CLSID";
  if (role === "COM interface (IID)") return "IID";
  return null;
};

export const analyzeTypeLibraryRegistrations = (
  resources: PeResources | null
): TypeLibraryRegistrationLink[] => {
  if (!resources) return [];
  const targets = libraryTargets(resources);
  const links: TypeLibraryRegistrationLink[] = [];
  const seen = new Set<string>();
  for (const group of resources.detail) for (const entry of group.entries) {
    for (const lang of entry.langs) {
      if (!lang.registry) continue;
      const registryResource = entry.name ?? String(entry.id ?? "?");
      for (const location of registryLocations(lang.registry)) {
        const kind = registrationKind(registryComRole(location));
        const guid = guidKey(location.node.name);
        if (!kind || !guid) continue;
        for (const target of targets.get(`${kind}:${guid}`) ?? []) {
          const link = { ...target, registryResource };
          const key = JSON.stringify(link);
          if (!seen.has(key)) { seen.add(key); links.push(link); }
        }
      }
    }
  }
  return links;
};
