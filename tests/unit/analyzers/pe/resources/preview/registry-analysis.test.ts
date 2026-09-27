import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRegistryScript } from "../../../../../../analyzers/pe/resources/preview/registry-parser.js";
import {
  registryLocations, registryComRole, validateRegistryCom
} from "../../../../../../analyzers/pe/resources/preview/registry-analysis.js";
import type { RegistryLocation } from "../../../../../../analyzers/pe/resources/preview/registry-analysis.js";

const locationAt = (path: string[], name = path.at(-1) ?? ""): RegistryLocation => ({
  path,
  node: { name, directive: "key", line: 1, column: 1, value: null, children: [] }
});

void test("iterative traversal preserves unknown hives, named-value paths and sibling order", () => {
  const locations = [...registryLocations(parseRegistryScript(
    "Unknown { First { val Name = s 'value' } Sibling } HKCU { Last }", []))];
  assert.deepEqual(locations.map(({ node, path }) => [node.name, path]), [
    ["First", ["Unknown", "First"]], ["Name", ["Unknown", "First"]],
    ["Sibling", ["Unknown", "Sibling"]], ["Last", ["HKEY_CURRENT_USER", "Last"]]
  ]);
});

// CLSID and Interface subkeys from Microsoft's COM registry schema (links in production).
for (const [group, key, expected] of [
  ["CLSID", "InprocServer32", "In-process COM server"],
  ["CLSID", "LocalServer32", "Out-of-process COM server"],
  ["CLSID", "InprocHandler32", "In-process COM handler"],
  ["CLSID", "ProgID", "Versioned ProgID"],
  ["CLSID", "VersionIndependentProgID", "Version-independent ProgID"],
  ["CLSID", "TypeLib", "Type library reference"], ["CLSID", "Version", "Type library version"],
  ["CLSID", "AppID", "COM AppID reference"], ["CLSID", "TreatAs", "COM class redirection"],
  ["CLSID", "AutoConvertTo", "COM class conversion"],
  ["Interface", "ProxyStubClsid32", "Interface proxy/stub CLSID"],
  ["Interface", "ProxyStubClsid", "Interface proxy/stub CLSID"],
  ["Interface", "TypeLib", "Type library reference"], ["Interface", "NumMethods", "Interface method count"],
  ["Interface", "BaseInterface", "Base interface IID"]
] as const) {
  void test(`COM role ${group}/${key} has its exact schema meaning`, () => {
    assert.equal(registryComRole(locationAt(["HKEY_CLASSES_ROOT", group, "%ID%", key])), expected);
  });
}

for (const path of [
  ["HKEY_CLASSES_ROOT"], ["HKEY_CURRENT_USER"],
  ["HKEY_CLASSES_ROOT", "CLSID"], ["HKEY_CLASSES_ROOT", "Interface"],
  ["HKEY_CLASSES_ROOT", "TypeLib"], ["HKEY_CLASSES_ROOT", "AppID"],
  ["HKEY_USERS", "Software", "Classes", "CLSID", "%ID%"],
  ["HKEY_CURRENT_USER", "Other", "Classes", "CLSID", "%ID%"],
  ["HKEY_CURRENT_USER", "Software", "Other", "CLSID", "%ID%"],
  ["HKEY_LOCAL_MACHINE", "Software", "Classes", "Other"],
  ["HKEY_CLASSES_ROOT", "AppID", "%ID%", "Other"],
  ["HKEY_CLASSES_ROOT", "Interface", "%ID%", "TypeLib", "Other"],
  ["HKEY_CLASSES_ROOT", "CLSID", "%ID%", "Other", "Nested"],
  ["HKEY_CLASSES_ROOT", "Other", "Nested", "CurVer"],
  ["HKEY_CLASSES_ROOT", "Other", "Nested", "CLSID"],
  ["HKEY_CLASSES_ROOT", "Sample", "CLSID", "Extra"],
  ["HKEY_CLASSES_ROOT", "Sample", "CurVer", "Extra"],
  ["HKEY_CLASSES_ROOT", "Other", "Other"],
  ["HKEY_CLASSES_ROOT", "CLSID", "%ID%", "Other"],
  ["HKEY_CLASSES_ROOT", "CLSID", "%ID%", "Implemented Categories"],
  ["HKEY_CLASSES_ROOT", "CLSID", "%ID%", "Implemented Categories", "%CATID%", "Extra"]
]) {
  void test(`COM-looking path ${path.join("/")} outside schema is not classified`, () => {
    assert.equal(registryComRole(locationAt(path)), null);
  });
}

void test("machine Classes registrations have the same COM meaning as HKCR", () => {
  assert.equal(registryComRole(locationAt(
    ["HKEY_LOCAL_MACHINE", "Software", "Classes", "CLSID", "%ID%"])), "COM class (CLSID)");
});

for (const [path, name, expected] of [
  [["HKEY_CLASSES_ROOT", "CLSID", "%ID%"], "AppID", "COM AppID reference"],
  [["HKEY_CLASSES_ROOT", "CLSID", "%ID%", "InprocServer32"], "ThreadingModel", "COM threading model"],
  [["HKEY_CLASSES_ROOT", "AppID", "%ID%"], "LocalService", "COM application setting"],
  [["HKEY_CLASSES_ROOT", "CLSID", "%ID%"], "Unknown", null],
  [["HKEY_CLASSES_ROOT", "Other", "%ID%"], "AppID", null],
  [["HKEY_CLASSES_ROOT", "Other", "%ID%", "InprocServer32"], "ThreadingModel", null],
  [["HKEY_CLASSES_ROOT", "CLSID", "%ID%", "Extra"], "AppID", null],
  [["HKEY_CLASSES_ROOT", "CLSID", "%ID%"], "ThreadingModel", null],
  [["HKEY_CLASSES_ROOT", "CLSID", "%ID%", "Other"], "ThreadingModel", null],
  [["HKEY_CLASSES_ROOT", "CLSID", "%ID%", "InprocServer32"], "Unknown", null],
  [["HKEY_CLASSES_ROOT", "CLSID", "%ID%", "InprocServer32", "Extra"], "ThreadingModel", null],
  [["HKEY_CLASSES_ROOT", "AppID", "%ID%", "Other"], "LocalService", null],
  [["HKEY_CLASSES_ROOT", "Other"], "ThreadingModel", null]
] as const) {
  void test(`named COM role ${path.join("/")}/${name} respects key depth`, () => {
    const location = locationAt([...path], name);
    location.node.directive = "val";
    assert.equal(registryComRole(location), expected);
  });
}

void test("COM roles are limited to class registration hives and include per-user classes", () => {
  const script = parseRegistryScript(
    "HKCU { Software { Classes { CLSID { '%CLSID%' { InprocServer32 = s '%MODULE%' " +
    "{ val ThreadingModel = s 'Apartment' } } } } } }", []);
  const locations = [...registryLocations(script)];
  assert.equal(registryComRole(locations[3]!), "COM class (CLSID)");
  assert.equal(registryComRole(locations[4]!), "In-process COM server");
  assert.equal(registryComRole(locations[5]!), "COM threading model");
  const unrelated = [...registryLocations(parseRegistryScript(
    "HKLM { CLSID { Foo { InprocServer32 = s 'file.dll' } } }", []))];
  assert.equal(registryComRole(unrelated[2]!), null);
});

void test("ProgID detection requires a direct CLSID child and respects path depth", () => {
  const valid = locationAt(["HKEY_CLASSES_ROOT", "Sample"]);
  valid.node.children = [locationAt([], "Other").node, locationAt([], "clsid").node];
  assert.equal(registryComRole(valid), "COM programmatic identifier (ProgID)");
  const nested = locationAt(["HKEY_CLASSES_ROOT", "Sample", "Nested"]);
  nested.node.children = valid.node.children;
  assert.equal(registryComRole(nested), null);
  const wrong = locationAt(["HKEY_CLASSES_ROOT", "Other"]);
  wrong.node.children = [locationAt([], "Other").node];
  assert.equal(registryComRole(wrong), null);
  assert.equal(registryComRole(locationAt(["HKEY_CLASSES_ROOT", "Sample", "CurVer"])),
    "Current ProgID version");
  assert.equal(registryComRole(locationAt(["HKEY_CLASSES_ROOT", "TypeLib", "%ID%", "1.0"])),
    "Type library registration");
});

void test("validation ignores ordinary values even when they resemble invalid COM identifiers", () => {
  const issues: string[] = [];
  validateRegistryCom(parseRegistryScript("HKCR { Ordinary = s 'broken' { val Name = s 'bad' } }", []), issues);
  assert.deepEqual(issues, []);
});

void test("COM validation warns on invalid GUIDs and threading models", () => {
  const issues: string[] = [];
  validateRegistryCom(parseRegistryScript(
    "HKCR { CLSID { Broken { InprocServer32 { val ThreadingModel = s 'Unsupported' } } } }", []
  ), issues);
  assert.match(issues.join(" "), /GUID/);
  assert.match(issues.join(" "), /threading model/i);
});

const GUID = "{44EC053A-400F-11D0-9DCD-00A0C90391D3}";

void test("COM schema covers classes, interfaces, type libraries, applications and ProgIDs", () => {
  const script = parseRegistryScript(`HKCR {
    CLSID { '${GUID}' {
      LocalServer32 = s '%MODULE_RAW%' InprocHandler32 = s 'handler.dll'
      ProgID = s 'Sample.1' VersionIndependentProgID = s 'Sample'
      TypeLib = s '${GUID}' Version = s '1.0' AppID = s '${GUID}'
      TreatAs = s '${GUID}' AutoConvertTo = s '${GUID}'
      val AppID = s '${GUID}' val Unknown = s 'data'
      'Implemented Categories' { '${GUID}' }
    } }
    Interface { '${GUID}' {
      ProxyStubClsid32 = s '${GUID}' ProxyStubClsid = s '${GUID}'
      TypeLib = s '${GUID}' NumMethods = d '3' BaseInterface = s '${GUID}'
      Unknown
    } }
    TypeLib { '${GUID}' { '1.0' { '0' { win32 = s '%MODULE%' } } } }
    AppID { '${GUID}' { val LocalService = s 'service' } }
    Sample { CLSID = s '${GUID}' CurVer = s 'Sample.1' }
  } HKLM { Software { Classes { CLSID { '%ID%' } } } }`, []);
  const roles = [...registryLocations(script)].map(registryComRole);
  assert.ok(roles.includes("COM interface (IID)"));
  assert.ok(roles.includes("COM type library (LIBID)"));
  assert.ok(roles.includes("COM application (AppID)"));
  assert.ok(roles.includes("COM application setting"));
  assert.ok(roles.includes("Out-of-process COM server"));
  assert.ok(roles.includes("In-process COM handler"));
  assert.ok(roles.includes("COM programmatic identifier (ProgID)"));
  assert.ok(roles.includes("ProgID class reference"));
  assert.ok(roles.includes("Current ProgID version"));
  assert.ok(roles.includes("Type library registration"));
  assert.ok(roles.includes("Implemented COM category (CATID)"));
  assert.ok(roles.includes("COM AppID reference"));
  const issues: string[] = [];
  validateRegistryCom(script, issues);
  assert.deepEqual(issues, []);
});

void test("COM validation preserves symbolic IDs and diagnoses malformed references", () => {
  const issues: string[] = [];
  validateRegistryCom(parseRegistryScript(`HKCR { CLSID { '%ID%' {
    TypeLib = s 'broken' val AppID = d '1' Unknown
    InprocServer32 { val ThreadingModel = s '%THREADING%' }
  } } }`, []), issues);
  assert.equal(issues.length, 1);
  assert.match(issues[0] ?? "", /GUID/);
});

for (const invalid of [GUID.slice(1, -1), `${GUID}extra`, `extra${GUID}`,
  GUID.replace("44EC", "44EG"), GUID.replace("400F", "400"), GUID.replace("400F", "400FF")]) {
  void test(`COM GUID ${invalid} is not accepted by partial matching`, () => {
    const issues: string[] = [];
    validateRegistryCom(parseRegistryScript(`HKCR { CLSID { '${invalid}' } }`, []), issues);
    assert.equal(issues.length, 1);
  });
}

for (const model of ["", "Apartment", "Free", "Both", "Neutral"]) {
  void test(`COM threading model '${model}' is recognized`, () => {
    const issues: string[] = [];
    validateRegistryCom(parseRegistryScript(`HKCR { CLSID { '${GUID}' {
      InprocServer32 { val ThreadingModel = s '${model}' } } } }`, []), issues);
    assert.deepEqual(issues, []);
  });
}
