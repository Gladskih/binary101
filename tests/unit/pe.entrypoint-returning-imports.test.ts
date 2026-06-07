"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isKnownReturningImport
} from "../../analyzers/pe/disassembly/entrypoint/returning-imports.js";

void test("isKnownReturningImport accepts documented returning Kernel32 query APIs", () => {
  assert.equal(isKnownReturningImport("KERNEL32.dll!GetSystemTimeAsFileTime"), true);
  assert.equal(isKnownReturningImport("KernelBase.dll!GetTickCount64"), true);
  assert.equal(isKnownReturningImport("KERNEL32.dll!GetStdHandle"), true);
  assert.equal(isKnownReturningImport("KERNEL32.dll!GetModuleHandleW"), true);
  assert.equal(isKnownReturningImport("KERNEL32.dll!GetModuleHandleA"), true);
  assert.equal(isKnownReturningImport("KERNEL32.dll!IsProcessorFeaturePresent"), true);
  assert.equal(isKnownReturningImport("KERNEL32.dll!WriteFile"), true);
  assert.equal(
    isKnownReturningImport("api-ms-win-core-processthreads-l1-1-0.dll!GetCurrentProcessId"),
    true
  );
  assert.equal(isKnownReturningImport("KERNEL32.dll!_WriteFile@20"), true);
});

void test("isKnownReturningImport accepts CRT startup imports", () => {
  assert.equal(
    isKnownReturningImport("api-ms-win-crt-runtime-l1-1-0.dll!_initterm_e"),
    true
  );
  assert.equal(isKnownReturningImport("ucrtbase.dll!_initterm"), true);
  assert.equal(
    isKnownReturningImport("api-ms-win-crt-runtime-l1-1-0.dll!_get_initial_narrow_environment"),
    true
  );
  assert.equal(
    isKnownReturningImport(
      "api-ms-win-crt-runtime-l1-1-0.dll!_register_thread_local_exe_atexit_callback"
    ),
    true
  );
  assert.equal(isKnownReturningImport("api-ms-win-crt-runtime-l1-1-0.dll!__p___argv"), true);
  assert.equal(isKnownReturningImport("api-ms-win-crt-runtime-l1-1-0.dll!__p___argc"), true);
  assert.equal(isKnownReturningImport("api-ms-win-crt-stdio-l1-1-0.dll!puts"), true);
  assert.equal(isKnownReturningImport("api-ms-win-crt-string-l1-1-0.dll!strlen"), true);
  assert.equal(
    isKnownReturningImport("MSVCP140.dll!?good@ios_base@std@@QBE_NXZ"),
    true
  );
  assert.equal(
    isKnownReturningImport(
      "MSVCP140.dll!?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@" +
      "QAEXH_N@Z"
    ),
    true
  );
  assert.equal(
    isKnownReturningImport(
      "MSVCP140.dll!?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV12@XZ"
    ),
    true
  );
  assert.equal(
    isKnownReturningImport("MSVCP140.dll!?uncaught_exception@std@@YA_NXZ"),
    true
  );
  assert.equal(
    isKnownReturningImport(
      "MSVCP140.dll!?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEXXZ"
    ),
    true
  );
  assert.equal(isKnownReturningImport("api-ms-win-crt-runtime-l1-1-0.dll!_cexit"), true);
  assert.equal(isKnownReturningImport("api-ms-win-crt-runtime-l1-1-0.dll!_c_exit"), true);
});

void test(
  "isKnownReturningImport rejects unknown DLLs, unknown functions, and malformed labels",
  () => {
    assert.equal(isKnownReturningImport("KERNEL32.dll!ExitProcess"), false);
    assert.equal(isKnownReturningImport("USER32.dll!GetTickCount64"), false);
    assert.equal(isKnownReturningImport("GetSystemTimeAsFileTime"), false);
  }
);
