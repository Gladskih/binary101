extern void ehMayThrow();
volatile int ehCounter;

struct EhGuard {
  ~EhGuard() { ++ehCounter; }
};

extern "C" __declspec(dllexport) int exerciseEh() {
  EhGuard guard;
  try { ehMayThrow(); }
#ifndef EH_CATCH_ALL_ONLY
  catch (int) { return 3; }
#endif
  catch (...) { return 4; }
  return 1;
}
