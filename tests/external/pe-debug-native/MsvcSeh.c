extern void sehMayFail(char *storage);
volatile int sehCounter;

__declspec(dllexport) int exerciseSeh(void) {
  // A non-pointer array larger than four bytes qualifies as a GS buffer.
  // https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check
  char storage[32];
  __try { sehMayFail(storage); }
  __except (1) { return 2; }
  return 1;
}

void sehMayFail(char *storage) { storage[0] = (char)++sehCounter; }
