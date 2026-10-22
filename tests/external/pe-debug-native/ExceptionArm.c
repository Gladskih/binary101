__declspec(noinline) int leaf(int value) {
  volatile int values[16];
  values[0] = value;
  return values[0];
}
int entry(void) { return leaf(7); }
