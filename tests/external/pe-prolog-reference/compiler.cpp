// Deliberately header-free so the same source works with independent Windows toolchains.
#if defined(_MSC_VER)
extern "C" void *_alloca(unsigned long long);
#pragma intrinsic(_alloca)
#define LOCAL_ALLOC(size) _alloca(size)
#else
#define LOCAL_ALLOC(size) __builtin_alloca(size)
#endif

volatile unsigned long long observed;
__declspec(noinline) unsigned long long consume(volatile unsigned char *data, unsigned length) {
  unsigned long long result = 0;
  for (unsigned index = 0; index < length; index++) result = result * 33 + data[index];
  observed = result;
  return result;
}

__declspec(noinline) unsigned long long fixed_frame(unsigned seed) {
  volatile unsigned char data[8192];
  for (unsigned index = 0; index < sizeof(data); index++) data[index] = (unsigned char)(index + seed);
  return consume(data, sizeof(data));
}

__declspec(noinline) unsigned long long aligned_frame(unsigned seed) {
  alignas(64) volatile unsigned char data[192];
  for (unsigned index = 0; index < sizeof(data); index++) data[index] = (unsigned char)(seed - index);
  return consume(data, sizeof(data));
}

__declspec(noinline) unsigned long long dynamic_frame(unsigned length) {
  auto data = (volatile unsigned char *)LOCAL_ALLOC(length);
  for (unsigned index = 0; index < length; index++) data[index] = (unsigned char)index;
  return consume(data, length);
}

__declspec(noinline) unsigned long long exception_frame(unsigned seed) {
  try {
    if (seed & 1) throw seed;
    return fixed_frame(seed) + aligned_frame(seed);
  } catch (unsigned value) {
    return dynamic_frame(value + 64);
  }
}

int main(int count, char **) {
  return (int)exception_frame((unsigned)count);
}
