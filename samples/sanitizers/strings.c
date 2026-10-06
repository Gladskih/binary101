/* Diagnostic-looking strings alone must never be sanitizer evidence. */
const char *sample = "__asan_init __asan_report_load4 libasan.so.8 __tsan_init";

int main(int count, char **arguments) {
  (void)arguments;
  return sample[count & 1];
}
