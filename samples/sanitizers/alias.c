int sample(int *integer, float *floating) {
  *floating = 1.0f;
  return *integer;
}

int main(void) {
  int value = 0;
  return sample(&value, (float *)&value);
}
