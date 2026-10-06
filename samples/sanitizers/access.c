/* Keep accesses observable at -O0 without deliberately executing a fault. */
int sample(int *pointer, int index) {
  return pointer[index] + index + 1;
}

int main(int count, char **arguments) {
  int values[2] = {1, 2};
  (void)arguments;
  return sample(values, count & 1);
}
