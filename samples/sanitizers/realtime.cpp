int sample(int value) [[clang::nonblocking]] {
  return value + 1;
}

int main(int count, char **) {
  return sample(count);
}
