#include "stack.h"

#include <stdio.h>

char TestStack[1 << 20];

// Initialize stack pointer to bottom of stack area:
uintptr_t SecureStackBase = (uintptr_t)TestStack + sizeof(TestStack);

int main() {
  printf("TestFunc(3,5) = %d\n", TestFunc(3, 5));
  return 0;
}

void Foobar() {
  // Random computation nonsense
  unsigned i;
  for (i = 0; i < 100; ++i) {
    if (i * SecureStackBase < i) {
      printf("%u\n", i);
    }
  }
}

SECURE_WRAPPER(int, TestFunc, int a, int b) {
  // Can we call other non-trivial functions?
  // Let's find out, go go gadget printf:
  printf("a=%d, b=%d\n", a, b);
  // (This should also help ensure our arguments are intact)

  // Try calling other functions...
  Foobar();

  // Check return path works via simple calculation:
  return a + b;
}
