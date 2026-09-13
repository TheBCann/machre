/* hello-dylib: exports 3 functions and 1 global. */
#include <stdio.h>
int hello_global = 42;
int hello_add(int a, int b) { return a + b; }
int hello_mul(int a, int b) { return a * b; }
void hello_print(const char *s) { printf("libhello: %s (%d)\n", s, hello_global); }
