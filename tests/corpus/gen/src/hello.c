/* hello-c: minimal C program with a few defined symbols and libc imports. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int global_counter = 7;
const char *greeting = "hello from machre corpus";
static int static_helper(int x) { return x * 3 + 1; }

int add_numbers(int a, int b) { return a + b + global_counter; }

int main(int argc, char **argv) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s (%d args)", greeting, argc);
    puts(buf);
    if (argc > 1 && strcmp(argv[1], "exit") == 0) exit(add_numbers(1, 2));
    return static_helper(argc) & 0;
}
