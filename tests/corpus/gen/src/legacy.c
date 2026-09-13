/* legacy-bind: built with -Wl,-no_fixup_chains so LC_DYLD_INFO_ONLY bind/rebase opcodes exist. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int (*cmp_fn)(const void *, const void *);
static int cmp_int(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
/* pointer table forces rebases; libc function pointers force non-lazy binds. */
void *table[] = { (void *)&puts, (void *)&printf, (void *)&cmp_int, (void *)&malloc, (void *)&free };
const char *names[] = { "puts", "printf", "cmp_int", "malloc", "free" };
int main(void) {
    int v[] = { 5, 3, 9, 1 };
    qsort(v, 4, sizeof v[0], (cmp_fn)table[2]);
    for (int i = 0; i < 5; i++) printf("%s=%p\n", names[i], table[i]);
    return strlen(names[0]) == 4 ? v[0] - 1 : 1;
}
