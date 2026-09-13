/* hello-usedylib: links libhello.dylib via @rpath. */
extern int hello_global;
extern int hello_add(int, int);
extern int hello_mul(int, int);
extern void hello_print(const char *);
int main(void) {
    hello_global = hello_add(1, 2) + hello_mul(3, 4);
    hello_print("from use_dylib");
    return 0;
}
