/* fake-packed: custom __XHDR segment so name-based packer heuristics fire. */
#include <stdio.h>
__attribute__((section("__XHDR,__xhdr"))) const unsigned char xhdr_blob[256] = { 0x55, 0x50, 0x58, 0x21, 1, 2, 3, 4 };
__attribute__((section("__XHDR,__text2"))) const char xhdr_note[] = "not really packed";
int main(void) { printf("xhdr[0]=%d %s\n", xhdr_blob[0], xhdr_note); return 0; }
