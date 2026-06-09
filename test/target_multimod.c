/*
 * target_multimod.c -- exercises multi-module LCV3 patching by calling
 * into both its own functions and into libmultimod_helper.so. Used by
 * test/run_validation_multimod.sh to verify that gen_patchlist.py
 * --module produces a patch list whose runtime resolves both module
 * load bases correctly and emits edges from both modules.
 *
 * Built -no-pie -fno-stack-protector for deterministic addresses; the
 * helper library is built -fPIC -shared.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmultimod_helper.h"

int main_classify(int v) {
    if (v < -10)  return -2;
    if (v < 0)    return -1;
    if (v == 0)   return  0;
    if (v < 50)   return  1;
    return 2;
}

void main_print(int v) {
    int c = main_classify(v);
    if (c < 0)       printf("M:neg c=%d v=%d\n", c, v);
    else if (c == 0) printf("M:zero\n");
    else             printf("M:pos c=%d v=%d\n", c, v);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        int v = atoi(argv[i]);
        main_print(v);
        helper_print(argv[i], v);
        int h = helper_classify(v);
        printf("class main=%d helper=%d\n", main_classify(v), h);
    }
    return 0;
}
