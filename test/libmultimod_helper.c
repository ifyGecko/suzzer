/*
 * libmultimod_helper.c -- tiny shared library used by target_multimod to
 * exercise LCV3 multi-module patching. Two leaf functions, each with a
 * couple of conditional branches that gen_patchlist will pick up as
 * patch sites distinct from those in the main executable.
 */
#include <stdio.h>
#include <string.h>

#include "libmultimod_helper.h"

int helper_classify(int v) {
    if (v < 0)   return -1;
    if (v == 0)  return  0;
    if (v < 10)  return  1;
    if (v < 100) return  2;
    return 3;
}

void helper_print(const char *tag, int v) {
    if (!tag) tag = "?";
    if (v < 0)        printf("H:%s neg=%d\n", tag, v);
    else if (v == 0)  printf("H:%s zero\n",   tag);
    else              printf("H:%s pos=%d\n", tag, v);
}
