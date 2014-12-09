#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/time.h>

#include "sva/dummy.h"
#include "opt_sva_mmu.h"

void sva_nk_bench(void *unused);
void sva_nk_bench(void *unused) {
#ifdef SVA_MMU
    // Attempt to determine average cost of invoking a NK function!
    struct timeval before, after;
    const unsigned ITERS = 1000000;
    const unsigned RUNS = 5;
    long long unsigned usecs;
    for (unsigned r = 0 ; r < RUNS; ++r) {
        microuptime(&before);
        for (unsigned u = 0; u < ITERS; ++u)
            sva_dummy();
        microuptime(&after);
        usecs = (after.tv_usec - before.tv_usec) +
            (after.tv_sec - before.tv_sec)*1000000ULL;
        printf("Calling 'sva_dummy()' %u times took %llu usecs!\n", ITERS, usecs);
    }
#endif // SVA_MMU
}
SYSINIT(nkbench, SI_SUB_CLOCKS+1, SI_ORDER_ANY, sva_nk_bench, NULL);

