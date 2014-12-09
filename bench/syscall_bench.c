#include <stdio.h>
#include <sys/time.h>

int nk_dummy();
int nk_dummy_gettime(struct timeval *tv);

void syscall_bench() {
    struct timeval before, after;
    const unsigned ITERS = 1000000;
    const unsigned RUNS = 5;
    long long unsigned usecs;
    unsigned r, u;
    for (r = 0 ; r < RUNS; ++r) {
        nk_dummy_gettime(&before);
        for (u = 0; u < ITERS; ++u)
            nk_dummy();
        nk_dummy_gettime(&after);
        usecs = (after.tv_usec - before.tv_usec) +
            (after.tv_sec - before.tv_sec)*1000000ULL;
        printf("Syscall to nk_dummy %u times took %llu usecs!\n", ITERS, usecs);
    }
}

int main() {
    syscall_bench();
}
