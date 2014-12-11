#include <sys/nk_dummy.h>

int sys_nk_dummy_gettime(struct thread *td, struct nk_dummy_gettime_args *args) {
    // XXX: Error checking, >>.<<
    // "What could possibly go wrong"
    microuptime(args->tv);
    // return value
    td->td_retval[0] = 0;
    // errno
    return 0;
}

int sys_nk_dummy(struct thread *td, struct nk_dummy_args *args) {
    // return value
    td->td_retval[0] = 0;
    // errno
    return 0;
}
