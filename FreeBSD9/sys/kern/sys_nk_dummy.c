#include <sys/nk_dummy.h>

int sys_nk_dummy(struct thread *td, struct nk_dummy_args *args) {
    // return value
    td->td_retval[0] = 0;
    // errno
    return 0;
}
