#ifndef _SYS_NK_DUMMY_H_
#define _SYS_NK_DUMMY_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/proc.h>

int sys_nk_dummy(struct thread *td, struct nk_dummy_args *args);

#endif // _SYS_NK_DUMMY_H_
