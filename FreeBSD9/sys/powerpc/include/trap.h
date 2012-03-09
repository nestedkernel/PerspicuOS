/* $FreeBSD: release/9.0.0/sys/powerpc/include/trap.h 176770 2008-03-03 13:20:52Z raj $ */

#if defined(AIM)
#include <machine/trap_aim.h>
#elif defined(E500)
#include <machine/trap_booke.h>
#endif

#ifndef LOCORE
struct trapframe;
void    trap(struct trapframe *);
#endif
