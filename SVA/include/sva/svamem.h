#ifndef _SVAMEM_H_
#define _SVAMEM_H_

asm(".section svamem, \"aw\", @nobits");
#define SVAMEM __attribute__((section("svamem")))

#endif // _SVA_MEM_H_

