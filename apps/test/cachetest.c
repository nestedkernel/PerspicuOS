/* Put this code into SVA/lib/secmem.c to test for cache behavior */
#if 1
  volatile unsigned char * p = (unsigned char *)(SECMEMSTART);
  volatile unsigned char v = 'z';
  volatile unsigned char v1 = 'y';

  extern uintptr_t * get_pgeVaddr (uintptr_t vaddr);
  uintptr_t * pte = get_pgeVaddr (SECMEMSTART);

  /* Write initial values into the two pages */
  __asm__ __volatile__ ("cli\n");
  unprotect_paging ();
  p[0] = 'a';
  *pte += 0x1000;
  __asm__ __volatile__ ("invlpg %0" : : "m" (*((char *)p)) : "memory");
  p[0] = 'b';
  *pte -= 0x1000;
  __asm__ __volatile__ ("invlpg %0" : : "m" (*((char *)p)) : "memory");

  while (1) {
    /* Load the value into the cache */
    __asm__ __volatile__ ("wbinvd\n");
    v1 = p[0];

    /* Change the translation and re-read the value */
    *pte += 0x1000;
    __asm__ __volatile__ ("invlpg %0" : : "m" (*((char *)p)) : "memory");
    v = p[0];

    /* See if we get the correct value of 'b' */
    if (v != 'b')
      panic ("SVA: Bad Cache %lx %lx %c %x\n", p, pte, v, v);
    else
      printf ("SVA: Good Cache %lx %lx %c %x\n", p, pte, v, v);
    *pte -= 0x1000;
  }
#endif

