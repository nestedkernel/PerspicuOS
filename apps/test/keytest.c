#include <stdio.h>
#include <stdlib.h>

#include "sva/userghost.h"

int
main (int argc, char ** argv) {
  unsigned index;
  unsigned char * key = sva_get_key();
  for (index = 0; index < 256; ++index) {
    printf ("%c", key[index]);
  }
  printf ("\n");
  return 0;
}
