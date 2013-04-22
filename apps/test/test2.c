#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char ** argv) {
  unsigned char * ptr = (unsigned char *) 0xffffff0000000000u;
  unsigned index;
  unsigned int status;

  for (index = 0; index < 10; ++index) {
    printf ("Address: %p %c\n", &(ptr[index]), ptr[index]);
    fflush (stdout);
  }

  return 0;
}
