#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

volatile char * secret = "secret-jtc";
int
main (int argc, char ** argv) {
  printf ("PID = %d\n", getpid());
  fflush (stdout);
  sleep (3600);
  return 0;
}

