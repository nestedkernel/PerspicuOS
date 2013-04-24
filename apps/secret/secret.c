#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>

volatile char * secret = "\nsecret-jtc";
int
main (int argc, char ** argv) {
  int fds[2];

  /*
   * Create a pipe.
   */
  if (pipe (fds) == -1) {
    printf ("pipe error: %d\n", errno);
  }

  printf ("%p %lx\n", secret, strlen (secret));
  printf ("PID = %d\n", getpid());
  fflush (stdout);

  /*
   * Read and write data on the pipe.
   */
  do {
    static unsigned char buf;
    write (fds[1], "c", 1);
    printf ("w");
    fflush (stdout);

    read (fds[0], &buf, 1);
    printf ("r");
    fflush (stdout);

    sleep (5);
  } while (1);

  return 0;
}

