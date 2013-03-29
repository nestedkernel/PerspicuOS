#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

void
sighandler (int signal) {
  printf ("3: Caught signal %d: %lx\n", signal, __builtin_return_address(0));
  fflush (stdout);
  return;
}

int
main (int argc, char ** argv) {
  printf ("1: Setting up signal handler\n");
  fflush (stdout);

  signal (SIGUSR1, sighandler);

  printf ("2: Sending myself the signal\n");
  fflush (stdout);

  kill (getpid(), SIGUSR1);

  printf ("4: Resuming from signal handler\n");
  fflush (stdout);

  return 0;
}

