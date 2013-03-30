#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

int pid = 0;

void
sighandler (int signal) {
  static int count = 3;
  printf ("%d: Caught signal %d: %lx\n", count++, signal, __builtin_return_address(0));
  fflush (stdout);
  return;
}

int
main (int argc, char ** argv) {
  pid = getpid();
  printf ("1: Setting up signal handler\n");
  fflush (stdout);

  signal (SIGUSR1, sighandler);

  printf ("2: Sending myself the signal\n");
  fflush (stdout);

  kill (getpid(), SIGUSR1);
  kill (getpid(), SIGUSR1);

  printf ("5: Resuming from signal handler\n");
  fflush (stdout);

  return 0;
}

