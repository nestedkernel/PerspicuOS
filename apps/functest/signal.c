#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

void
handler (int sig, siginfo_t * siginfo, void * extra) {
  printf ("Signal: %d\n", sig);
  return;
}

int
main (int argc, char ** argv) {
  struct sigaction act;

  /*
   * Configure a signal handler.
   */
  bzero (&act, sizeof (struct sigaction));
  act.sa_sigaction = handler;
  act.sa_flags = SA_SIGINFO;
  sigaction (SIGEMT, &act, NULL);
  sigaction (SIGSYS, &act, NULL);

  /*
   * Send ourselves the signal.
   */
  kill (getpid(), SIGEMT);
  kill (getpid(), SIGSYS);
  printf ("Done\n");
  return 0;
}

