#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <unistd.h>

int pid = 0;

void
sighandler (int signal) {
  printf ("3: Caught signal %d: %lx\n", signal, __builtin_return_address(0));
  fflush (stdout);
  return;
}

void
sigacthandler (int signal, siginfo_t * sinfo, void * p) {
  ucontext_t * up = p;

  printf ("4: Caught signal %d: pid=%d, sinfo=%lx, p=%lx\n", signal, pid, sinfo, up);
  printf ("4: Caught signal %d: pid=%d, sig pid=%d, flags=%lx\n", signal, pid, sinfo->si_pid, up->uc_flags);
}

int
main (int argc, char ** argv) {
  struct sigaction usr2action;
  usr2action.sa_sigaction = sigacthandler;
  usr2action.sa_flags = SA_SIGINFO;

  pid = getpid();
  printf ("1: Setting up signal handler\n");
  fflush (stdout);

  signal (SIGUSR1, sighandler);
  sigaction (SIGUSR2, &usr2action, NULL);

  printf ("2: Sending myself the signal\n");
  fflush (stdout);

  kill (getpid(), SIGUSR2);
  kill (getpid(), SIGUSR2);

  printf ("5: Resuming from signal handler\n");
  fflush (stdout);

  return 0;
}

