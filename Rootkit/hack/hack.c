#include <stdio.h>
#include <stdlib.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>

static inline void
setVictimProcess (pid_t pid) {
  syscall (11, pid);
  return;
}

int
main (int argc, char ** argv) {
  //
  // Check that we have a sufficient number of arguments.
  //
  if (argc != 2) {
    fprintf (stderr, "Usage: %s <victim process ID>\n", argv[0]);
    return -1;
  }

  //
  // Convert the target pid into a string.
  //
  pid_t victim = atoi (argv[1]);

  //
  // Configure the victim process.
  //
  setVictimProcess (victim);
  printf ("Victim set to %d\n", victim);
  return 0;
}

