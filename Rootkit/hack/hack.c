#include <stdio.h>
#include <stdlib.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>

static inline void
setVictimProcess (pid_t pid, unsigned char hackType) {
  syscall (11, pid, hackType);
  return;
}

int
main (int argc, char ** argv) {
  //
  // Check that we have a sufficient number of arguments.
  //
  if (argc != 3) {
    fprintf (stderr, "Usage: %s <victim process ID> <hack type>\n", argv[0]);
    return -1;
  }

  //
  // Convert the target pid and hack type from a string to an integer.
  //
  pid_t victim = atoi (argv[1]);
  unsigned char hackType = atoi (argv[2]);

  //
  // Configure the victim process.
  //
  setVictimProcess (victim, hackType);
  printf ("Victim set to %d: Hack with %d\n", victim, hackType);
  return 0;
}

