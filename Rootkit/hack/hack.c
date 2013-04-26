#include <stdio.h>
#include <stdlib.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>

static inline void
setVictimProcess (pid_t pid, int hackType, uintptr_t addr, uintptr_t len) {
  syscall (11, pid, hackType, addr, len);
  return;
}

int
main (int argc, char ** argv) {
  //
  // Check that we have a sufficient number of arguments.
  //
  if (argc != 5) {
    fprintf (stderr, "Usage: %s <victim process ID> <hack type>\n", argv[0]);
    return -1;
  }

  //
  // Convert the target pid and hack type from a string to an integer.
  //
  pid_t victim = atoi (argv[1]);
  int hackType = atoi (argv[2]);
  uintptr_t addr = atoi (argv[3]);
  uintptr_t len = atoi (argv[4]);

  //
  // Configure the victim process.
  //
  setVictimProcess (victim, hackType, addr, len);
  printf ("Victim set to %d: Hack with %d\n", victim, hackType);
  return 0;
}

