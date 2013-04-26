#include <stdio.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <fcntl.h>

int
main (int argc, char ** argv) {
  int fd;
  struct stat sb;
  extern void ghostinit (void);
  ghostinit();

  if (argc < 2) {
    fprintf (stderr, "Specify filename please\n");
    return 1;
  }

  fd = open (argv[1], O_RDONLY);
  fstat (fd, &sb);
  printf ("file uid = %d\n", sb.st_uid);
  return 0;
}
