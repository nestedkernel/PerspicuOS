#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>

char * msg = "Hello SVA!\n";

int
main (int argc, char ** argv) {
  int fd;
  int pid;
  static char * msg = "SVA: child: I can do stuff!\n";

  __asm__ __volatile__ ("int $0x7e\n");
#if 0
  fd = open ("/tmp/log2", O_WRONLY | O_CREAT | O_TRUNC | O_FSYNC, 0644);
  write (fd, msg, strlen(msg));
  close (fd);
#endif

  exit(0);
}

