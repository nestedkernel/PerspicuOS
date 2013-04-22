#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>

char * msg = "Hello SVA!\n";

static inline void
domsg (unsigned long v) {
  __asm__ __volatile__ ("movq $0, %%rdi\n"
                        "movq %0, %%rsi\n"
                        "int $0x7e\n" : : "m" (v));
  return;
}

int
main (int argc, char ** argv) {
  static char * msg = "SVA: child: I can do stuff!\n";
  int fd;
  int size;

  domsg (strlen (msg));
  fd = open ("/tmp/log2", O_WRONLY | O_CREAT | O_TRUNC | O_FSYNC, 0644);
  domsg (fd);
  size = write (fd, msg, strlen(msg));
  domsg (size);
  fd = close (fd);
  domsg (fd);
  sync();
  domsg (0);

  exit(0);
}

