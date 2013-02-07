#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

char * msg = "Hello SVA!\n";

int
main (int argc, char ** argv) {
  int fd = 0;
  int pid = 5;

  /*
   * Open a file to record data.
   */
#if 0
  fd = open ("/tmp/log1", O_WRONLY | O_CREAT | O_TRUNC | O_FSYNC, 0644);
  if (fd == -1) {
    __asm__ __volatile__ ("movq %0, %%rdi\n"
                          "int $0x7e\n" : : "m" (errno));
  }

  __asm__ __volatile__ ("movq %0, %%rdi\n"
                        "int $0x7f\n" : : "i" (0));

  /*
   * Make this file stdout.
   */
  close (STDOUT_FILENO);
  close (STDERR_FILENO);
  dup2 (fd, STDOUT_FILENO);
  dup2 (fd, STDERR_FILENO);

  __asm__ __volatile__ ("movq %0, %%rdi\n"
                        "int $0x7f\n" : : "i" (1));
#endif

  /*
   * Create a child process.
   */
  pid = fork ();

  switch (pid) {
    case 0: {
#if 0
      static char * msg = "SVA: child: Try to exec!\n";
      static char * bad = "SVA: child: exec failed!\n";
#endif
      __asm__ __volatile__ ("movq %0, %%rdi\n"
                            "int $0x7f\n" : : "m" (pid));
#if  0
      write (fd, msg, strlen(msg));
#endif
      execlp ("/sbin/panic2", "/sbin/panic2", 0);
#if 0
      __asm__ __volatile__ ("movq %0, %%rdi\n"
                            "int $0x7e\n" : : "m" (errno));
      write (fd, bad, strlen(bad));
      close (fd);
#endif
      while (1) { ; }
      break;
    }

    case -1:
      while (1) { ; }
      break;

    default: {
#if 0
      static char * msg = "SVA: parent: fork worked!\n";
      write (fd, msg, strlen(msg));
#endif
      __asm__ __volatile__ ("movq %0, %%rdi\n"
                            "int $0x7f\n" : : "m" (pid));
      while (1) { ; }
      break;
    }
  }

  return 0;
}

