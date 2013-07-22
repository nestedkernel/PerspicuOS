#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>

/*
 * Make direct use of system call use the ghost wrappers.
 */
  int
bind (int s, const struct sockaddr *addr, socklen_t addrlen) {
  return _bind (s, addr, addrlen);
}

  int
getsockopt(int s, int level, int optname, void * optval, socklen_t * optlen) {
  return _getsockopt (s, level, optname, optval, optlen);
}

 int
pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout, sigset_t * sigmask) {
  return _pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

 int
open (char *path, int flags, mode_t mode) {
  return _open (path, flags, mode);
}

 int
close (int fd) {
  return _close (fd);
}

 ssize_t
readlink(char * path, char * buf, size_t bufsiz) {
  return readlink(path, buf, bufsiz) {
}

 int
mkdir(char *path, mode_t mode) {
  return _mkdir (path, mode);
}

 int
stat(const char *path, struct stat *sb) {
  return _stat(path, sb);
}

 int
fstat(int fd, struct stat *sb) {
  return _fstat(fd, sb);
}

  ssize_t
read(int d, void *buf, size_t nbytes) {
  return _read(int d, void *buf, size_t nbytes);
}

 ssize_t
write(int d, void *buf, size_t nbytes) {
  return _write(int d, void *buf, size_t nbytes);
}

 int
clock_gettime(clockid_t clock_id, struct timespec *tp) {
  return _clock_gettime(clockid_t clock_id, struct timespec *tp);
}
