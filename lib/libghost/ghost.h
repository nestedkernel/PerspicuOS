//
// Declare all of the system call wrappers as having C linkage.
//
extern "C" void ghostinit (void);

extern "C" int _bind(int s, const struct sockaddr *addr, socklen_t addrlen);
extern "C" int _getsockopt(int s, int level, int optname, void * optval, socklen_t * optlen);
extern "C" int _pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout, sigset_t * sigmask);
extern "C" int _open (char *path, int flags, mode_t mode);
extern "C" int _close (int fd);
extern "C" ssize_t _readlink(char * path, char * buf, size_t bufsiz);
extern "C" int _mkdir(char *path, mode_t mode);
extern "C" int _stat(char *path, struct stat *sb);
extern "C" int _fstat(int fd, struct stat *sb);
extern "C" ssize_t _read(int d, void *buf, size_t nbytes);
extern "C" ssize_t _write(int d, void *buf, size_t nbytes);
extern "C" int _clock_gettime(clockid_t clock_id, struct timespec *tp);
extern "C" struct passwd * ghost_getpwuid (uid_t uid);
extern "C" int gethostname(char * name, size_t namelen);
extern "C" int ghost_getaddrinfo (char *hostname, char *servname,
             struct addrinfo *hints, struct addrinfo **res);
extern "C" int ghost_connect(int s, const struct sockaddr *addr, socklen_t addrlen);
extern "C" int ghost_accept (int s, struct sockaddr * addr, socklen_t * addrlen);
extern "C" int ghost_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
extern "C" int ghost_getpeereid(int s, uid_t *euid, gid_t *egid);
extern "C" ssize_t ghost_read(int d, void *buf, size_t nbytes);
extern "C" ssize_t ghost_write(int d, void *buf, size_t nbytes);
extern "C" sig_t ghost_signal (int sig, sig_t func);
extern "C" int ghost_sigaction (int sig, struct sigaction * act, struct sigaction * oact);
extern "C" int ghost_open (char *path, int flags, mode_t mode);
extern "C" int ghost_stat(char *path, struct stat *sb);

extern "C" int _getsockname(int s, struct sockaddr * name, socklen_t * namelen);

extern "C" void ghostAllowFunction (void * f);
