//
// Declare all of the system call wrappers as having C linkage.
//
extern "C" void ghostinit (void);

extern "C" int _accept (int s, struct sockaddr * addr, socklen_t * addrlen);
extern "C" int _open (char *path, int flags, mode_t mode);
extern "C" ssize_t _readlink(char * path, char * buf, size_t bufsiz);
extern "C" int _mkdir(char *path, mode_t mode);
extern "C" int _stat(const char *path, struct stat *sb);
extern "C" int _fstat(int fd, struct stat *sb);
