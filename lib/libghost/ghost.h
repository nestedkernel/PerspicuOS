//
// Declare all of the system call wrappers as having C linkage.
//
extern "C" void ghostinit (void);
extern "C" int accept (int s, struct sockaddr * addr, socklen_t * addrlen);
extern "C" int fstat(int fd, struct stat *sb);
