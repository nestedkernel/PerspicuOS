/*===- appendlog.h - PerspicuOS Protection =---------------------------------===
 *
 * PerspicuOS equivalent log data structure, used for the base line of
 * the system call logging use case.
 *
 * This file was developed by the LLVM research group and is distributed  under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 * TODO: Add description
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _PERSPICUOS_APPENDLOG_H
#define _PERSPICUOS_APPENDLOG_H

/*
 * Declaration of the log_record data structure
 *
 * The log is populated with these objects, that hold
 * information about the processes entering or exiting
 * the kernel
 */
enum persp_log_event {
    PLE_ENTERED,
    PLE_EXITED
};

struct persp_log_record {
    pid_t p_pid; // process pid
    char p_comm[MAXCOMLEN + 1]; // process name
    unsigned short code; // system call code
    int error; // system call return value
    enum persp_log_event event; // event
};

/*
 * Lock that should be obtained for reading or writing the log
 */
extern struct mtx persp_log_mtx;

/* Function prototypes for secure manipulation of the log */
int persp_log_full(void);
int persp_log_empty(void);
void persp_log_syscallenter(unsigned short code, struct thread *td, int overwrite);
void persp_log_syscallexit(int error, struct thread *td, int overwrite);
void persp_log_remove(struct persp_log_record *plr);

#endif /* _PERSPICUOS_APPENDLOG_H */
