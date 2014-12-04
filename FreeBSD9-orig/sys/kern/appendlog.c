/*===- appendlog.c - PerspicuOS Protection =---------------------------------===
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

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/proc.h>

#include <stdio.h>

#include <sys/appendlog.h>

/*
 * Lock that should be obtained for reading or writing the log
 */
struct mtx persp_log_mtx;

/*
 * Statically allocated pspace memory for the append log
 */
#define PERSP_LOG_SIZE 1000
static struct persp_log_record plog[PERSP_LOG_SIZE];

/*
 * Index of the next available slot in the log
 */
static int log_next = 0;

/*
 * Index of the oldest entry in the log
 *
 * If the log is empty, this is negative
 */
static int log_first = -1;

/* 
 * Helper function that is called in system initialization to init the
 * log mutexes
 */
static void persp_log_init(void)
{
    // Assert that the size of the statically allocated memory for log
    // is greater than zero
    if (!(PERSP_LOG_SIZE > 0))
		panic("Space statically allocated memory for append log is"
               "of zero size");

    // Init the log mutex
	mtx_init(&persp_log_mtx, "persp_log_mtx", NULL, MTX_DEF);
}
SYSINIT(persp_log_init, SI_SUB_AUDIT, SI_ORDER_SECOND, persp_log_init, NULL);

/* 
 * Helper function that copies memory
 */
static void *simple_memcpy(void *dest, const void *src, size_t cnt)
{
    unsigned char* dst8 = (unsigned char*) dest;
    unsigned char* src8 = (unsigned char*) src;

    while (cnt--)
        *dst8++ = *src8++;

    return dest;
}

/*
 * Helper function that updates a log entry
 */
static void update_log_entry(int i, pid_t pid, char *comm, size_t comm_len,
        unsigned short code, int error, enum persp_log_event event)
{
    plog[i].p_pid = pid;
    simple_memcpy(&plog[i].p_comm[0], comm, comm_len);
    plog[i].code = code;
    plog[i].error = error;
    plog[i].event = event;
}

/*
 * Function: persp_log_full
 *
 * Description:
 *   This function checks if the log is full
 */
inline int persp_log_full(void)
{
    return log_next == log_first;
}

/*
 * Function: persp_log_empty
 *
 * Description:
 *   This function checks if the log is empty
 */
inline int persp_log_empty(void)
{
    return log_first < 0;
}

/*
 * Function: persp_log_syscallenter
 *
 * Description:
 *   This function will record a syscall enter 
 *
 * Inputs:
 *   code : the code of the system call
 *   td   : the thread of execution that services this system call
 */
void 
persp_log_syscallenter(unsigned short code, struct thread *td, int overwrite)
{
    pid_t pid;
    char *comm;

    // Get information about the system call
    pid = td->td_proc->p_pid;
    comm = &td->td_proc->p_comm[0];

    // Check if the log is full
    if (persp_log_full()) {
        if (overwrite) {
            // Overwrite the first entry
            log_first = (log_first + 1) % PERSP_LOG_SIZE;
            if (log_first == log_next) // the log becomes empty - would only happen
                                       // for a log of size one
                log_first = -1;
        }
        else
            panic("persp_logsyscallenter: Attempted to insert in a full log");
    }

    // Append an entry to the log
    update_log_entry(log_next, pid, comm, MAXCOMLEN + 1, code, 0, PLE_ENTERED);

    // Update the log indices
    if (persp_log_empty())
        log_first = log_next;
    log_next = (log_next + 1) % PERSP_LOG_SIZE;

    printf("persp_log_syscallenter: Process %s (pid %d) entered "
           "system call %u\n", comm, pid, code);
}

/*
 * Function: persp_log_syscallexit
 *
 * Description:
 *   This function will record a syscall exit
 *
 * Inputs:
 *   td   : the thread of execution that services this system call
 */
void 
persp_log_syscallexit(int error, struct thread *td, int overwrite)
{
    pid_t pid;
    char *comm;

    // Get information about the system call
    pid = td->td_proc->p_pid;
    comm = &td->td_proc->p_comm[0];

    // Assert that the log is not full
    if (persp_log_full()) {
        if (overwrite) {
            // Overwrite the first entry
            log_first = (log_first + 1) % PERSP_LOG_SIZE;
            if (log_first == log_next) // the log becomes empty - would only happen
                                       // for a log of size one
                log_first = -1;
        }
        else
            panic("persp_logsyscallexit: Attempted to insert in a full log");
    }

    // Append an entry to the log
    update_log_entry(log_next, pid, comm, MAXCOMLEN + 1, 0, error, PLE_EXITED);

    // Update the log indices
    if (persp_log_empty())
        log_first = log_next;
    log_next = (log_next + 1) % PERSP_LOG_SIZE;

    printf("persp_log_syscallexit: Process %s (pid %d) exited "
           "with return value %d\n", comm, pid, error);
}

/*
 * Function: persp_log_remove
 *
 * Description:
 *   This function will remove a log entry from the start of the block
 *
 * Outputs:
 *   plr : pointer to a persp_log_record object that will be updated
 *         with the information of the removed record
 */
void persp_log_remove(struct persp_log_record *plr)
{
    pid_t pid;
    char *comm;

    // Assert that the log is not empty
    if (persp_log_empty())
        panic("persp_logsyscallexit: Attempted to remove from an empty log");

    // Copy the first log entry to the given record
    plr->p_pid = plog[log_first].p_pid;
    simple_memcpy(&plr->p_comm[0], &plog[log_first].p_comm[0], MAXCOMLEN);
    plr->code = plog[log_first].code;
    plr->event = plog[log_first].event;

    // Update the log indices
    log_first = (log_first + 1) % PERSP_LOG_SIZE;
    if (log_first == log_next) // the log becomes empty
        log_first = -1;
}
