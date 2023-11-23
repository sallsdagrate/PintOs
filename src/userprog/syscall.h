#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define ERROR_STATUS -1
#define SUCCESS_STATUS 0
#define WORD_SIZE 4 //word size in bytes

#define SYSCALL_ARG 0
#define FIRST_ARG 1
#define SECOND_ARG 2
#define THIRD_ARG 3

#define BUFFER_STACK_SIZE 99

#define MAX_SYS_CALL SYS_CLOSE

void syscall_init (void);
typedef int (system_call_t) (void *);

void t_exit (int);
#endif /* userprog/syscall.h */
