#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#include <stdlib.h>

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct tid_elem {
  tid_t tid;
  int status;
  bool load_status;
  bool checked;
  struct list_elem elem;
};

bool push_args_to_stack (char *file_name, void **esp);
bool enough_stack_left(void **esp, int argc);
#endif /* userprog/process.h */
