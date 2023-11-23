#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/user/syscall.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "threads/malloc.h"

#include "process.h"
#include "threads/interrupt.h"
#include "devices/input.h"


static void syscall_handler (struct intr_frame*);
static void *access_user_memory (void *);
static struct file *get_file_by_fd (int);
static struct lock file_lock; //lock for accessing filesystem
static struct file_fd *get_file_fd_by_fd (int);
static int write_holder(int, char[], int);
static int read_holder(int, char[], int);
static void get_holder(void *, int, char *);
static unsigned get_contiguous (void *, unsigned);

static system_call_t *handlers[MAX_SYS_CALL+1];

/* Prototypes for handlers */
static system_call_t halt_call;
static system_call_t exit_call;
static system_call_t exec_call;
static system_call_t wait_call;
static system_call_t create_call;
static system_call_t remove_call;
static system_call_t open_call;
static system_call_t filesize_call;
static system_call_t read_call;
static system_call_t write_call;
static system_call_t seek_call;
static system_call_t tell_call;
static system_call_t close_call;

/*functions for getting the syscall argument from the stack by their number*/
static char *get_char_ptr_arg (void *, int);
static int get_int_arg (void *, int);
static unsigned get_unsigned_arg (void *, int);

static void destroy_action (struct hash_elem *, void *);

void check_args_in_user_space(void* esp, int syscall);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  handlers[SYS_HALT] = &halt_call;
  handlers[SYS_EXIT] = &exit_call;
  handlers[SYS_EXEC] = &exec_call;
  handlers[SYS_WAIT] = &wait_call;
  handlers[SYS_CREATE] = &create_call;
  handlers[SYS_REMOVE] = &remove_call;
  handlers[SYS_OPEN] = &open_call;
  handlers[SYS_FILESIZE] = &filesize_call;
  handlers[SYS_READ] = &read_call;
  handlers[SYS_WRITE] = &write_call;
  handlers[SYS_SEEK] = &seek_call;
  handlers[SYS_TELL] = &tell_call;
  handlers[SYS_CLOSE] = &close_call;
}

/* getting arguments from the stack */
char *get_char_ptr_arg (void *ptr, int num)
{
  return (char *) (access_user_memory(*((char**) (ptr + num*WORD_SIZE))));
}

void get_holder (void *up, int size, char holder[]) {
  for (int i = 0; i < size; ++i) {
	holder[i] = *((char *) access_user_memory(up + i));
  }
}

unsigned get_contiguous (void *up, unsigned size) {
  unsigned remaining = PGSIZE - (((unsigned) up)  % PGSIZE);
  if (remaining < size) {
	return remaining;
  } else {
	return size;
  }
}

int get_int_arg (void *ptr, int num)
{
  return *((int*) (ptr + num*WORD_SIZE));
}

unsigned get_unsigned_arg (void *ptr, int num)
{
  return *((unsigned*) (ptr + num*WORD_SIZE));
}

/* section with system calls */

/* removes a file from the file system */
int remove_call (void *psp) {
  char *name = get_char_ptr_arg(psp, FIRST_ARG);
  if (!name)
  {
    t_exit(ERROR_STATUS);
  }
  lock_acquire(&file_lock);
  bool success = filesys_remove (name);
  lock_release(&file_lock);
  return success;
}

/* returns a size of a file by ots name */
int filesize_call (void *psp) {
  struct file *file = get_file_by_fd (get_int_arg (psp, FIRST_ARG));
  lock_acquire (&file_lock);
  int size = file_length (file);
  lock_release (&file_lock);

  return size;
}

/* reads from the open file into buffer */
int seek_call (void *psp) {
  struct file *file = get_file_by_fd (get_int_arg (psp, FIRST_ARG));
  int pos = get_int_arg(psp, SECOND_ARG);
  lock_acquire (&file_lock);
  file_seek(file, pos);
  lock_release (&file_lock);
  return SUCCESS_STATUS;
}

/* Returns the position of the next byte to be 
read or written in open file */
int tell_call (void *psp) {
  struct file *file = get_file_by_fd (get_int_arg (psp, FIRST_ARG));
  lock_acquire (&file_lock);
  int pos = file_tell (file);
  lock_release (&file_lock);

  return pos;
}

/* closes file descriptor */
int close_call (void *psp) {
  int fd = get_int_arg(psp, FIRST_ARG);
  lock_acquire(&file_lock);
  struct file_fd *ffd = get_file_fd_by_fd(fd);
  file_close(ffd->file);
  lock_release(&file_lock);
  hash_delete(&(thread_current()->opened_files), &(ffd->hash_elem));
  free(ffd);
  return SUCCESS_STATUS;
}

/* waits for a child process pid and 
retrieves the child’s exit status */
int wait_call (void *psp)
{
  return process_wait (get_int_arg(psp, FIRST_ARG));
}

/* runs the executable */
int exec_call (void *psp)
{
  const char *cmd_line = get_char_ptr_arg(psp, FIRST_ARG);
  tid_t tid = process_execute(cmd_line);
  bool success;
  if(tid == TID_ERROR){
    /* If thread failed to spawn then return error */
    return PID_ERROR;
  }
  success = false;
  enum intr_level old_level = intr_disable ();

  struct thread * cur = thread_current ();

  /* If child thread is in dead child list then return appropriate message based on status */
  for (struct list_elem* it = list_rbegin(&cur->dead_children); it != list_rend(&cur->dead_children); it = list_prev(it)) {
    struct tid_elem * dead_child = list_entry(it, struct tid_elem, elem);
    if(dead_child->tid == tid){
      if(!dead_child->load_status){
        return PID_ERROR;
      }
      return (pid_t) dead_child->tid;
     }
  }

  /* iterate through the list of children from the back to find appropriate child.
     should be last in the list. iterated just in case */
  for (struct list_elem* it = list_rbegin(&cur->children);it != list_rend(&cur->children); it = list_prev(it)) {
    struct thread* t = list_entry (it, struct thread, child_elem);
    if (t->tid == tid) {
      success = t->load_status;
      break;
    }
  }
  intr_set_level (old_level);
  

  /* return appropriate success message */
  if (success) {
    return (pid_t) tid;
  } else {
    return PID_ERROR;
  }
}

/* Terminates the current user program */
int exit_call (void *psp) {
  int status = get_int_arg(psp, FIRST_ARG);
  t_exit(status);
  return status; // unreachable
}

/* opens file */
int open_call (void *psp) {
  const char *file = get_char_ptr_arg(psp, FIRST_ARG);
  lock_acquire(&file_lock);
  struct file *open_file = filesys_open(file);

  lock_release(&file_lock);
  if (!open_file)
  {
    return ERROR_STATUS;
  } else {
	struct thread *cur_thread = thread_current();
	int count = cur_thread->next_fd;
  /*creating a new file_fd struct that will represent the file and
  its fd and adding it to the thread's hash table*/
	struct file_fd *new_file_fd = (struct file_fd*) malloc(sizeof(struct file_fd));
	new_file_fd->file = open_file;
	new_file_fd->fd = count;
	/* adding file_fd to the hash table of current thread 
  to be able to access the file through its fd */
  hash_insert(
		&(cur_thread->opened_files),
		&(new_file_fd->hash_elem)
	);
  /* incrementing the count of opened files 
  which is also a fd for next file */
	(cur_thread->next_fd)++;
	return count;
  }
}


/* reads from open file to the buffer */
int read_call (void *psp) {
  int fd = get_int_arg(psp, FIRST_ARG);
  void *buffer = *((char**) (psp + SECOND_ARG*WORD_SIZE));
  unsigned size = get_unsigned_arg(psp, THIRD_ARG);
  unsigned total_read = 0;
  lock_acquire(&file_lock);
  while (size > total_read) {
    unsigned readable = get_contiguous(buffer + total_read, size);
    unsigned read = read_holder(
		fd,
		access_user_memory(buffer + total_read),
		readable
		);
    total_read += read;
    if (read < readable) {
      break;
    }
  }
  lock_release(&file_lock);
  return total_read;
}

/* writes from buffer to the open file */
int write_call (void *psp) {
  int fd = get_int_arg(psp, FIRST_ARG);
  void *buffer = *((char**) (psp + SECOND_ARG*WORD_SIZE));
  unsigned size = get_unsigned_arg(psp, THIRD_ARG);
  unsigned total_written = 0;
  lock_acquire(&file_lock);
  while (size > 0) {
    unsigned doing = size;
    if (size > BUFFER_STACK_SIZE) {
      doing = BUFFER_STACK_SIZE;
      size -= BUFFER_STACK_SIZE;
    } else {
      size = 0;
    }
    char holder[doing];
    get_holder(buffer, doing, holder);
    buffer += doing;
    unsigned written = write_holder(fd, holder, doing);
    total_written += written;
    if (written < doing) {
      break;
	  }
  }
  lock_release(&file_lock);
  return total_written;
}

/* terminates pintos */
int halt_call (void *psp UNUSED) {
  shutdown_power_off();
  return SUCCESS_STATUS;
}

/* creates a new file called */
int create_call (void *psp) {
  const char *file = get_char_ptr_arg(psp, FIRST_ARG);
  unsigned initial_size = get_unsigned_arg(psp, SECOND_ARG);
  if (!file) {
	  t_exit(ERROR_STATUS);
  }
  lock_acquire(&file_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return success;
}

//Helper function to write. Actually writes based on fd.
int write_holder (int fd, char holder[], int size) {
  if (fd == STDOUT_FILENO) {
	  putbuf(holder, size);
	return size;
  } else {
	int written_bytes = file_write(
		get_file_by_fd(fd),
		holder,
		size
	);
	return written_bytes;
  }
}

//Helper function to read. Actually reads based on fd.
int read_holder (int fd, char holder[], int size) {
  if (fd == STDIN_FILENO) {
	for (int i = 0; i < size; ++i) {
	  holder[i] = input_getc();
	}
	lock_release(&file_lock);
	return size;
  } else {
	int read_bytes = file_read(
		get_file_by_fd(fd),
		holder,
		size
	);
	return read_bytes;
  }
}

/* the real exit call. Error status is printed, 
inserts itself into parent's dead child list, releases 
filesys lock if it still holds it, hash destroys and then 
thread exit, from where more termination code is executed and 
thread is deleted.
*/
void t_exit (int status){
  enum intr_level old_level = intr_disable ();
  struct thread * cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  if(lock_held_by_current_thread((&file_lock))){
    lock_release(&file_lock);
  }
  if (cur->parent_process){
	/* return it's exit status to the parent before the thread exits and gets deallocated */
    struct tid_elem * dead_child = malloc(sizeof(struct tid_elem));
    dead_child->tid = cur->tid;
    dead_child->status = status;
    dead_child->load_status = cur->load_status;
    dead_child->checked = false;
    enum intr_level old_level = intr_disable ();
    list_push_back(&cur->parent_process->dead_children, &dead_child->elem);
  }
  intr_set_level(old_level);

  hash_destroy(&(cur->opened_files), &destroy_action);
  thread_exit();
}

// if pointer is within user memory, return get_page
void *
access_user_memory (void *up) {
  if (is_user_vaddr(up)) {
	void *pp = pagedir_get_page(thread_current()->pagedir, up);
    if (!pp) {
	  t_exit(ERROR_STATUS);
    }
    return pp;
  }
  else {
    t_exit(ERROR_STATUS);
	return NULL; // unreachable
  }
}

/*returns the pointer to an opened file by its file descriptor*/
struct file *get_file_by_fd (int fd)
{
  return get_file_fd_by_fd(fd)->file;
}

/*returns the pointer to a struct file_fd by fd*/
struct file_fd *get_file_fd_by_fd (int fd)
{
  struct file_fd ffd;
  struct hash_elem *e;
  ffd.fd = fd;
  e = hash_find(
	  &(thread_current()->opened_files),
	  &(ffd.hash_elem)
	  );
  if (!e)
  {
	  t_exit(ERROR_STATUS);
	  return NULL; // unreachable
  } else {
	  return hash_entry(e, struct file_fd, hash_elem);
  }
}

//checks if end of syscall arguments is within the bounds of user memory
// number of arguments depends on syscall.
void check_args_in_user_space(void* esp, int syscall){
  int offset;
  switch(syscall){
    case SYS_READ:
    case SYS_WRITE:
      offset = 4;
      break;
    case SYS_SEEK:
    case SYS_CREATE:
      offset = 3;
      break;
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
      offset = 2;
      break;
    default:
      offset = 1;
      break;
  }

  //check if last argument is outside of user memory space
  if(!is_user_vaddr(esp + (offset*WORD_SIZE)-1)) t_exit(ERROR_STATUS);
}

void
syscall_handler (struct intr_frame *f)
{
  //get psp and verify it
  void *psp = access_user_memory(f->esp);
  if (!psp) {
    t_exit(ERROR_STATUS);
	  return;
  }
  //get syscall_number and check it is within bounds for task 2
  int syscall_number = ((int *) psp)[SYSCALL_ARG];
  if (syscall_number < SYS_HALT || syscall_number > MAX_SYS_CALL) t_exit(ERROR_STATUS);
  
  // check all arguments are within bounds on the stack based on syscall
  check_args_in_user_space(f->esp, syscall_number);

  // run appropriate syscall from array of functions
  f->eax = handlers[syscall_number] (psp);
}

/*function used when the hash table of opened files gets destroyed*/
void destroy_action (struct hash_elem *e, void *aux UNUSED)
{
  struct file_fd *f = hash_entry(e, struct file_fd, hash_elem);
  lock_acquire(&file_lock);
  file_close(f->file);
  lock_release(&file_lock);
  free(f);
}
