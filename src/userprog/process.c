#include <stdlib.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "userprog/process.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "threads/malloc.h"

#define ADDR_SIZE 4

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);


void push_cmd_args(char *file_name, int* argc, char**arg_ads, void **esp);
void push_word_align (void **esp);
void push_arg_addresses(int argc, char**arg_ads, void **esp);
void push_pointer_to_start_of_argaddrs(void ** esp);
void push_argc(int argc, void **esp);
void push_fake_return_addr(void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  if(strlen(file_name) + 1 >= PGSIZE) return -1; //+1 for null terminator at the end
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  char * saveptr;
  strtok_r((char *) file_name, " ", &saveptr);

  enum intr_level old_level = intr_disable ();
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  /* Process sleeps itself until child performs load */
  sema_down(&(thread_current()->load_sema));
  intr_set_level (old_level);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* push each argument onto the stack */
void push_cmd_args(char *file_name, int* argc, char**arg_ads, void **esp){
  char * rem = file_name; //remainder of file_name
  char * arg;
  int agc=0;

  while((arg = strtok_r(rem, " ", &rem)))
    {
      *esp -= (strlen(arg) + 1);
      strlcpy(*esp, arg, PGSIZE); //copy until pagesize (max size of argument input)
      arg_ads[agc++] = *esp; //save each arg address for later
    }
  
  *argc = agc;
}

/* null pointer sentinel
keep pushing word align until addr is a multiple of 4 */
void push_word_align (void **esp){
  uint8_t word_align = 0;
  while((PHYS_BASE - *esp) % ADDR_SIZE){
    *esp -= sizeof(uint8_t);
    * (uint8_t *) *esp = word_align;
  }
}

/* push addresses of each argument onto stack with null pointer */
void push_arg_addresses(int argc, char**arg_ads, void **esp){
  *esp -= sizeof(char *);
  char final_arg = 0;
  * (char *) *esp = final_arg;
  
  for(int x = argc - 1; x >= 0; x-- )
    {
      *esp -= sizeof(char *);
      * (char **) *esp = arg_ads[x];
    }
}

/* push pointer to start of arg addr array */
void push_pointer_to_start_of_argaddrs(void ** esp){
  char ** arg_arr = *esp;
  *esp -= sizeof(char **);
  * (char ***) *esp = arg_arr;
}

/*pushes argc onto stack*/
void push_argc(int argc, void **esp){
  *esp -= sizeof (int);
  * (int *) *esp = argc;
}

/*pushes null pointer onto stack*/
void push_fake_return_addr(void **esp){
  *esp -= sizeof (void *);
  * (void **) *esp = 0x0;
}

/* Performs a calculation based on the location of esp relative 
to physbase and argc to check if there is enough remaining space 
left on the stack for argument passing to be completed successfully */
bool enough_stack_left(void **esp, int argc){
  int offset = 0;

  offset += (argc * ADDR_SIZE);

  int word_align = (ADDR_SIZE - ((int)*esp % ADDR_SIZE));
  if (word_align < ADDR_SIZE) offset += word_align;

  offset += sizeof(char**);
  offset += sizeof(int);
  offset += sizeof(void *);

  if((PHYS_BASE - (*esp - offset)) < PGSIZE) return false;
  return true;
}

bool push_args_to_stack (char *file_name, void **esp)
{
  int argc = 0;
  char** arg_ads = palloc_get_page(0);
  
  /* push each argument onto the stack */
  push_cmd_args(file_name, &argc, arg_ads, esp);

  /* See if there is enough space left on the stack based on argc */
  if(enough_stack_left(esp, argc)) return false;  

  /* null pointer sentinel */
  push_word_align(esp);

  /* push addresses of each argument onto stack with null pointer */
  push_arg_addresses(argc, arg_ads, esp);
  palloc_free_page(arg_ads); 
 
  /* push pointer to start of arg addr array */
  push_pointer_to_start_of_argaddrs(esp);

  /* push argc */
  push_argc(argc, esp);

  /* push fake return address */
  push_fake_return_addr(esp);
  return true;
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{

  struct thread* t = thread_current();
  hash_init(&t->opened_files, &file_fd_hash, &file_fd_less, NULL);
  t->next_fd = 2;

  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  char * prog_name = palloc_get_page(0);
  strlcpy(prog_name, file_name, PGSIZE);
  
  char * useless_saveptr; //only exits to get past (saveptr != NULL) assertion
  strtok_r(prog_name, " ", &useless_saveptr);
   
  success = load (prog_name, &if_.eip, &if_.esp);
  palloc_free_page(prog_name); 
 
  if(success) {
    success = push_args_to_stack(file_name, &if_.esp);
  }

  //success must be true from both load and pushing arguements to 
  //stack for loading to be completed successfully
  
  enum intr_level old_level = intr_disable();
  
  struct thread * cur = thread_current();
  cur->load_status = success;
  
  sema_up(&cur->parent_process->load_sema);
  
  intr_set_level(old_level);
  /* If load failed, quit. */
  if (!success) 
    thread_exit ();


  palloc_free_page (file_name);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */


int
process_wait (tid_t child_tid) 
{
  //check if tid is direct child

  enum intr_level old_level = intr_disable ();

  struct thread * cur = thread_current();

  /*check if process is in dead children list,
   if already been checked (waited on), return -1,
  otherwise return status and set checked to true*/

  for (struct list_elem* it = list_rbegin(&cur->dead_children); it != list_rend(&cur->dead_children); it = list_prev(it)) {
    struct tid_elem * dead_child = list_entry(it, struct tid_elem, elem);
    if(dead_child->tid == child_tid){
      if (dead_child->checked) {
        intr_set_level(old_level);
        return -1;
      }
      else{
        dead_child->checked = true;
        intr_set_level(old_level);
        return dead_child->status;
      }
    }
  }
    

  //finds thread in list of children
  //struct list* children = &thread_current ()->children;
  struct thread* child_process = NULL;
  for (struct list_elem* it = list_rbegin(&cur->children); it != list_rend(&cur->children); it = list_prev(it)) {
    struct thread* t = list_entry (it, struct thread, child_elem);
    if (child_tid == t->tid) {
      child_process = t;
    }
  }

  /* if didnt find child process in dead or alive children lists, return error code */
  if (!child_process) {
    intr_set_level(old_level);
    return ERROR_STATUS;
  }

  /* otherwise sema_down on the child's wait semaphore */
  sema_down (&(child_process->wait_sema));
  
  /*by now the child should be in the dead thread list.
    find it and return it's status.
    search from back. Should be at back anyway most of the time so constant time */
  for (struct list_elem* it = list_rbegin(&cur->dead_children); it != list_rend(&cur->dead_children); it = list_prev(it)) {
    struct tid_elem * dead_child = list_entry(it, struct tid_elem, elem);
    if(dead_child->tid == child_tid){
      dead_child->checked = true;
      intr_set_level(old_level);
      return dead_child->status;
    }
  }

  intr_set_level(old_level);
  /*return error if this did not work*/
  return ERROR_STATUS;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  enum intr_level old_level = intr_disable ();
  struct thread *cur = thread_current ();
  //orphaning all current threads child processes
  struct list_elem* it = list_begin (&cur->children);
  for (; it != list_end(&cur->children); it = list_next(it)) {
    struct thread* t = list_entry (it, struct thread, child_elem);
    t->parent_process = NULL;
  }
  if(cur->parent_process){
    //orphan itself from its parent
    list_remove(&cur->child_elem);
  
  }

/* freeing all its dead children as they were malloced */  
  it = list_begin (&cur->dead_children);
  for (; it != list_end(&cur->dead_children);) {
    struct tid_elem * dead_child = list_entry(it, struct tid_elem, elem);
    it = list_remove(it);
    free(dead_child); 
  }
  intr_set_level (old_level);
  
  // setting not alive flag so parent process can wake up and continue
  uint32_t *pd;
  if (cur->exec_file)
  {
    file_allow_write(cur->exec_file);
  }
  file_close (cur->exec_file); 
  sema_up(&(cur->wait_sema));



  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    } 
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  t->exec_file = file;
  if (t->exec_file) 
  {
    file_deny_write (t->exec_file);
  }
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      /* Check if virtual page already allocated */
      struct thread *t = thread_current ();
      uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
      
      if (kpage == NULL){
        
        /* Get a new page of memory. */
        kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL){
          return false;
        }
        
        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }     
        
      } else {
        
        /* Check if writable flag for the page should be updated */
        if(writable && !pagedir_is_writable(t->pagedir, upage)){
          pagedir_set_writable(t->pagedir, upage, writable); 
        }
        
      }

      /* Load data into the page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes){
        return false; 
      }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
