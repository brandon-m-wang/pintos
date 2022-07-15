#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  /* START TASK: File Operation Syscalls */
  struct list active_files; /* List of active_files in process. */
  struct list
      available_fds; /* List of available file descriptors for a process to assign a file when opening a file. */
  struct file* executing_file;    /* File that the process is currently running. */
  struct lock file_syscalls_lock; /* Lock for file operation syscalls for the process. */
  /* END TASK: File Operation Syscalls */
};

struct process_fields {
  struct semaphore sem;
  struct lock lock;
  struct list_elem elem;
  pid_t pid;
  int ec;
  int process_started;
};

/* START TASK: File Operation Syscalls */

/* struct active_file represents an open file in the process. */
typedef struct active_file {
  int fd;                /* File descriptor of file */
  struct file* file;     /* Pointer to file struct */
  struct list_elem elem; /* Used to represent struct as an element in a PintOS list */
} active_file;

/* struct available_fd represents a single file descriptor that can either belong to a file in the process or not. */
typedef struct fd {
  int fd;                /* File descriptor which does not belonging to a file yet */
  struct list_elem elem; /* Used to represent struct as an element in a PintOS list */
} fd;

/* END TASK: File Operation Syscalls */

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

#endif /* userprog/process.h */
