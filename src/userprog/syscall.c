#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_PRACTICE) {
    f->eax = args[1]++;
  } else if (args[0] == SYS_EXIT) {

  /* START TASK: File Operation Syscalls */

  /* Lock for File Operation Syscalls */
  struct lock file_syscalls_lock;
  lock_init(&file_syscalls_lock);

  /* END TASK: File Operation Syscalls */

  /* FILE SYSCALLS TODO: 
     - Exiting or terminating a process must implicitly close all its open file descriptors, as if by calling this function for each one.
     - Argument authentication
     - Error Handling
  */

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    thread_current()->process_fields->ec = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  } else if (args[0] == SYS_HALT) {
    shutdown_power_off();
  } else if (args[0] == SYS_EXEC) {
    f->eax = process_execute((char *)args[1]);
  } else if (args[0] == SYS_WAIT) {
    f->eax = process_wait(args[1]);
  } else if (args[0] == SYS_CREATE) {

    lock_acquire(&file_syscalls_lock);
    f->eax = create(args[1], args[2]);
    lock_release(&file_syscalls_lock);

  } else if (args[0] == SYS_REMOVE) {

    lock_acquire(&file_syscalls_lock);
    f->eax = remove(args[1]);
    lock_release(&file_syscalls_lock);

  } else if (args[0] == SYS_OPEN) {

    lock_acquire(&file_syscalls_lock);
    f->eax = open(args[1]);
    lock_release(&file_syscalls_lock);

  } else if (args[0] == SYS_FILESIZE) {

    lock_acquire(&file_syscalls_lock);
    f->eax = filesize(args[1]);
    lock_release(&file_syscalls_lock);

  } else if (args[0] == SYS_READ) {

    lock_acquire(&file_syscalls_lock);
    f->eax = read(args[1], args[2], args[3]);
    lock_release(&file_syscalls_lock);

  } else if (args[0] == SYS_WRITE) {

    lock_acquire(&file_syscalls_lock);
    f->eax = write(args[1], args[2], args[3]);
    lock_release(&file_syscalls_lock);

  } else if (args[0] == SYS_SEEK) {

    lock_acquire(&file_syscalls_lock);
    seek(args[1], args[2]);
    lock_release(&file_syscalls_lock);

  } else if (args[0] == SYS_TELL) {

    lock_acquire(&file_syscalls_lock);
    f->eax = tell(args[1]);
    lock_release(&file_syscalls_lock);

  } else if (args[0] == SYS_CLOSE) {

    lock_acquire(&file_syscalls_lock);
    close(args[1]);
    lock_release(&file_syscalls_lock);

  }
}

/* START TASK: File Operation Syscalls */

/* Creates a new file called file initially initial_size
   bytes in size. Returns true if successful, false otherwise. */
bool create(const char* file, unsigned initial_size) {
  /* Check for valid pointer. */
  if (file == NULL) {
    return false;
  }

  /* Call filesys_create */
  bool return_code = filesys_create(file, initial_size);

  return return_code;
}

/* Deletes the file named file. Returns true if successful, false otherwise. */
bool remove(const char* file) {
  /* Check for valid pointer. */
  if (file == NULL) {
    return false;
  }

  /* Call filesys_remove() */
  bool return_code = filesys_remove(file);

  return return_code;
}

/* Opens the file named file. Returns a nonnegative 
  integer handle called a “file descriptor” (fd), or 
  -1 if the file could not be opened. */
int open(const char* file) {
  /* Check for valid pointer. */
  if (file == NULL) {
    return -1;
  }

  struct file* opened_file = filesys_open(file);

  /* Check if filesys_open failed. */
  if (opened_file == NULL) {
    return -1;
  }

  /* Get get the process struct of current process */
  struct thread* main_thread = thread_current();
  struct process* main_pcb = main_thread->pcb;

  int new_fd = -1;
  struct list* available_fds = main_pcb->available_fds;

  /* Check if there are any more available file descriptors.
    If none, close new file and return -1. */
  if (list_empty(available_fds)) {
    file_close(opened_file);
    return -1;
  }

  /* Take out a file descriptor struct from available_fds. */
  struct fd* opened_fd = list_entry(list_pop_front(available_fds), struct fd, elem);

  /* Take fd value and assign it to new_fd. */
  new_fd = opened_fd->fd;

  /* Free the fd struct because it is no longer in available_fds. */
  free(opened_fd);

  /* Initialize a new active file and add it to the main process's active_files. */
  struct active_file* new_open_file = (struct active_file*)malloc(sizeof(struct active_file));
  new_open_file->fd = new_fd;
  new_open_file->file = opened_file;

  struct list_elem new_elem = {NULL, NULL};
  new_open_file->elem = new_elem;
  list_push_back(main_pcb->active_files, &(new_open_file->elem));

  return new_fd;
}

/* Returns the size, in bytes, of the open file with file descriptor fd. 
  Return -1 if file with fd is not found. */
int filesize(int fd) {
  /* Get the process's active_file with its file descriptor matching fd. */
  struct active_file* target_file = get_active_file(fd);

  /* Check if active_file matching fd is found. 
    If it is found, then return the length of the file.
    Otherwise if an active_file matching fd is not found, return -1.*/
  if (target_file != NULL) {
    return file_length(target_file->file);
  } else {
    return -1;
  }
}

/* Reads size bytes from the file open as fd into buffer. 
  Returns the number of bytes actually read (0 at end of 
  file), or -1 if the file could not be read (due to a 
  condition other than end of file). Return -1 if file with
  fd is not found.*/
int read(int fd, void* buffer, unsigned size) {
  /* Get the process's active_file with its file descriptor matching fd. */
  struct active_file* target_active_file = get_active_file(fd);

  /* Check if active_file matching fd is found. 
  If it is found, then read size bytes to the buffer 
  from the file and return the number of bytes read.
  Otherwise if an active_file matching fd is not found, return -1.*/
  if (target_active_file != NULL) {
    return file_read(target_active_file->file, buffer, size);
  } else {
    return -1;
  }
}

/* Writes size bytes from buffer to the open file with 
  file descriptor fd. Returns the number of bytes actually 
  written, which may be less than size if some bytes could 
  not be written.*/
int write(int fd, const void* buffer, unsigned size) {
  /* Check if fd == 1, in other words, the console. */
  if (fd == 1) {
    /* The number of times putbuf will be called (writing 300 bytes at a time).
    interations = (size / 300) rounded UP to the nearest whole number. */
    int iterations = (size + (300 - 1)) / 300;

    /* Write size bytes to the console */
    for (int i = 0; i < iterations; i++) {
      putbuf(buffer, 300);
      buffer += 300;
    }
    return;
  }

  /* Get the process's active_file with its file descriptor matching fd. */
  struct active_file* target_active_file = get_active_file(fd);

  /* Check if active_file matching fd is found. 
  If it is found, then write size bytes from the buffer 
  into the file and return the number of bytes written. 
  Otherwise if an active_file matching fd is not found, return -1.*/
  if (target_active_file != NULL) {
    return file_write(target_active_file->file, buffer, size);
    ;
  } else {
    return -1;
  }
}

/* Changes the next byte to be read or written in open file 
  fd to position, expressed in bytes from the beginning of 
  the file. Return -1 if file with fd is not found. */
void seek(int fd, unsigned position) {
  /* Get the process's active_file with its file descriptor matching fd. */
  struct active_file* target_active_file = get_active_file(fd);

  /* Check if active_file matching fd is found. 
  If it is found, move the read/write pointer of
  the file to position. Otherwise if an active_file 
  matching fd is not found, return -1.*/
  if (target_active_file != NULL) {
    return file_seek(target_active_file->file, position);
  } else {
    return -1;
  }
}

/* Returns the position of the next byte to be read or written
 in open file fd, expressed in bytes from the beginning of the file. 
 Returns 0 if fd does not match any of process's files. */
unsigned tell(int fd) {
  /* Get the process's active_file with its file descriptor matching fd. */
  struct active_file* target_active_file = get_active_file(fd);

  /* Check if active_file matching fd is found. 
  If it is found, return the current position
  of the read/write pointer of that file. 
  Otherwise if an active_file matching fd is not 
  found, return -1.*/
  if (target_active_file != NULL) {
    return file_tell(target_active_file->file);
  } else {
    return 0;
  }
}

/* Closes file descriptor fd. */
void close(int fd) {
  /* Get get the process struct of current process */
  struct thread* main_thread = thread_current();
  struct process* main_pcb = main_thread->pcb;
  struct list* available_fds = main_pcb->available_fds;

  /* Iterate through process's active_files
    to find the file matching the fd. */
  struct list_elem* e;
  struct list* active_files = main_pcb->active_files;

  for (e = list_begin(active_files); e != list_end(active_files); e = list_next(e)) {
    struct active_file* temp_file = list_entry(e, struct active_file, elem);

    /* Found file matching fd, "close" file by removing it from the process's active_files. */
    if (temp_file->fd == fd) {
      /* Make fd available by putting it back into process's available_fds. */
      struct fd* new_fd = (struct fd*)malloc(sizeof(struct fd));
      struct list_elem new_elem = {NULL, NULL};
      new_fd->fd = fd;
      new_fd->elem = new_elem;
      list_push_front(available_fds, &(new_fd->elem));

      /* Close struct file */
      file_close(temp_file->file);

      /* Remove file from process's active_files list*/
      list_remove(&(temp_file->elem));

      /* Finally, free memory allocated for the removed file. */
      free(temp_file);

      return;
    }
  }
}

/* END TASK: File Operation Syscalls */