#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <string.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/float.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /* Verify args pointer. Exits thread if invalid. */
  if (!valid_pointer(args, sizeof(uint32_t*))) {
    exit_with_error(&f->eax, -1);
  }

  /* Get the main process struct. */
  struct process* main_pcb = process_current();

  if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  } else if (args[0] == SYS_EXIT) {
    // If I'm orphaned, then all it suffices to put exit code in f->eax
    f->eax = args[1];
    // If I have a parent, then I also need to give info to my parent, otherwise this serves no purpose and can be ignored
    if (thread_current()->process_fields != NULL) {
      thread_current()->process_fields->ec = args[1];
    }
    process_exit();
  } else if (args[0] == SYS_HALT) {
    shutdown_power_off();
  } else if (args[0] == SYS_EXEC) {
    /* Verify char* pointer */
    if (!valid_pointer((void*)args + 4, sizeof(uint32_t*)) || !valid_string((char*)args[1])) {
      exit_with_error(&f->eax, -1);
    }
    f->eax = process_execute((char*)args[1]);
  } else if (args[0] == SYS_WAIT) {
    f->eax = process_wait(args[1]);
  } else if (args[0] == SYS_CREATE) {
    /* Verify char* pointer */
    if (!valid_pointer((void*)args + 4, sizeof(uint32_t*)) || !valid_string((char*)args[1])) {
      exit_with_error(&f->eax, -1);
    }

    lock_acquire(&main_pcb->file_syscalls_lock);
    f->eax = create((char*)args[1], args[2]);
    lock_release(&main_pcb->file_syscalls_lock);

  } else if (args[0] == SYS_REMOVE) {
    /* Verify char* pointer */
    if (!valid_pointer((void*)args + 4, sizeof(uint32_t*)) || !valid_string((char*)args[1])) {
      exit_with_error(&f->eax, -1);
    }

    lock_acquire(&main_pcb->file_syscalls_lock);
    f->eax = remove((char*)args[1]);
    lock_release(&main_pcb->file_syscalls_lock);

  } else if (args[0] == SYS_OPEN) {
    /* Verify char* pointer */
    if (!valid_pointer((void*)args + 4, sizeof(uint32_t*)) || !valid_string((char*)args[1])) {
      exit_with_error(&f->eax, -1);
    }

    lock_acquire(&main_pcb->file_syscalls_lock);
    f->eax = open((char*)args[1]);
    lock_release(&main_pcb->file_syscalls_lock);

  } else if (args[0] == SYS_FILESIZE) {

    lock_acquire(&main_pcb->file_syscalls_lock);
    f->eax = filesize(args[1]);
    lock_release(&main_pcb->file_syscalls_lock);

  } else if (args[0] == SYS_READ) {
    /* Verify buffer pointer */
    if (!valid_pointer((void*)args[2], args[3])) {
      exit_with_error(&f->eax, -1);
    }

    lock_acquire(&main_pcb->file_syscalls_lock);
    f->eax = read(args[1], (void*)args[2], args[3]);
    lock_release(&main_pcb->file_syscalls_lock);

  } else if (args[0] == SYS_WRITE) {
    /* Verify buffer pointer */
    if (!valid_pointer((void*)args[2], args[3])) {
      exit_with_error(&f->eax, -1);
    }

    lock_acquire(&main_pcb->file_syscalls_lock);
    f->eax = write(args[1], (void*)args[2], args[3]);
    lock_release(&main_pcb->file_syscalls_lock);

  } else if (args[0] == SYS_SEEK) {

    lock_acquire(&main_pcb->file_syscalls_lock);
    seek(args[1], args[2]);
    lock_release(&main_pcb->file_syscalls_lock);

  } else if (args[0] == SYS_TELL) {

    lock_acquire(&main_pcb->file_syscalls_lock);
    f->eax = tell(args[1]);
    lock_release(&main_pcb->file_syscalls_lock);

  } else if (args[0] == SYS_CLOSE) {

    lock_acquire(&main_pcb->file_syscalls_lock);
    close(args[1]);
    lock_release(&main_pcb->file_syscalls_lock);

  } else if (args[0] == SYS_COMPUTE_E) {
    /* Verify args pointer */
    if (!valid_pointer((void*)args + 4, sizeof(uint32_t*))) {
      exit_with_error(&f->eax, -1);
    }

    f->eax = sys_sum_to_e((int)args[1]);
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

  /* Get the main process struct. */
  struct process* main_pcb = process_current();

  int new_fd = -1;
  struct list* available_fds = &main_pcb->available_fds;

  /* Check if there are any more available file descriptors.
    If none, close new file and return -1. */
  if (list_empty(available_fds)) {
    file_close(opened_file);
    return -1;
  }

  /* Take out a file descriptor struct from available_fds. */
  struct list_elem* front_available_fd = list_pop_front(available_fds);
  struct fd* opened_fd = list_entry(front_available_fd, struct fd, elem);

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
  list_push_back(&main_pcb->active_files, &(new_open_file->elem));

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
    /* Write size bytes to the console */
    putbuf(buffer, size);
    return size;
  }

  /* Get the process's active_file with its file descriptor matching fd. */
  struct active_file* target_active_file = get_active_file(fd);

  /* Check if active_file matching fd is found.
  If it is found, then write size bytes from the buffer 
  into the file and return the number of bytes written. 
  Otherwise if an active_file matching fd is not found, return -1.*/
  if (target_active_file != NULL) {
    return file_write(target_active_file->file, buffer, size);
  } else {
    return -1;
  }
}

/* Changes the next byte to be read or written in open file 
  fd to position, expressed in bytes from the beginning of 
  the file. */
void seek(int fd, unsigned position) {
  /* Get the process's active_file with its file descriptor matching fd. */
  struct active_file* target_active_file = get_active_file(fd);

  /* Check if active_file matching fd is found. 
  If it is found, move the read/write pointer of
  the file to position. Otherwise if an active_file 
  matching fd is not found, return -1.*/
  if (target_active_file != NULL) {
    file_seek(target_active_file->file, position);
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
  /* Get the main process struct. */
  struct process* main_pcb = process_current();
  struct list* available_fds = &main_pcb->available_fds;

  /* Iterate through process's active_files
    to find the file matching the fd. */
  struct list_elem* e;
  struct list* active_files = &main_pcb->active_files;

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

/* Returns the active_file struct of the current process
  corresponding to the given fd. Return NULL if not found */
struct active_file* get_active_file(int fd) {
  /* Get the main process struct. */
  struct process* main_pcb = process_current();

  /* Iterate through process's active_files
    to find the file matching the fd. */
  struct list_elem* e;
  struct list* active_files = &main_pcb->active_files;

  for (e = list_begin(active_files); e != list_end(active_files); e = list_next(e)) {
    struct active_file* temp_file = list_entry(e, struct active_file, elem);

    /* Found active_file matching fd, return it. */
    if (temp_file->fd == fd) {
      return temp_file;
    }
  }

  /* File not found, return null. */
  return NULL;
}

/* Returns true if pointer is entirely in user memory and
  there exists a physical mapping to the ptr in user virtual mem.
  Otherwise, return false. */
bool valid_pointer(void* ptr, size_t size) {
  /* Check for NULL pointer */
  if (ptr == NULL) {
    return false;
  }

  /* Get the main process struct. */
  struct process* main_pcb = process_current();

  /* Check if start and end of pointer is in user memory
    and has physical mapping from user to physical memory. */
  return is_user_vaddr(ptr) && is_user_vaddr(ptr + size) &&
         pagedir_get_page(main_pcb->pagedir, ptr) != NULL &&
         pagedir_get_page(main_pcb->pagedir, ptr + size) != NULL;
}

/* Returns true if string exists in user memory and
  if there exits a physical mapping to the ptr in user virtual mem.
  Otherwise, return false. */
bool valid_string(char* str) {
  /* Check for NULL pointer and if string pointer exists in user memory.*/
  if (str == NULL || !is_user_vaddr(str)) {
    return false;
  }

  /* Get the main process struct. */
  struct process* main_pcb = process_current();

  /* Get address of string in kernel memory */
  void* kernel_string_addr = pagedir_get_page(main_pcb->pagedir, str);

  if (kernel_string_addr == NULL) {
    return false;
  } else {
    /* Get string length of kernel string, it is not safe to get strlen of user provided string. */
    int string_length = strlen(kernel_string_addr) + 1;

    /* Check if end of string exists in user memory and if there is a mapping to it from physical memory */
    return is_user_vaddr(str + string_length) &&
           pagedir_get_page(main_pcb->pagedir, str + string_length) != NULL;
  }
}

/* Exits the running thread with error code error_code. */
void exit_with_error(uint32_t* eax, int error_code) {
  *eax = error_code;
  thread_current()->process_fields->ec = error_code;
  process_exit();
  NOT_REACHED();
}

/* Get the current process struct. */
struct process* process_current(void) {
  /* Get get the process struct of current process through the current thread. */
  struct thread* main_thread = thread_current();
  struct process* main_pcb = main_thread->pcb;
  return main_pcb;
}

/* END TASK: File Operation Syscalls */