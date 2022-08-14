#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include <stdio.h>

void syscall_init(void);

/* START TASK: File Operation Syscalls */

bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
struct active_file* get_active_file(int fd);
bool valid_pointer(void* ptr, size_t size);
bool valid_string(char* str);
void exit_with_error(uint32_t* eax, int error_code);
struct process* process_current(void);

/* END TASK: File Operation Syscalls */

#endif /* userprog/syscall.h */
