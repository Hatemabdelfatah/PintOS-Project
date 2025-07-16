#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/thread.h"
#define USER_VADDR_BOTTOM_LIMIT ((void *) 0x08048000)

void syscall_init (void);
bool pull_args(int syscall_code , int esp ,int *args);
int get_args_count(int syscall_code );
void halt(void);
int write (int fd, const void *buffer, unsigned size);
bool is_valid_ptr(const void * ptr);                  
void validate_user_range(const void *start, size_t size); 
void validate_string(const char *str);                    
pid_t exec(const char *cmd_line);
void exit(int status);
int wait(pid_t tid);
struct open_file* get_file(int fd);
int sys_open(char *file_name);
int file_size(int fd);
int sys_read(int fd, void *buffer, int length);
#endif /* userprog/syscall.h */
