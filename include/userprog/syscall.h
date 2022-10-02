#include <list.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define READDIR_MAX_LEN 14

void syscall_init (void);

struct lock filesys_lock;

struct file_fd {
	struct list_elem elem_fd;
	int fd;
	struct file* file;
	int std;
};

#endif /* userprog/syscall.h */
