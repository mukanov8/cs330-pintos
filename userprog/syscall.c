#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"

#ifdef VM
	#include "vm/vm.h"
#endif

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* Validate the Virtual Address. true if valid, false if invalidv
	* on top thread_exit() something more should be done
*/
void validate_user_ptr(void* va, bool writing) {
	if (va == NULL) {
		thread_current() -> exit_status = -1;
		thread_exit();
		NOT_REACHED ();
	}
	if (is_user_vaddr(va) == false) {
		thread_current() -> exit_status = -1;
		thread_exit();
		NOT_REACHED ();
	}
	#ifndef VM
		if (pml4_get_page(thread_current() -> pml4, va) == NULL) {
			thread_current() -> exit_status = -1;
			thread_exit();
			NOT_REACHED ();
		}
	#else
		struct page* page = spt_find_page(&thread_current() -> spt, pg_round_down(va));
		if (page == NULL) {
			thread_current() -> exit_status = -1;
			thread_exit();
			NOT_REACHED ();
		}
		if (writing && !page -> writable) {
			thread_current() -> exit_status = -1;
			thread_exit();
			NOT_REACHED ();
		}
	#endif
}

int get_optimal_fd() {
	int fd = 2;
	enum intr_level old_level = intr_disable();
	struct thread *t = thread_current();
  	
	for (struct list_elem *e = list_begin(&t -> fds); e != list_end(&t -> fds); e = list_next(e)) {
		struct file_fd* curr = list_entry(e, struct file_fd, elem_fd);
		if (curr -> fd < 2) {
			continue;
		}
		if (curr -> fd == fd) {
			fd++;
		}
		else {
			break;
		}
	}
	intr_set_level(old_level);
	return fd;
}
struct file_fd* lookup_file(int fd) {
	struct file_fd* ret_file = NULL;
	enum intr_level old_level = intr_disable();
	struct thread *t = thread_current();
	for (struct list_elem *e = list_begin(&t -> fds); e != list_end(&t -> fds); e = list_next(e)) {
		struct file_fd* curr = list_entry(e, struct file_fd, elem_fd);
		if (curr -> fd <= fd) {
			ret_file = curr;
		}
		if (fd == curr -> fd) {
			break;
		}
	}
	intr_set_level(old_level);
	return ret_file;
}

void try_close(struct file* f, struct list* fds) {
	for (struct list_elem *e = list_begin(fds); e != list_end(fds); e = list_next(e)) {
		struct file_fd* af = list_entry(e, struct file_fd, elem_fd);
		if (af -> file == f) {
			return;
		}
	}
	file_close(f);
}

void halt_handler(void) {
	power_off();
	NOT_REACHED ();
}

void exit_handler(int status) {
	thread_current() -> exit_status = status;
	thread_exit();
	NOT_REACHED ();
}

void fork_handler(const char *thread_name, struct intr_frame *f) {
	validate_user_ptr(thread_name, false);
	struct thread *parent = thread_current();
	tid_t ret_tid = process_fork(thread_name, f);
	if (ret_tid == TID_ERROR) {
		f -> R.rax = TID_ERROR;
	}
	else {
		sema_down(&parent -> child_creation);
	}
	ASSERT(f -> R.rax == TID_ERROR || f -> R.rax == ret_tid);
}

int exec_handler(const char *cmd_line) {
	validate_user_ptr(cmd_line, false);
	char* fn_copy = palloc_get_page(PAL_USER);
	if (fn_copy == NULL)
		return -1;
	strlcpy (fn_copy, cmd_line, strlen(cmd_line) + 1);
	if (process_exec(fn_copy) < 0) {
		thread_current() -> exit_status = -1;
		thread_exit();
	}
}

int wait_handler(tid_t pid) {
	return process_wait(pid);
}

bool create_handler(const char *file, size_t initial_size) {
	validate_user_ptr(file, false);
	lock_acquire(&filesys_lock);
	bool ret_value = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return ret_value;
}

bool remove_handler(const char *file) {
	validate_user_ptr(file, false);
	lock_acquire(&filesys_lock);
	bool ret_value = filesys_remove(file);
	lock_release(&filesys_lock);
	return ret_value;
}

int open_handler(const char *file) {
	struct file_fd* curr = calloc (1, sizeof(struct file_fd));
	if (curr == NULL) {
		return -1;
	}
	validate_user_ptr(file, false);
	lock_acquire(&filesys_lock);
	curr -> file = filesys_open(file);
	lock_release(&filesys_lock);
	if (curr -> file == NULL) {
		free(curr);
		return -1;
	}
	
	enum intr_level old_level = intr_disable();
	int fd = get_optimal_fd();
	struct file_fd* before = lookup_file(fd - 1);
	if (before != NULL) {
		list_insert(list_next(&before -> elem_fd), &curr -> elem_fd);
	}
	else {
		list_push_front(&thread_current() -> fds, &curr -> elem_fd);
	}
	curr -> fd = fd;
  	curr -> std = 0;
	intr_set_level(old_level);
	return fd;
}

int filesize_handler(int fd) {
	struct file_fd* curr = lookup_file(fd);
	if (curr == NULL || curr -> fd != fd || curr -> std != 0) {
		return 0;
	}
	if (curr -> file == NULL || inode_is_directory(file_get_inode(curr -> file))) {
		return 0;
	}

	lock_acquire(&filesys_lock);
	int ret_value = file_length(curr -> file);
	lock_release(&filesys_lock);
	return ret_value;
}

int read_handler(int fd, void *buffer, size_t size) {
	validate_user_ptr(buffer, true);
	int ret_value = 0;
	struct file_fd* curr = lookup_file(fd);
	if (curr == NULL || curr -> fd != fd || curr->std == 1){
		return -1;
	}

	if (curr->std == 2 && curr-> file == NULL) {
		while (size-- > 0) {
			*(uint8_t*)buffer = input_getc();
			buffer += sizeof(uint8_t);	
			ret_value++;
		}
	}
	else {
		if (curr -> file == NULL || inode_is_directory(file_get_inode(curr -> file))) {
			return -1;
		}
    	ASSERT(curr->file!= NULL);
		lock_acquire(&filesys_lock);
		ret_value = file_read(curr -> file, buffer, size);
		lock_release(&filesys_lock);
	}
	return ret_value;
}

int write_handler(int fd, const void *buffer, size_t size) {
	validate_user_ptr(buffer, false);
	struct file_fd* curr = lookup_file(fd);
  	if (curr == NULL || curr -> fd != fd || curr -> std == 2){
		return -1;
	}
	int ret_value = 0;
	if (curr->std == 1 && curr-> file == NULL) {
		putbuf(buffer, size);
		ASSERT(size <= 400);
		ret_value = size;
	}
	else {
		if (curr -> file == NULL || inode_is_directory(file_get_inode(curr -> file))) {
			return -1;
		}
    	ASSERT(curr->file != NULL);
		lock_acquire(&filesys_lock);
		ret_value = file_write(curr -> file, buffer, size);
		lock_release(&filesys_lock);
	}
	return ret_value;
}

void seek_handler(int fd, uint64_t position) {
	struct file_fd* curr = lookup_file(fd);
	if (curr == NULL || curr -> fd != fd || curr -> std != 0) {
		return;
	}
	if (curr -> file == NULL || inode_is_directory(file_get_inode(curr -> file))) {
		return;
	}
	lock_acquire(&filesys_lock);
	file_seek(curr -> file, position);
	lock_release(&filesys_lock);
}

uint64_t tell_handler(int fd) {
	struct file_fd* curr = lookup_file(fd);
	if (curr == NULL || curr -> fd != fd || curr -> std != 0) {
		return 0;
	}
	if (curr -> file == NULL || inode_is_directory(file_get_inode(curr -> file))) {
		return 0;
	}
	lock_acquire(&filesys_lock);
	int ret_value = file_tell(curr -> file);
	lock_release(&filesys_lock);
	return ret_value;
}

void close_handler(int fd) {
	struct file_fd* curr = lookup_file(fd);
	if (curr == NULL || curr -> fd != fd) {
		return;
	}
	lock_acquire(&filesys_lock);
	list_remove(&curr -> elem_fd);
	if (curr -> file != NULL)
		try_close(curr -> file, &thread_current() -> fds);
	lock_release(&filesys_lock);
	free(curr);
}

int dup2_handler(int oldfd, int newfd) {
	struct file_fd* old = lookup_file(oldfd);
	if (old == NULL || old -> fd != oldfd || newfd < 0) {
		return -1;
	}
	if (newfd == oldfd) {
		return newfd;
	}
	close_handler(newfd);
	struct file_fd* new = calloc (1, sizeof(struct file_fd));
	if (new == NULL) {
		return -1;
	}
	new -> fd = newfd;
	new -> file = old -> file;
	new -> std = old -> std;

	enum intr_level old_level = intr_disable();
	struct file_fd* before = lookup_file(newfd - 1);
	if (before != NULL) {
		list_insert(list_next(&before -> elem_fd), &new -> elem_fd);
	}
	else {
		list_push_front(&thread_current() -> fds, &new -> elem_fd);
	}
	intr_set_level(old_level);
	return newfd;
}

void* mmap_handler(void* addr, size_t length, int writable, int fd, off_t offset) {
	if (addr == NULL || length == 0) {
		return NULL;
	}
	struct file_fd* file_fd = lookup_file(fd);
	if (file_fd == NULL || file_fd -> file == NULL || file_fd -> std > 0 || inode_is_directory(file_get_inode(file_fd -> file))) {
		return NULL;
	}
	if (file_length(file_fd -> file) == 0) {
		return NULL;
	}
	return do_mmap(addr, length, writable, file_fd -> file, offset);
}

void* munmap_handler(void* addr) {
	validate_user_ptr(addr, false);
	if (addr == NULL) {
		return;
	}
	do_munmap(addr);
}

bool chdir_handler(const char* dir) {
	validate_user_ptr(dir, false);
	return filesys_chdir(dir);
}

bool mkdir_handler(const char* dir) {
	validate_user_ptr(dir, false);
	return filesys_mkdir(dir);
}

bool readdir_handler(int fd, char* name) {
	validate_user_ptr(name, true);
	if (strlen(name) > READDIR_MAX_LEN) {
		return false;
	}
	struct file_fd* file_fd = lookup_file(fd);
	if (file_fd == NULL || file_fd -> file == NULL || file_fd -> std > 0) {
		return false;
	}
	if (!inode_is_directory(file_get_inode(file_fd -> file))) {
		return false;
	}
	char temp_name[READDIR_MAX_LEN + 1];
	if (!filesys_readdir(file_fd -> file, temp_name)) {
		return false;
	}
	strlcpy(name, temp_name, sizeof temp_name);
	return true;
}

bool isdir_handler(int fd) {
	struct file_fd* file_fd = lookup_file(fd);
	if (file_fd == NULL || file_fd -> file == NULL || file_fd -> std > 0) {
		return false;
	}
	return inode_is_directory(file_get_inode(file_fd -> file));
}

int inumber_handler(int fd) {
	struct file_fd* file_fd = lookup_file(fd);
	if (file_fd == NULL || file_fd -> file == NULL || file_fd -> std > 0) {
		return false;
	}
	struct inode *inode = file_get_inode(file_fd -> file);
	ASSERT(inode != NULL);
	return inode_get_inumber(inode);
}

int symlink_handler(const char* target, const char *linkpath) {
	validate_user_ptr(target, false);
	validate_user_ptr(linkpath, false);
	size_t sz_target = strlen(target);
	size_t sz_linkpath = strlen(linkpath);
	char temp_target[sz_target + 1];
	char temp_linkpath[sz_linkpath + 1];
	strlcpy(temp_target, target, sizeof temp_target);
	strlcpy(temp_linkpath, linkpath, sizeof temp_linkpath);
	return filesys_symlink(temp_target, temp_linkpath);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	uint64_t syscall_number = f -> R.rax;
	
	//%rdi, %rsi, %rdx, %r10, %r8, and %r9
	uint64_t args[] = {f -> R.rdi, f -> R.rsi, f -> R.rdx, f -> R.r10, f -> R.r8, f -> R.r9};

	// saving the rsp in transition from user mode to kernel mode
	#ifdef VM
		thread_current() -> actual_rsp = f -> rsp;
	#endif

	if (syscall_number == SYS_HALT) {
		halt_handler();
	}
	else if (syscall_number == SYS_EXIT) {
		exit_handler(args[0]);
	}
	else if (syscall_number == SYS_FORK) {
		fork_handler(args[0], f);
	}
	else if (syscall_number == SYS_EXEC) {
		f -> R.rax = exec_handler(args[0]);
	}

	else if (syscall_number == SYS_WAIT) {
		f -> R.rax = wait_handler(args[0]);
	}
	else if (syscall_number == SYS_CREATE) {
		f -> R.rax = create_handler(args[0], args[1]);
	}
	else if (syscall_number == SYS_REMOVE) {
		f -> R.rax = remove_handler(args[0]);
	}
	else if (syscall_number == SYS_OPEN) {
		f -> R.rax = open_handler(args[0]);
	}
	else if (syscall_number == SYS_FILESIZE) {
		f -> R.rax = filesize_handler(args[0]);
	}
	else if (syscall_number == SYS_READ) {
		f -> R.rax = read_handler(args[0], args[1], args[2]);
	}
	else if (syscall_number == SYS_WRITE) {
		f -> R.rax = write_handler(args[0], args[1], args[2]);
	}
	else if (syscall_number == SYS_SEEK) {
		seek_handler(args[0], args[1]);
	}
	else if (syscall_number == SYS_TELL) {
		f -> R.rax = tell_handler(args[0]);
	}
	else if (syscall_number == SYS_CLOSE) {
		close_handler(args[0]);
	}
	else if (syscall_number == SYS_DUP2) {
		f -> R.rax = dup2_handler(args[0], args[1]);
	}
	else if (syscall_number == SYS_MMAP) {
		f -> R.rax = mmap_handler(args[0], args[1], args[2], args[3], args[4]);
	}
	else if (syscall_number == SYS_MUNMAP) {
		munmap_handler(args[0]);
	}
	else if (syscall_number == SYS_CHDIR) {
		f -> R.rax = chdir_handler(args[0]);
	}
	else if (syscall_number == SYS_MKDIR) {
		f -> R.rax = mkdir_handler(args[0]);
	}
	else if (syscall_number == SYS_READDIR) {
		f -> R.rax = readdir_handler(args[0], args[1]);
	}
	else if (syscall_number == SYS_ISDIR) {
		f -> R.rax = isdir_handler(args[0]);
	}
	else if (syscall_number == SYS_INUMBER) {
		f -> R.rax = inumber_handler(args[0]);
	}
	else if (syscall_number == SYS_SYMLINK) {
		f -> R.rax = symlink_handler(args[0], args[1]);
	}
	else {
		ASSERT(false);
	}
	//thread_exit ();
}