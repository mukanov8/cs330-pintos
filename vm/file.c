/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
//#include "userprog/process.h"


static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

void file_backed_write_back(struct file* file, struct page* page) {
	ASSERT(page_get_type(page) == VM_FILE);
	ASSERT(page -> frame != NULL);
	if (page -> writable == false || pml4_is_dirty(thread_current() -> pml4, page -> va) == false) {
		return;
	}
	struct file_page *file_page = &page->file;
	void* kva = page -> frame -> kva;
	file_write_at(file, kva, file_page -> size, file_page -> ofs);
	pml4_set_dirty(thread_current() -> pml4, page -> va, false);
}

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
	
	struct file_page *file_page = &page->file;
	file_page -> file = NULL;
	file_page -> start_addr = NULL;
	file_page -> ofs = 0;
	file_page -> size = 0;
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	ASSERT(page != NULL);
	enum vm_type type = page_get_type(page);
	ASSERT(VM_TYPE(type) == VM_FILE);
	ASSERT(!page_is_uninit(page));
	
	struct file_page *file_page = &page->file;
	if (file_page -> file == NULL) {
		return false;
	}
	int32_t res_read_bytes = file_read_at(file_page -> file, kva, file_page -> size, file_page -> ofs);
	int32_t zero_bytes = PGSIZE - file_page -> size;
	if (res_read_bytes != (int32_t)(file_page -> size)) {
		int32_t diff = (int32_t)(file_page -> size) - res_read_bytes;
		memset(kva + res_read_bytes, 0, diff);
	}
	memset(kva + file_page -> size, 0, zero_bytes);
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	ASSERT(page != NULL);
	enum vm_type type = page_get_type(page);
	ASSERT(VM_TYPE(type) == VM_FILE);
	ASSERT(!page_is_uninit(page));
	
	struct file_page *file_page = &page->file;
	if (file_page -> file == NULL) {
		return false;
	}
	if (page -> frame != NULL) {
		file_backed_write_back(file_page -> file, page);
	}
	ASSERT(pml4_is_dirty(thread_current() -> pml4, page -> va) == false);
	pml4_clear_page (thread_current() -> pml4, page -> va);
	pml4_set_accessed (thread_current() -> pml4, page -> va, false);
	page -> frame = NULL;
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	ASSERT(page != NULL);
	enum vm_type type = page_get_type(page);
	ASSERT(VM_TYPE(type) == VM_FILE);
	ASSERT(!page_is_uninit(page));
	struct file_page *file_page = &page->file;
	if (file_page -> file == NULL) {
		return;
	}
	ASSERT(file_page -> file != NULL);
	if (page -> frame != NULL) {
		file_backed_write_back(file_page -> file, page);
	}
	ASSERT(pml4_is_dirty(thread_current() -> pml4, page -> va) == false);
	file_close(file_page -> file);
	file_page -> file = NULL;
	file_page -> start_addr = NULL;
	file_page -> ofs = 0;
	file_page -> size = 0;
	if (page -> frame != NULL) {
		list_remove(&(page -> frame -> elem_all));
		free(page -> frame);
	}
}

static bool
file_lazy_load (struct page *page, void *aux) {
	struct for_lazy_load *info = aux;
	uint8_t *buffer = page -> frame -> kva;
	int32_t res_read_bytes = file_read_at(info -> file, buffer, info -> page_read_bytes, info -> ofs);
	if (res_read_bytes != (int32_t)(info -> page_read_bytes)) {
		int32_t diff = (int32_t)(info -> page_read_bytes) - res_read_bytes;
		memset(buffer + res_read_bytes, 0, diff);
		// if (info -> need_to_close) {
		// 	file_close(info -> file);
		// }
		// free(info);
		// return false;
	}
	memset(buffer + info -> page_read_bytes, 0, info -> page_zero_bytes);
	
	struct file_page *file_page = &page->file;
	file_page -> file = info -> file;
	file_page -> start_addr = info -> start_addr;
	file_page -> ofs = info -> ofs;
	file_page -> size = info -> page_read_bytes;
	free(info);
	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t ofs) {
	if (pg_ofs(addr) != 0 || pg_ofs(ofs) != 0) {
		return NULL;
	}
	void* start_addr = addr;
	//overlap
	while (length > 0) {
		if (is_user_vaddr(addr) == false) {
			return NULL;
		}
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct for_lazy_load* my_aux = calloc(sizeof(struct for_lazy_load), 1);
		my_aux -> file = file_reopen(file);
		ASSERT(my_aux -> file != NULL);
		my_aux -> need_to_close = true;
		my_aux -> ofs = ofs;
		my_aux -> page_read_bytes = page_read_bytes;
		my_aux -> page_zero_bytes = page_zero_bytes;
		my_aux -> start_addr = start_addr;
		void *aux = my_aux;
		if (!vm_alloc_page_with_initializer (VM_FILE, addr,
					writable, file_lazy_load, aux)) {
			if (my_aux -> need_to_close) {
				file_close(my_aux -> file);
			}
			free (my_aux);
			return NULL;
		}

		length -= page_read_bytes;
		addr += PGSIZE;
		ofs += page_read_bytes;
	}
	return start_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	if (pg_ofs(addr) != 0) {
		return;
	}
	void* start_addr = addr;
	while (true) {
		struct page* page = spt_find_page(&thread_current() -> spt, addr);
		if (page == NULL) {
			return;
		}
		enum vm_type type = page_get_type(page);
		if (page_is_uninit(page)) {
			struct uninit_page *uninit_page = &page -> uninit;
			if (VM_TYPE(uninit_page -> type) != VM_FILE) {
				return;
			}
			struct for_lazy_load* my_aux = uninit_page -> aux;
			if (my_aux -> start_addr != start_addr) {
				return;
			}
		}
		else {
			if (VM_TYPE(type) != VM_FILE) {
				return;
			}
			struct file_page *file_page = &page->file;
			if (file_page -> start_addr != start_addr) {
				return;
			}	
		}
		spt_remove_page(&thread_current() -> spt, page);
		addr += PGSIZE;
	}
}
