/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"


struct list all_frames;
struct lock all_frames_lock;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init(&all_frames_lock);
	list_init(&all_frames);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

bool page_is_uninit(struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	return VM_TYPE(ty) == VM_UNINIT;
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {
	ASSERT (pg_ofs(upage) == 0);
	ASSERT (VM_TYPE(type) != VM_UNINIT);
	struct supplemental_page_table *spt = &thread_current ()->spt;
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page* cur_page = calloc(1, sizeof(struct page));
		if (cur_page == NULL) {
			goto err;
		}
		
		bool (*page_initializer) (struct page *, enum vm_type, void *kva);

		if (VM_TYPE(type) == VM_ANON) {
			page_initializer = anon_initializer;
		}
		else if (VM_TYPE(type) == VM_FILE) {
			page_initializer = file_backed_initializer;
		}
		else if (VM_TYPE(type) == VM_PAGE_CACHE) {
			page_initializer = page_cache_initializer;
		}
		else {
			goto err;
		}
		uninit_new(cur_page, upage, init, type, aux, page_initializer);
		cur_page -> writable = writable;
		
		/* TODO: Insert the page into the spt. */
		if (spt_insert_page(spt, cur_page) == false) {
			vm_dealloc_page(cur_page);
			goto err;
		}
		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	ASSERT (pg_ofs(va) == 0);
	struct page *page = NULL;
	/* TODO: Fill this function. */
	// copy of va
	page = calloc(1, sizeof(struct page));
	if (page == NULL) {
		return NULL;
	}
	page -> va = va;

	//lock_acquire(&spt -> page_table_lock);
	struct hash_elem *e = hash_find(&spt -> page_table, &page -> hash_spt);
	//lock_release(&spt -> page_table_lock);
	
	free(page);
	if (e == NULL) {
		return NULL;
	}
	return hash_entry(e, struct page, hash_spt);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	int succ = false;

	/* TODO: Fill this function. */

	if (spt_find_page(spt, page -> va) == NULL) {
		lock_acquire(&spt -> page_table_lock);
		hash_insert(&spt -> page_table, &page -> hash_spt);
		lock_release(&spt -> page_table_lock);
		succ = true;
	}

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	lock_acquire(&spt -> page_table_lock);
	hash_delete(&spt -> page_table, &page -> hash_spt);
	lock_release(&spt -> page_table_lock);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */
	if (list_empty(&all_frames)) {
		PANIC("Could not find victim");
	}
	lock_acquire(&all_frames_lock);
	struct list_elem* front = list_front(&all_frames);
	victim = list_entry (front, struct frame, elem_all);
	ASSERT(victim -> page != NULL);
	list_remove(&victim -> elem_all);
	lock_release(&all_frames_lock);
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim -> page);
	victim -> page = NULL;
	return victim;
}
/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	void* kva = palloc_get_page(PAL_USER);
	if (kva == NULL) {
		return vm_evict_frame();
	}
	frame = calloc(1, sizeof(struct frame));
	if (frame == NULL) {
		PANIC("PAGE ALLOCATION FAILURE 2");
	}
	
	frame -> kva = kva;
	frame -> page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	void* page_rsp = thread_current() -> stack_bottom;
	while (page_rsp > addr) {
		void* stack_bottom = (void *) (((uint8_t *) page_rsp) - PGSIZE);
		if (vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, true))
			vm_claim_page(stack_bottom);
		page_rsp = stack_bottom;
	}
	thread_current() -> stack_bottom = page_rsp;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {

	struct supplemental_page_table *spt = &thread_current ()->spt;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (user && is_kernel_vaddr(addr)) {
		return false;
	}
	void* page_addr = pg_round_down(addr);
	uint32_t page_ofs = pg_ofs(addr);
	if (not_present) {
		uintptr_t rsp = f -> rsp;
		// stack growth
		if (!user) {
			rsp = thread_current() -> actual_rsp;
		}
		vm_stack_growth(rsp);	
		if (thread_current() -> stack_bottom > addr && (thread_current() -> stack_bottom - (uintptr_t)addr) <= 8) {
			if ((USER_STACK - (uint32_t)addr) > MAX_STACK_SIZE) {
				return false;
			}
			vm_stack_growth(addr);
			return true;
		}
		return vm_claim_page(page_addr);
	}
	else {
		// copy on write
		return false;
	}
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	ASSERT (pg_ofs(va) == 0);
	
	struct page *page = NULL;

	struct thread* t = thread_current();
	/* TODO: Fill this function */
	page = spt_find_page(&(t -> spt), va);
	if (page == NULL) {
		return false;
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (pml4_set_page(thread_current() -> pml4, page -> va, frame -> kva, page -> writable) == false) {
		palloc_free_page(frame -> kva);
		free(frame);
		page -> frame = NULL;
		return false;
	}
	list_push_back(&all_frames, &frame -> elem_all);
	return swap_in (page, frame->kva);
}

bool hash_less(const struct hash_elem *a,
		const struct hash_elem *b,
		void *aux) {
	struct page* p1 = hash_entry(a, struct page, hash_spt);
	struct page* p2 = hash_entry(b, struct page, hash_spt);
	return p1 -> va < p2 -> va;
}

uint64_t hash_hash(const struct hash_elem *e, void *aux) {
	struct page* p1 = hash_entry(e, struct page, hash_spt);
	return hash_bytes(&p1 -> va, sizeof(p1 -> va));
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	lock_init(&spt -> page_table_lock);
	lock_acquire(&spt -> page_table_lock);
	hash_init(&spt -> page_table, hash_hash, hash_less, NULL);
	lock_release(&spt -> page_table_lock);
	spt -> initialized = true;
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	bool succ = true;
	struct hash_iterator i;
	
	lock_acquire(&src -> page_table_lock);
	hash_first (&i, &src -> page_table);
	lock_release(&src -> page_table_lock);
	while (true)
	{
		lock_acquire(&src -> page_table_lock);
		hash_next (&i);
		lock_release(&src -> page_table_lock);
		if (!hash_cur(&i)) {
			break;
		}

		struct page* page = hash_entry (hash_cur (&i), struct page, hash_spt);
		enum vm_type type = page_get_type(page);
		// if (!vm_alloc_page(type, page -> va, page -> writable)) {
		// 	return false;
		// }
		// struct page* cur_page = spt_find_page(src, page -> va);
		// vm_do_claim_page(cur_page);
		struct page* cur_page = calloc(1, sizeof(struct page));
		if (cur_page == NULL) {
			succ = false;
			goto error;
		}
		if (page_is_uninit(page)) {
			struct uninit_page* uninit = &page -> uninit;
			
			// copy aux
			void* cur_aux = NULL;
			if (uninit -> aux != NULL) {
				cur_aux = calloc(sizeof(struct for_lazy_load), 1);
				if (cur_aux == NULL) {
					vm_dealloc_page(cur_page);
					succ = false;
					goto error;
				}
				memcpy(cur_aux, uninit -> aux, sizeof(struct for_lazy_load));
			}
			uninit_new(cur_page, page -> va, uninit -> init, uninit -> type, cur_aux, uninit -> page_initializer);
			cur_page -> writable = page -> writable;

			/* TODO: Insert the page into the spt. */
			if (spt_insert_page(dst, cur_page) == false) {
				vm_dealloc_page(cur_page);
				succ = false;
				goto error;
			}
			continue;
		}
		ASSERT(VM_TYPE(type) != VM_UNINIT);
		bool (*page_initializer) (struct page *, enum vm_type, void *kva);

		if (VM_TYPE(type) == VM_ANON) {
			page_initializer = anon_initializer;
		}
		else if (VM_TYPE(type) == VM_FILE) {
			page_initializer = file_backed_initializer;
		}
		else if (VM_TYPE(type) == VM_PAGE_CACHE) {
			NOT_REACHED();
		}
		else {
			vm_dealloc_page(cur_page);
			succ = false;
			goto error;
		}
		uninit_new(cur_page, page -> va, NULL, type, NULL, page_initializer);
		cur_page -> writable = page -> writable;
		
		if (vm_do_claim_page(cur_page) == false) {
			vm_dealloc_page(cur_page);
			succ = false;
			goto error;
		}
		/* TODO: Insert the page into the spt. */
		if (spt_insert_page(dst, cur_page) == false) {
			vm_dealloc_page(cur_page);
			succ = false;
			goto error;
		}
		memcpy(cur_page -> frame -> kva, page -> frame -> kva, PGSIZE);
	}
error:
	return succ;
}

void hash_destructor(struct hash_elem* e, void* aux) {
	struct page* page = hash_entry(e, struct page, hash_spt);
	vm_dealloc_page(page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if (spt -> initialized == false) {
		return;
	}
	lock_acquire(&spt -> page_table_lock);
	hash_clear(&spt -> page_table, &hash_destructor);
	lock_release(&spt -> page_table_lock);
}
