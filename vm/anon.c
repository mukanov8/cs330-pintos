/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "random.h"

static struct swap_table main_st;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

static struct swap_table *st;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	st = &main_st;
	lock_init(&st -> swap_table_lock);
	lock_acquire(&st -> swap_table_lock);
	st -> swap_table = bitmap_create(disk_size(swap_disk));
	printf("initalized with: %x, %x\n", disk_size(swap_disk), bitmap_size(st -> swap_table));
	lock_release(&st -> swap_table_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	ASSERT(VM_TYPE(type) == VM_ANON);
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	for (uint32_t i = 0; i < SECTORS_PER_PAGE; i++) {
		anon_page -> st_sectors[i] = BITMAP_ERROR;
	}

	anon_page -> in_swap_disk = false;
	return true;
}

bool anon_swap_in_read_disk (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	ASSERT(anon_page -> in_swap_disk);
	bool succ = true;
	for (uint32_t i = 0; i < SECTORS_PER_PAGE; i++) {	
		disk_sector_t* cur_sector = &anon_page -> st_sectors[i];
		ASSERT(*cur_sector != BITMAP_ERROR);
		ASSERT(bitmap_test(st -> swap_table, *cur_sector));
		void* addr = page -> frame -> kva + (i * DISK_SECTOR_SIZE);
		disk_read(swap_disk, *cur_sector, addr);
		lock_acquire(&st -> swap_table_lock);
		bitmap_set(st -> swap_table, *cur_sector, false);
		lock_release(&st -> swap_table_lock);
		*cur_sector = BITMAP_ERROR; 
	}
	anon_page -> in_swap_disk = false;
	return succ;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	if (anon_page -> in_swap_disk) {
		return anon_swap_in_read_disk(page, kva);
	}
	ASSERT(page -> frame != NULL);
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	ASSERT(!anon_page -> in_swap_disk);
	bool succ = true;
	for (uint32_t i = 0; i < SECTORS_PER_PAGE; i++) {	
		disk_sector_t* cur_sector = &anon_page -> st_sectors[i];
		ASSERT(*cur_sector == BITMAP_ERROR);
		size_t iterations = 0;
		while (*cur_sector == BITMAP_ERROR && iterations <= 100000) {
			iterations++;
			size_t start = random_ulong() % bitmap_size(st -> swap_table);
			lock_acquire(&st -> swap_table_lock);
			*cur_sector = bitmap_scan_and_flip(st -> swap_table, start, 1, false);
			lock_release(&st -> swap_table_lock);
		}
		if (*cur_sector == BITMAP_ERROR) {
			PANIC("Could not swap out");
		}
		void* addr = page -> frame -> kva + (i * DISK_SECTOR_SIZE);
		
		disk_write(swap_disk, *cur_sector, addr);
	}
	anon_page -> in_swap_disk = true;
	pml4_clear_page (thread_current() -> pml4, page -> va);
	pml4_set_accessed (thread_current() -> pml4, page -> va, false);
	page -> frame = NULL;
	return succ;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if (page -> frame != NULL) {
		list_remove(&page -> frame -> elem_all);
		free(page -> frame);
	}
	return;
}
