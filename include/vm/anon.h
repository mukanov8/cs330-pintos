#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "devices/disk.h"
#include "bitmap.h"
#include "threads/vaddr.h"

struct page;
enum vm_type;

#define SECTORS_PER_PAGE (PGSIZE / DISK_SECTOR_SIZE)

struct anon_page {
    disk_sector_t st_sectors[SECTORS_PER_PAGE];
	bool in_swap_disk;
};

struct swap_table {
	struct bitmap* swap_table;
	struct lock swap_table_lock;
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
