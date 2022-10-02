#ifndef FILESYS_PAGE_CACHE_H
#define FILESYS_PAGE_CACHE_H
#include "vm/vm.h"

struct page;
enum vm_type;

#define CACHE_SECTORS 64
#define CACHE_PAGES CACHE_SECTORS / SECTORS_PER_PAGE

struct page_cache {
    disk_sector_t sector_ptrs[SECTORS_PER_PAGE];
    bool occupied[SECTORS_PER_PAGE];
};

void page_cache_init (void);
bool page_cache_initializer (struct page *page, enum vm_type type, void *kva);
#endif
