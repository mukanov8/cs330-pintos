#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/disk.h"
#include "filesys/off_t.h"

/* Maximum length of a file name component.
 * This is the traditional UNIX maximum length.
 * After directories are implemented, this maximum length may be
 * retained, but much longer full path names must be allowed. */
#define NAME_MAX 14
#define PATH_MAX 100

#define DIRECTORY_SEP "/"

struct inode;

/* Opening and closing directories. */
bool dir_create (disk_sector_t sector, size_t entry_cnt);
struct dir *dir_open (struct inode *);
struct dir *dir_open_root (void);
struct dir *dir_reopen (struct dir *);
void dir_close (struct dir *);
struct inode *dir_get_inode (struct dir *);

/* Reading and writing. */
bool dir_lookup (const struct dir *, const char *name, struct inode **);
bool dir_add (struct dir *, const char *name, disk_sector_t);
bool dir_remove (struct dir *, const char *name);
bool dir_readdir (struct dir *, char name[NAME_MAX + 1]);

#ifdef EFILESYS
    bool dir_add_symlink(struct dir *, const char *name, const char *target);
    bool dir_chdir(struct dir **, char*, bool);
    bool dir_is_empty(struct inode *);
    bool dir_is_available(struct dir *);
    bool dir_is_available(struct dir *);
    void dir_seek (struct dir *, off_t);
    off_t dir_tell (struct dir *);
    bool dir_create_adv(disk_sector_t, disk_sector_t);
#endif
#endif /* filesys/directory.h */
