#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/fat.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* A directory. */
struct dir {
	struct inode *inode;                /* Backing store. */
	off_t pos;                          /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
	disk_sector_t inode_sector;         /* Sector number of header. */
	char name[NAME_MAX + 1];            /* Null terminated file name. */
	bool in_use;                        /* In use or free? */
	bool is_symlink;
	char symlink[PATH_MAX + 1];
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt) {
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry));
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) {
	struct dir *dir = calloc (1, sizeof *dir);
	if (inode != NULL && dir != NULL) {
		dir->inode = inode;
		dir->pos = 0;
		return dir;
	} else {
		inode_close (inode);
		free (dir);
		return NULL;
	}
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *
dir_open_root (void) {
	#ifdef EFILESYS
		return dir_open (inode_open (cluster_to_sector (ROOT_DIR_CLUSTER)));
	#else
		return dir_open (inode_open (ROOT_DIR_SECTOR));
	#endif
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) {
	return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) {
	if (dir != NULL) {
		inode_close (dir->inode);
		free (dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) {
	return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
		struct dir_entry *ep, off_t *ofsp) {
	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e) {
		if (e.in_use && !strcmp (name, e.name)) {
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			return true;
		}
	}
	return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
		struct inode **inode) {
	struct dir_entry e;
	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if (lookup (dir, name, &e, NULL)) {
		#ifdef EFILESYS
			if (e.is_symlink) {
				//decode
				char temp_symlink[sizeof e.symlink];
				strlcpy(temp_symlink, e.symlink, sizeof e.symlink);
				struct dir* temp_dir = dir_reopen(dir);
				if (!dir_chdir(&temp_dir, temp_symlink, true)) {
					dir_close(temp_dir);
					return false;
				}
				bool result = dir_lookup(temp_dir, temp_symlink, inode);
				dir_close(temp_dir);
				return result;
			}
		#endif
		*inode = inode_open (e.inode_sector);
	}
	else
		*inode = NULL;

	return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);
	/* Check NAME for validity. */
	if (*name == '\0' || strlen (name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. */
	if (lookup (dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;
	/* Write slot. */
	e.in_use = true;
	strlcpy (e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	e.is_symlink = false;
	success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
	return success;
}

bool dir_add_symlink(struct dir *dir, const char *name, const char* target) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);
	ASSERT (target != NULL);

	/* Check NAME for validity. */
	if (*name == '\0' || strlen (name) > NAME_MAX)
		return false;

	if (*target == '\0' || strlen(target) > PATH_MAX) {
		return false;
	}
	/* Check that NAME is not in use. */
	if (lookup (dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy (e.name, name, sizeof e.name);
	e.inode_sector = 0;
	e.is_symlink = true;
	strlcpy(e.symlink, target, sizeof e.symlink);
	success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
done:
	return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) {
	struct dir_entry e;
	struct inode *inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Find directory entry. */
	if (!lookup (dir, name, &e, &ofs))
		goto done;
	if (e.is_symlink) {
		e.in_use = false;
		if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
			return false;
		return true;
	}
	/* Open inode. */
	inode = inode_open (e.inode_sector);
	if (inode == NULL)
		goto done;
	
	if (inode_is_directory(inode) && !dir_is_empty(inode)) {
		goto done;
	}
	
	if (inode_is_root_directory(inode)) {
		goto done;
	}
	
	/* Erase directory entry. */
	e.in_use = false;
	if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. */
	inode_remove (inode);
	success = true;

done:
	inode_close (inode);
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1]) {
	struct dir_entry e;

	while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
		dir->pos += sizeof e;
		if (e.in_use) {
			strlcpy (name, e.name, sizeof e.name);
			return true;
		}
	}
	return false;
}

#ifdef EFILESYS

void
dir_seek (struct dir *dir, off_t new_pos) {
	ASSERT (dir != NULL);
	ASSERT (new_pos >= 0);
	dir->pos = new_pos;
}

/* Returns the current position in FILE as a byte offset from the
 * start of the file. */
off_t
dir_tell (struct dir *dir) {
	ASSERT (dir != NULL);
	return dir->pos;
}

bool dir_is_empty(struct inode *inode) {
	ASSERT(inode_is_directory(inode));
	struct dir_entry e;
	
	for (off_t ofs = 0; inode_read_at (inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (e.in_use) {
			if (!strcmp(e.name, ".") || !strcmp(e.name, "..")) {
				continue;
			}
			return false;
		}
	return true;
}

bool dir_create_adv(disk_sector_t sector, disk_sector_t parent) {
	if (inode_create(sector, 0)) {
		struct inode *inode = inode_open(sector);
		inode_make_directory(inode);
		struct dir *dir = dir_open(inode);
		bool success = dir_add(dir, ".", sector) && dir_add(dir, "..", parent);
		dir_close(dir);
		return success;
	}
	return false;
}

bool dir_chdir(struct dir **dir, char* path, bool skip_last) {
	ASSERT(*dir != NULL);
	ASSERT(path != NULL);
	char *token, *save_ptr;
	if (path[0] == '/') {
		dir_close(*dir);
		*dir = dir_open_root();
	}
	size_t act_path_start = 0;
	while (path[act_path_start] == '/') act_path_start++;
	strlcpy(path, path + act_path_start, PATH_MAX + 1);
	for (token = strtok_r(path, DIRECTORY_SEP, &save_ptr); token != NULL;
		token = strtok_r(NULL, DIRECTORY_SEP, &save_ptr)) {
		if (skip_last && *save_ptr == '\0') {
			strlcpy(path, token, PATH_MAX + 1);
			break;
		}
		struct inode *inode;
		if (!dir_lookup(*dir, token, &inode)) {
			return false;
		}
		if (inode == NULL) {
			return false;	
		}
		if (!inode_is_directory(inode)) {
			return false;
		}
		struct dir* nxt = dir_open(inode);
		dir_close(*dir);
		*dir = nxt;
	}
	return true;
}

bool dir_is_available(struct dir *dir) {
	if (dir == NULL) {
		return false;
	}
	if (inode_is_root_directory(dir -> inode)) {
		return true;
	}
	struct inode *parent_inode;
	struct dir_entry e;
	if (!dir_lookup(dir, "..", &parent_inode)) {
		return false;
	}
	for (off_t ofs = 0; inode_read_at (parent_inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e) {
		if (e.in_use) {
			if (!strcmp(e.name, ".") || !strcmp(e.name, "..")) {
				continue;
			}
			if (e.inode_sector == inode_get_inumber(dir -> inode)) {
				return true;
			}
		}
	}
	return false;
}
#endif