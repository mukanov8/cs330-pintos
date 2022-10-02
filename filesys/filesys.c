#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/fat.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "threads/thread.h"

/*

rm -f tmp.dsk
pintos-mkdisk tmp.dsk 2
pintos -v -k -T 60 -m 20   --fs-disk=tmp.dsk -p tests/filesys/extended/dir-empty-name:dir-empty-name -p tests/filesys/extended/tar:tar --swap-disk=4 -- -q   -f run dir-empty-name
pintos -v -k -T 120   --fs-disk=tmp.dsk -g fs.tar:tests/filesys/extended/dir-empty-name.tar --swap-disk=4 -- -q  run 'tar fs.tar /'

rm -f tmp.dsk
pintos-mkdisk tmp.dsk 2
pintos -v -k -T 60 -m 20   --fs-disk=tmp.dsk -p tests/filesys/extended/dir-mk-tree:dir-mk-tree -p tests/filesys/extended/tar:tar --swap-disk=4 -- -q   -f run dir-mk-tree
pintos -v -k -T 120   --fs-disk=tmp.dsk -g fs.tar:tests/filesys/extended/dir-mk-tree.tar --swap-disk=4 -- -q  run 'tar fs.tar /'

synch issue
rm -f tmp.dsk
pintos-mkdisk tmp.dsk 2
pintos -v -k -T 60 -m 20   --fs-disk=tmp.dsk -p tests/filesys/extended/syn-rw:syn-rw -p tests/filesys/extended/tar:tar -p tests/filesys/extended/child-syn-rw:child-syn-rw --swap-disk=4 -- -q   -f run syn-rw < /dev/null 2> tests/filesys/extended/syn-rw.errors > tests/filesys/extended/syn-rw.output
pintos -v -k -T 120   --fs-disk=tmp.dsk -g fs.tar:tests/filesys/extended/syn-rw.tar --swap-disk=4 -- -q  run 'tar fs.tar /' < /dev/null 2> tests/filesys/extended/syn-rw-persistence.errors > tests/filesys/extended/syn-rw-persistence.output

rm -f tmp.dsk
pintos-mkdisk tmp.dsk 2
pintos -v -k -T 60 -m 20   --fs-disk=tmp.dsk -p tests/filesys/extended/grow-create:grow-create -p tests/filesys/extended/tar:tar --swap-disk=4 -- -q   -f run grow-create
pintos -v -k -T 120   --fs-disk=tmp.dsk -g fs.tar:tests/filesys/extended/grow-create.tar --swap-disk=4 -- -q  run 'tar fs.tar /'

*/

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	inode_close_all();
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	#ifdef EFILESYS
		if (strlen(name) > PATH_MAX) {
			return false;
		}
		char temp_name[PATH_MAX + 1];
		strlcpy(temp_name, name, sizeof temp_name);
		cluster_t start = fat_create_chain(0);
		if (start == 0) {
			return false;
		}
		disk_sector_t sector = cluster_to_sector(start);
		if (!inode_create(sector, 0)) {
			fat_remove_chain(start, 0);
			return false;
		}
		
		struct dir *dir;
		if (thread_current() -> current_dir == NULL) {
			//kernel process -> root
			dir = dir_open_root();
		}
		else {
			dir = dir_reopen(thread_current() -> current_dir);
		}
		if (!dir_chdir(&dir, temp_name, true)) {
			dir_close(dir);
			fat_remove_chain(start, 0);
			return false;
		}

		if (dir == NULL || !dir_is_available(dir) || !dir_add(dir, temp_name, sector)) {
			dir_close(dir);
			fat_remove_chain(start, 0);
			return false;
		}
		struct inode *inode = inode_open(sector);
		char zeros[DISK_SECTOR_SIZE];
		memset(zeros, 0, sizeof zeros);
		uint32_t written = 0;
		while (written < initial_size) {
			uint32_t chunk_size = (initial_size - written) < DISK_SECTOR_SIZE ? (initial_size - written) : DISK_SECTOR_SIZE;
			if (inode_write_at(inode, zeros, chunk_size, written) != chunk_size) {
				inode_remove(inode);
				inode_close(inode);
				dir_close(dir);
				return false;
			}
			written += chunk_size;
		}
		inode_close(inode);
		dir_close(dir);
		return true;
	#else	
		disk_sector_t inode_sector = 0;
		struct dir *dir = dir_open_root ();
		bool success = (dir != NULL
				&& free_map_allocate (1, &inode_sector)
				&& inode_create (inode_sector, initial_size)
				&& dir_add (dir, name, inode_sector));
		if (!success && inode_sector != 0)
			free_map_release (inode_sector, 1);
		dir_close (dir);

		return success;
	#endif
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	#ifdef EFILESYS
		if (strlen(name) > PATH_MAX) {
			return false;
		}
		char temp_name[PATH_MAX + 1];
		strlcpy(temp_name, name, sizeof temp_name);
		struct dir *dir;
		if (thread_current() -> current_dir == NULL) {
			//kernel process -> root
			dir = dir_open_root();
		}
		else {
			dir = dir_reopen(thread_current() -> current_dir);
		}
		if (!dir_chdir(&dir, temp_name, true)) {
			dir_close(dir);
			return NULL;
		}
		if (!strlen(temp_name)) {
			temp_name[0] = '.';
		}
		struct inode *inode = NULL;
		if (dir != NULL && dir_is_available(dir))
			dir_lookup (dir, temp_name, &inode);
		dir_close (dir);
		return file_open (inode);
	#else
		struct dir *dir = dir_open_root ();
		struct inode *inode = NULL;

		if (dir != NULL)
			dir_lookup (dir, name, &inode);
		dir_close (dir);

		return file_open (inode);
	#endif
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	#ifdef EFILESYS
		if (strlen(name) > PATH_MAX) {
			return false;
		}
		char temp_name[PATH_MAX + 1];
		strlcpy(temp_name, name, sizeof temp_name);
		struct dir *dir;
		if (thread_current() -> current_dir == NULL) {
			//kernel process -> root
			dir = dir_open_root();
		}
		else {
			dir = dir_reopen(thread_current() -> current_dir);
		}
		if (!dir_chdir(&dir, temp_name, true)) {
			dir_close(dir);
			return NULL;
		}
		bool success = dir != NULL && dir_remove (dir, temp_name);
		dir_close (dir);
		
		return success;
	#else
		struct dir *dir = dir_open_root ();
		bool success = dir != NULL && dir_remove (dir, name);
		dir_close (dir);
		return success;
	#endif
}

#ifdef EFILESYS
bool filesys_chdir(const char *name) {
	if (strlen(name) > PATH_MAX) {
		return false;
	}
	char temp_name[PATH_MAX + 1];
	strlcpy(temp_name, name, sizeof temp_name);
	ASSERT(thread_current() -> current_dir != NULL);
	struct dir *dir = dir_reopen(thread_current() -> current_dir);
	if (!dir_chdir(&dir, temp_name, false)) {
		dir_close(dir);
		return false;
	}
	if (dir != NULL) {
		dir_close(thread_current() -> current_dir);
		thread_current() -> current_dir = dir;
		return true;
	} 	
	return false;
}

bool filesys_mkdir(const char *name) {
	if (strlen(name) > PATH_MAX) {
		return false;
	}
	char temp_name[PATH_MAX + 1];
	strlcpy(temp_name, name, sizeof temp_name);
	ASSERT(thread_current() -> current_dir != NULL);
	struct dir *dir = dir_reopen(thread_current() -> current_dir);

	if (!dir_chdir(&dir, temp_name, true)) {
		dir_close(dir);
		return false;
	}
	cluster_t new_clst = fat_create_chain(0);
	if (!new_clst) {
		return false;
	}
	disk_sector_t new_sector = cluster_to_sector(new_clst);
	if (!dir_create_adv(new_sector, inode_get_inumber(dir_get_inode(dir)))) {
		fat_remove_chain(new_clst, 0);
		return false;
	}
	bool success = dir != NULL && dir_add(dir, temp_name, new_sector);
	dir_close(dir);
	return success;

}

bool filesys_readdir(struct file* file, char* name) {
	ASSERT(file != NULL);
	struct inode *inode = file_get_inode(file);
	ASSERT(inode_is_directory(inode))
	struct dir* dir = dir_open(inode);
	dir_seek(dir, file_tell(file));
	bool success = false;
	while (dir_readdir(dir, name)) {
		if (!strcmp(name, ".") || !strcmp(name, "..")) {
			continue;
		}
		success = true;
		break;
	}
	file_seek(file, dir_tell(dir));
	return success;
}

int filesys_symlink(char* target, char* linkpath) {
	char temp_linkpath[PATH_MAX + 1];
	strlcpy(temp_linkpath, linkpath, sizeof temp_linkpath);
	ASSERT(thread_current() -> current_dir != NULL);
	struct dir *dir = dir_reopen(thread_current() -> current_dir);
	int success = -1;
	if (!dir_chdir(&dir, temp_linkpath, true)) {
		dir_close(dir);
		return success;
	}
	if (dir_add_symlink(dir, temp_linkpath, target)) {
		success = 0;
	}
	dir_close(dir);
	return success;
}

#endif

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	//add . and .. for root
	disk_sector_t root_sector = cluster_to_sector(ROOT_DIR_CLUSTER);
	if (!dir_create_adv(root_sector, root_sector)) {
		PANIC("root directory creation failed");
	}
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
