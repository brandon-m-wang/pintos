#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

static int get_next_part(char part[NAME_MAX + 1], const char** srcp);
struct dir* get_directory(const char* path, bool mkdir);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  /* START TASK: Buffer Cache */
  init_buffer_cache();
  /* END TASK: Buffer Cache */

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  free_map_close();

  /* START TASK: Buffer Cache */
  flush_cache();
  /* END TASK: Buffer Cache */
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size, bool is_dir) {
  block_sector_t inode_sector = 0;
  
  /* START TASK: Subdirectories */
  struct dir *dir = get_directory(name, true);
  /* END TASK: Subdirectories */

  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size, is_dir) && dir_add(dir, name, inode_sector));

  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  
  /* START TASK: Subdirectories */
  if (is_dir) {
    struct inode* new_dir_inode = inode_open(inode_sector);
    struct dir* new_dir_struct = dir_open(new_dir_inode);

    struct inode *dir_inode = dir_get_inode(dir);
    bool success = (dir_add(new_dir_struct, ".", inode_sector) && dir_add(new_dir_struct, "..", inode_get_sector(dir_inode)));
    dir_close(new_dir_struct);
    if (!success) {
      return NULL;
    }
  }
  /* END TASK: Subdirectories */
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  struct dir* dir = dir_open_root();
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

/* Returns directory struct at end of path. */
struct dir* get_directory(const char* path, bool mkdir) {
  char part[NAME_MAX + 1];
  struct dir* prev = NULL;
  struct dir* cur = thread_current()->cwd;
  struct inode *temp_inode;

  int count = 0;
  int status = get_next_part(part, &path);
  while(status > 0) {
    /* Set temp_inode to be inode of directory named "part".*/
    bool success = dir_lookup(cur, part, &temp_inode);

    /* Free the previous struct directory. */
    if (prev != NULL && count != 1) {
      dir_close(prev);
    }

    if (!success) {
      /* Make sure to free cur before exiting. */
      if (cur != NULL && count != 0) {
        dir_close(cur);
      }
      return NULL;
    }

    /* Save the current directory into prev and set cur to the newly found directory. */
    prev = cur;
    cur = dir_open(temp_inode);

    count++;
    status = get_next_part(part, &path);
  }

  /* Check if path item name is too long. */
  if (status == -1) {
    return NULL;
  }

  /* If mkdir, then return directory where new directory is to be created.
  Otherwise, return the last item in the path. */
  if (mkdir) {
    /* Avoid freeing cur when cur == cwd */
    if (cur != NULL && count != 0) {
      dir_close(cur);
    }
    return prev;
  } else {
    /* Avoid freeing prev when prev == cwd */
    if (prev != NULL && count != 1) {
      dir_close(prev);
    }
    return cur;
  }
}


/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}
