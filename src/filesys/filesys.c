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
  
  struct dir* dir = dir_open(thread_current()->cwd->inode); /* Should be directory of last name in path */
  /* END TASK: Subdirectories */

  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size, is_dir) && dir_add(dir, name, inode_sector));

  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  
  /* START TASK: Subdirectories */
  if (is_dir) {
    struct inode* new_dir_inode = inode_open(inode_sector);
    struct dir* new_dir_struct = dir_open(new_dir_inode);

    bool success = (dir_add(new_dir_struct, ".", inode_sector) && dir_add(new_dir_struct, "..", dir->inode->sector));

    inode_close(new_dir_inode);
    dir_close(new_dir_struct);
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

struct dir* get_directory(const char* dir_path) {
  // dir = t->cwd
  // loop (get_next_part null)
  // get_next_part -> name
  // dir_lookup(dir, name, &inode)
  // dir = inode

  /* Determine if absolute or relative */

  // path = "/Home/Desktop"
  // Desktop cwd
  struct dir* curr_dir;
  if (dir_path[0] == '/') {
    curr_dir = dir_open_root();
  } else {
    curr_dir = thread_current()->cwd;
  }
  char part[NAME_MAX + 1];
  struct inode* inode = NULL;

  int ctr = 0;
  while (get_next_part(part, &dir_path) > 0) {
    bool success = dir_lookup(curr_dir, part, &inode);
    if (ctr > 0) {
      free(curr_dir);
    }
    if (!success) {
      return NULL;
    }
    curr_dir = dir_open(inode);
    ctr++;
  }
  return curr_dir;
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
