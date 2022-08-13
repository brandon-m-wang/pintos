#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

//static struct lock open_inodes_lock; /* acquire and release lock whenever adding or removing inodes from open_inodes list */

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {

  /* Project 3 Task 2 START */

  block_sector_t direct_blocks[124];    /* direct pointers to data */
  block_sector_t single_indirect_block; /* points to indirect_block struct which points to data */
  block_sector_t double_indirect_block; /* pointer to indirect_block struct that points to more indirect_blocks structs that point to data */

  /* Project 3 Task 2 END */

  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
};


/* Project 3 Task 2 START */

/* a single indirect block */
struct indirect_block {
  /* 8 MiB = 8388608 B => 8388608 B / 512 B = 16384 => sqrt(16384) = 128 */
     /* calculation to justify having array size 128^ */
 
  /* In the case where the file takes up the whole partition (8 MiB), we will have the double_indirect_block pointing to 128 single_indirect_blocks that will each point
   to 128 sectors resulting in 128 * 128 = 16384 blocks. */
  block_sector_t indirect_blocks[128]; /* array of pointers to data or indirect blocks */
};

/* Project 3 Task 2 END */


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */

  /* Project 3 Task 2 START */
  //struct lock inode_read_write_lock;  /* acquire and release lock whenever reading or writing from a single inode */
  /* Project 3 Task 2 END */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  /* Project 3 Task 2 START */

  // Calculate index of block based on pos
  off_t block_index = pos / BLOCK_SECTOR_SIZE;
  
  // Fetch inode_disk struct
  struct inode_disk inode_data = inode->data;

  if (block_index < 124) {
    // Case where we can fetch block from direct blocks
    return inode_data.direct_blocks[block_index];
  } else if (block_index < 252) {
    // Case where we have to check single_indirect_block

    // Read indirect_block struct from disk with cache read and store in buffer
    struct indirect_block *indirect_block; 
    cache_read(inode_data.single_indirect_block, (void*) indirect_block);

    // Using indirect_block struct, read from cache to get block
    return indirect_block->indirect_blocks[block_index - 128];


  } else if (block_index < 252 + 128*128) {
    // Case where we have to check double_direct_block

    // Read indirect_block struct from disk with cache read and store in buffer
    struct indirect_block *double_indirect_block; 
    cache_read(inode_data.double_indirect_block, (void*) double_indirect_block);

    // Using indirect_block struct, index into indirect blocks and read next indirect_block struct
    struct indirect_block *indirect_block; 
    cache_read(double_indirect_block->indirect_blocks[(block_index - 252) / 128], (void*) indirect_block);

    // Read from cache to get block
    return indirect_block->indirect_blocks[(block_index - 252) % 128];

  } else {
    return -1;
  }



  return -1;
  /* Project 3 Task 2 END */
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { 
  list_init(&open_inodes); 
  //lock_init(&open_inodes_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {

    /* Project 3 Task 2 START */

    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;

    // Allocate sector for single indirect block
    bool result = free_map_allocate(1, &disk_inode->single_indirect_block);
    if (result == false) {
      return false;
    }

    // Allocate sector for double indirect block
    result = free_map_allocate(1, &disk_inode->double_indirect_block);
    if (result == false) {
      return false;
    }

    // Allocate sectors within direct block, single indirect block, and double indirect block
    for (int i = 0; i < sectors; i++) {
      if (i < 124) {
        // Case where we can allocate sectors to direct blocks

        bool result = free_map_allocate(1, &disk_inode->direct_blocks[i]);
        if (result == false) {
          return false;
        }
        
      } else if (i < 252) {
        // Case where we can allocate sectors to single indirect blocks

        // Read indirect_block struct from disk with cache read and store in buffer
        struct indirect_block *indirect_block; 
        cache_read(disk_inode->single_indirect_block, (void*) indirect_block);

        // Using indirect_block struct, allocate sectors for its indirect_blocks array
        bool result = free_map_allocate(1, &indirect_block->indirect_blocks[i - 128]);
        if (result == false) {
          return false;
        }

      } else if (i < 252 + 128*128) {
        // Case where we can allocate sectors to double indirect blocks

        // Read indirect_block struct from disk with cache read and store in buffer
        struct indirect_block *double_indirect_block; 
        cache_read(disk_inode->double_indirect_block, (void*) double_indirect_block);

        // Allocate sector to access inner indirect block struct
        bool result = free_map_allocate(1, &double_indirect_block->indirect_blocks[(i - 252) / 128]);
        if (result == false) {
          return false;
        }

        // Using indirect_block struct, index into indirect blocks and read next indirect_block struct that we just allocated
        struct indirect_block *indirect_block; 
        cache_read(double_indirect_block->indirect_blocks[(i - 252) / 128], (void*) indirect_block);

        // Allocate another sector in the inner indirect_block struct to be able to put data in
        result = free_map_allocate(1, &indirect_block->indirect_blocks[(i - 252) % 128]);
        if (result == false) {
          return false;
        }

      } else {
        return false;
      }
    }
    
    // Write disk_inode to cache
    cache_write(sector, (void*) disk_inode);

    /* Project 3 Task 2 END */

    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      
      /* Project 3 Task 2 START */

      struct inode_disk disk_inode = inode->data;
 
      size_t sectors = bytes_to_sectors(disk_inode.length);

      // Read indirect_block struct from disk with cache read and store in buffer
      struct indirect_block *indirect_block; 
      cache_read(disk_inode.single_indirect_block, (void*) indirect_block);

      // Read indirect_block struct from disk with cache read and store in buffer
      struct indirect_block *double_indirect_block; 
      cache_read(disk_inode.double_indirect_block, (void*) double_indirect_block);

      // Allocate sectors within direct block, single indirect block, and double indirect block
      for (int i = 0; i < sectors; i++) {
        if (i < 124) {
          // Case where we can deallocate direct block sectors

          free_map_release(disk_inode.direct_blocks[i], 1);
        
        } else if (i < 252) {
          // Case where we can deallocate single indirect block sectors

          // Using indirect_block struct, deallocate sectors for its indirect_blocks array
          free_map_release(indirect_block->indirect_blocks[i - 128], 1);

        } else if (i < 252 + 128*128) {
          // Case where we can allocate sectors to double indirect blocks

          // Using indirect_block struct, index into indirect blocks and read next indirect_block struct that we just allocated
          struct indirect_block *indirect_block; 
          cache_read(double_indirect_block->indirect_blocks[(i - 252) / 128], (void*) indirect_block);

          // Allocate another sector in the inner indirect_block struct to be able to put data in
          free_map_release(indirect_block->indirect_blocks[(i - 252) % 128], 1);

          if ((i - 252) % 128 == 127) {
            free_map_release(double_indirect_block->indirect_blocks[(i - 252) / 128], 1);
          }
        }

        // Deallocate sector for single indirect block
        free_map_release(disk_inode.single_indirect_block, 1);

        // Deallocate sector for double indirect block
        free_map_release(disk_inode.double_indirect_block, 1);
      } 
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }
