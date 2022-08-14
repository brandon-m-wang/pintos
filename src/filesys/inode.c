#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

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
  struct inode_disk *inode_data = malloc(BLOCK_SECTOR_SIZE);
  cache_read(inode->sector, (void*) inode_data);

  if (block_index < 124) {
    // Case where we can fetch block from direct blocks
    return inode_data->direct_blocks[block_index];
  } else if (block_index < 252) {
    // Case where we have to check single_indirect_block

    // Read indirect_block struct from disk with cache read and store in buffer
    struct indirect_block *indirect_block; 
    cache_read(inode_data->single_indirect_block, (void*) indirect_block);

    // Using indirect_block struct, read from cache to get block
    return indirect_block->indirect_blocks[block_index - 128];


  } else if (block_index < 252 + 128*128) {
    // Case where we have to check double_direct_block

    // Read indirect_block struct from disk with cache read and store in buffer
    struct indirect_block *double_indirect_block; 
    cache_read(inode_data->double_indirect_block, (void*) double_indirect_block);

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
void inode_init(void) { list_init(&open_inodes); }

/* Rollback */
void rollback(struct list *allocated_sectors);

struct block_list_elem {
  block_sector_t *block_ptr;
  struct list_elem elem;
};

void rollback(struct list *allocated_sectors) {
  struct block_list_elem *block_elem;
  struct list_elem *iter = list_begin(allocated_sectors);
  while (iter != list_end(allocated_sectors)) {
    block_elem = list_entry(iter, struct block_list_elem, elem);
    iter = list_next(iter);
    free_map_release(*block_elem->block_ptr, 1);
    free(block_elem);
  }
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = true;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    /* Project 3 Task 2 START */
    static char zeros[BLOCK_SECTOR_SIZE];

    struct list allocated_sectors;
    list_init(&allocated_sectors);
    struct block_list_elem *block_elem;

    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;

    /* START TASK: Subdirectories */
    //disk_inode->is_dir = is_dir;
    /* END TASK: Subdirectories */

    // Allocate sector for single indirect block
    bool result = free_map_allocate(1, &disk_inode->single_indirect_block);
    if (result == false) {
      rollback(&allocated_sectors);
      return false;
    }

    // Write allocated sector to disk
    cache_write(disk_inode->single_indirect_block, zeros);

    block_elem = malloc(sizeof(struct block_list_elem));
    block_elem->block_ptr = &disk_inode->single_indirect_block;
    list_push_back(&allocated_sectors, &block_elem->elem);

    // Allocate sector for double indirect block
    result = free_map_allocate(1, &disk_inode->double_indirect_block);
    if (result == false) {
      rollback(&allocated_sectors);
      return false;
    }

    // Write allocated sector to disk
    cache_write(disk_inode->double_indirect_block, zeros);

    block_elem = malloc(sizeof(struct block_list_elem));
    block_elem->block_ptr = &disk_inode->double_indirect_block;
    list_push_back(&allocated_sectors, &block_elem->elem);

    // Allocate sectors within direct block, single indirect block, and double indirect block
    for (int i = 0; i < sectors; i++) {
      if (i < 124) {
        // Case where we can allocate sectors to direct blocks

        bool result = free_map_allocate(1, &disk_inode->direct_blocks[i]);
        if (result == false) {
          rollback(&allocated_sectors);
          return false;
        }

        // Write allocated sector to disk
        cache_write(disk_inode->direct_blocks[i], zeros);

        block_elem = malloc(sizeof(struct block_list_elem));
        block_elem->block_ptr = &disk_inode->direct_blocks[i];
        list_push_back(&allocated_sectors, &block_elem->elem);
        
      } else if (i < 252) {
        // Case where we can allocate sectors to single indirect blocks

        // Read indirect_block struct from disk with cache read and store in buffer
        struct indirect_block *indirect_block; 
        cache_read(disk_inode->single_indirect_block, (void*) indirect_block);

        // Using indirect_block struct, allocate sectors for its indirect_blocks array
        bool result = free_map_allocate(1, &indirect_block->indirect_blocks[i - 128]);
        if (result == false) {
          rollback(&allocated_sectors);
          return false;
        }

        // Write allocated sector to disk
        cache_write(indirect_block->indirect_blocks[i - 128], zeros);
        block_elem = malloc(sizeof(struct block_list_elem));
        block_elem->block_ptr = &indirect_block->indirect_blocks[i - 128];
        list_push_back(&allocated_sectors, &block_elem->elem);
      } else if (i < 252 + 128*128) {
        // Case where we can allocate sectors to double indirect blocks

        // Read indirect_block struct from disk with cache read and store in buffer
        struct indirect_block *double_indirect_block; 
        cache_read(disk_inode->double_indirect_block, (void*) double_indirect_block);

        // Allocate sector to access inner indirect block struct
        bool result = free_map_allocate(1, &double_indirect_block->indirect_blocks[(i - 252) / 128]);
        if (result == false) {
          rollback(&allocated_sectors);
          return false;
        }

        // Write allocated sector to disk
        cache_write(double_indirect_block->indirect_blocks[(i - 252) / 128], zeros);

        block_elem = malloc(sizeof(struct block_list_elem));
        block_elem->block_ptr = &double_indirect_block->indirect_blocks[(i - 252) / 128];
        list_push_back(&allocated_sectors, &block_elem->elem);

        // Using indirect_block struct, index into indirect blocks and read next indirect_block struct that we just allocated
        struct indirect_block *indirect_block; 
        cache_read(double_indirect_block->indirect_blocks[(i - 252) / 128], (void*) indirect_block);

        // Allocate another sector in the inner indirect_block struct to be able to put data in
        result = free_map_allocate(1, &indirect_block->indirect_blocks[(i - 252) % 128]);
        if (result == false) {
          rollback(&allocated_sectors);
          return false;
        }

        // Write allocated sector to disk
        cache_write(indirect_block->indirect_blocks[(i - 252) % 128], zeros);

        block_elem = malloc(sizeof(struct block_list_elem));
        block_elem->block_ptr = &indirect_block->indirect_blocks[(i - 252) % 128];
        list_push_back(&allocated_sectors, &block_elem->elem);
      } else {
        rollback(&allocated_sectors);
        return false;
      }
    }
    
    // Write disk_inode to cache
    cache_write(sector, (void*) disk_inode);
    
    // Free the malloc'd block_elems
    struct list_elem *iter = list_begin(&allocated_sectors);
    while (iter != list_end(&allocated_sectors)) {
      block_elem = list_entry(iter, struct block_list_elem, elem);
      iter = list_next(iter);
      free(block_elem);
    }
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
    struct inode_disk *disk_inode = malloc(BLOCK_SECTOR_SIZE);
    cache_read(inode->sector, (void*) disk_inode);

    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);

      /* Project 3 Task 2 START */
 
      size_t sectors = bytes_to_sectors(disk_inode->length);

      // Read indirect_block struct from disk with cache read and store in buffer
      struct indirect_block *indirect_block; 
      cache_read(disk_inode->single_indirect_block, (void*) indirect_block);

      // Read indirect_block struct from disk with cache read and store in buffer
      struct indirect_block *double_indirect_block; 
      cache_read(disk_inode->double_indirect_block, (void*) double_indirect_block);

      // Allocate sectors within direct block, single indirect block, and double indirect block
      for (int i = 0; i < sectors; i++) {
        if (i < 124) {
          // Case where we can deallocate direct block sectors

          free_map_release(disk_inode->direct_blocks[i], 1);
        
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
        free_map_release(disk_inode->single_indirect_block, 1);

        // Deallocate sector for double indirect block
        free_map_release(disk_inode->double_indirect_block, 1);
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
      cache_read(sector_idx, buffer + bytes_read);
      // block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      cache_read(sector_idx, bounce);
      // block_read(fs_device, sector_idx, bounce);
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

  /* Project 3 Task 2 START */
  static char zeros[BLOCK_SECTOR_SIZE];

  struct list allocated_sectors;
  list_init(&allocated_sectors);
  struct block_list_elem *block_elem;

  struct inode_disk *disk_inode = malloc(BLOCK_SECTOR_SIZE);
  cache_read(inode->sector, disk_inode);

  if (byte_to_sector(inode, offset + size - 1) == -1) {
    
    size_t sectors = bytes_to_sectors(disk_inode->length + offset + size);
    off_t length = disk_inode->length;

    // Allocate sectors within direct block, single indirect block, and double indirect block
    for (int i = length; i < sectors; i++) {
      if (i < 124) {
        // Case where we can allocate sectors to direct blocks

        bool result = free_map_allocate(1, &disk_inode->direct_blocks[i]);
        if (result == false) {
          rollback(&allocated_sectors);
          return false;
        }

        // Write allocated sector to disk
        cache_write(disk_inode->direct_blocks[i], zeros);

        block_elem = malloc(sizeof(struct block_list_elem));
        block_elem->block_ptr = &disk_inode->direct_blocks[i];
        list_push_back(&allocated_sectors, &block_elem->elem);
        
      } else if (i < 252) {
        // Case where we can allocate sectors to single indirect blocks

        // Read indirect_block struct from disk with cache read and store in buffer
        struct indirect_block *indirect_block; 
        cache_read(disk_inode->single_indirect_block, (void*) indirect_block);

        // Using indirect_block struct, allocate sectors for its indirect_blocks array
        bool result = free_map_allocate(1, &indirect_block->indirect_blocks[i - 128]);
        if (result == false) {
          rollback(&allocated_sectors);
          return false;
        }

        // Write allocated sector to disk
        cache_write(indirect_block->indirect_blocks[i - 128], zeros);

        block_elem = malloc(sizeof(struct block_list_elem));
        block_elem->block_ptr = &indirect_block->indirect_blocks[i - 128];
        list_push_back(&allocated_sectors, &block_elem->elem);

      } else if (i < 252 + 128*128) {
        // Case where we can allocate sectors to double indirect blocks

        // Read indirect_block struct from disk with cache read and store in buffer
        struct indirect_block *double_indirect_block; 
        cache_read(disk_inode->double_indirect_block, (void*) double_indirect_block);

        // Allocate sector to access inner indirect block struct
        bool result = free_map_allocate(1, &double_indirect_block->indirect_blocks[(i - 252) / 128]);
        if (result == false) {
          rollback(&allocated_sectors);
          return false;
        }

        // Write allocated sector to disk
        cache_write(double_indirect_block->indirect_blocks[(i - 252) / 128], zeros);

        block_elem = malloc(sizeof(struct block_list_elem));
        block_elem->block_ptr = &double_indirect_block->indirect_blocks[(i - 252) / 128];
        list_push_back(&allocated_sectors, &block_elem->elem);

        // Using indirect_block struct, index into indirect blocks and read next indirect_block struct that we just allocated
        struct indirect_block *indirect_block; 
        cache_read(double_indirect_block->indirect_blocks[(i - 252) / 128], (void*) indirect_block);

        // Allocate another sector in the inner indirect_block struct to be able to put data in
        result = free_map_allocate(1, &indirect_block->indirect_blocks[(i - 252) % 128]);
        if (result == false) {
          rollback(&allocated_sectors);
          return false;
        }

        // Write allocated sector to disk
        cache_write(indirect_block->indirect_blocks[(i - 252) % 128], zeros);

        block_elem = malloc(sizeof(struct block_list_elem));
        block_elem->block_ptr = &indirect_block->indirect_blocks[(i - 252) % 128];
        list_push_back(&allocated_sectors, &block_elem->elem);
      } else {
        rollback(&allocated_sectors);
        return false;
      }
    }

    // Change length of inode
    disk_inode->length = offset + size;

    // Write disk_inode to cache
    cache_write(inode->sector, (void*) inode);

    // Free the malloc'd block_elems
    struct list_elem *iter = list_begin(&allocated_sectors);
    while (iter != list_end(&allocated_sectors)) {
      block_elem = list_entry(iter, struct block_list_elem, elem);
      iter = list_next(iter);
      free(block_elem);
    }
  }

  /* Project 3 Task 2 END */

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
      cache_write(sector_idx, buffer + bytes_written);
      //block_write(fs_device, sector_idx, buffer + bytes_written);
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
        cache_read(sector_idx, bounce);
        // block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      cache_write(sector_idx, bounce);
      // block_write(fs_device, sector_idx, bounce);
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
off_t inode_length(const struct inode* inode) { 
  struct inode_disk *disk_inode = malloc(BLOCK_SECTOR_SIZE);
  cache_read(inode->sector, (void*) disk_inode);
  return disk_inode->length; 
}

/* START TASK: Buffer Cache */
/* The current position of the clock hand for clock replacement algorithm */
int clock_pos;

/* A buffer cache entry */
typedef struct block {
  char *data;             /* Pointer to a 512 byte buffer on the heap. */
  block_sector_t sector;  /* Location of block on disk */
  int clock_state;        /* either 1 or 0 for clock replacement algorithm */
  bool dirty;             /* Dirty bit. true = dirty, false = not dirty */
  bool valid;             /* Valid bit true = valid, false = invalid */
  struct lock b_lock;     /* Lock for reads/writes/evicts to this specific block */
} block;

/* Global buffer cache that stores blocks. */
block buffer_cache[64];

/* Lock for iterating through or replacing an item in the buffer cache. */
struct lock buffer_cache_lock;

/* Initializes buffer cache at system startup. */
void init_buffer_cache(void) {
  /* Initialize blocks in buffer cache */
  for (int i = 0; i < 64; i++) {
    /* Malloc space on heap for data in block. */
    buffer_cache[i].data = (char *) malloc(sizeof(char) * BLOCK_SECTOR_SIZE);
    /* Set entry to invalid (no data in block yet). */
    buffer_cache[i].valid = false;
    /* Set dirty bit to false */
    buffer_cache[i].dirty = false;
    /* Set clock state to 0 (ready for eviction) */
    buffer_cache[i].clock_state = 0;
    /* Set sector's default value to 0. */
    buffer_cache[i].sector = 0;
    /* Initialize block's lock */
    lock_init(&buffer_cache[i].b_lock);
  }

  /* Intiialize clock_pos */
  clock_pos = 0;
  /* Initialize buffer cache lock */
  lock_init(&buffer_cache_lock);
}

/* Flushes buffer cache out to disk and deallocates buffer cache memory at system shut down. */
void flush_cache(void) {
  lock_acquire(&buffer_cache_lock);
  block *cache_entry;
  for (int i = 0; i < 64; i++) {
    cache_entry = &buffer_cache[i];
    /* Make sure all reads/writes before system shutdown finishes before flushing */
    // lock_acquire(&(cache_entry->b_lock));

    /* Only flush if data is valid and dirty. */
    if (cache_entry->valid && cache_entry->dirty) {
      /* Write block's data out to disk. */
      block_write(fs_device, cache_entry->sector, cache_entry->data);
    }
    /* Free cache_entry's allocated data. */
    free(cache_entry->data);

    // lock_release(&(cache_entry->b_lock));
  }

  lock_release(&buffer_cache_lock);
}

/* Evicts a block from buffer cache according to the clock replacement algorithm. Then replaces it with a new block with the given sector on disk. */
int replace_block(block_sector_t sector) {
  /* Note: replace_block should be called in the context of the buffer_cache_lock already acquired. */
  block *cache_entry = NULL;
  block_sector_t evicted_sector;
  while (1) {
    /* Reset clock hand. */
    if (clock_pos >= 64) {
      clock_pos = 0;
    }

    /* Check if cache entry is ready for eviction */
    cache_entry = &buffer_cache[clock_pos];
    if (cache_entry->valid && cache_entry->clock_state == 1) {
      cache_entry->clock_state = 0;
      clock_pos++;
      continue;
    }

    /* Found entry for removal */
    evicted_sector = cache_entry->sector;
    // lock_acquire(&(cache_entry->b_lock));
    /* Check if data changed after acquiring evicted block's lock */
    if (evicted_sector != cache_entry->sector) {
      /* Find another eviction target */
      // lock_release(&(cache_entry->b_lock));
      clock_pos++;
      continue;
    }

    /* If dirty bit set, write data out to disk before eviction. */
    if (cache_entry->dirty) {
      block_write(fs_device, sector, cache_entry->data);
    }

    /* Data is consistent, read disk sector to buffer cache entry. */
    block_read(fs_device, sector, cache_entry->data);
    cache_entry->sector = sector;
    cache_entry->dirty = false;
    cache_entry->valid = true;
    cache_entry->clock_state = 1;
    // lock_release(&(cache_entry->b_lock));
    clock_pos++;
    break;
  }
  return evicted_sector;
}

/* Read an entry from the cache into buffer, pulling in a sector from disk into the cache for reading if the sector is not in the cache already. */
void cache_read(block_sector_t sector, void *buffer) {
  /* Acquire lock to iterate through buffer cache and evict if necessary */
  lock_acquire(&buffer_cache_lock);
  block *cache_entry = NULL;
  block* temp_entry;
  /* Find entry in buffer cache */
  for (int i = 0; i < 64; i++) {
    temp_entry = &buffer_cache[i];
    if (temp_entry->valid && temp_entry->sector == sector) {
      cache_entry = temp_entry;
      break;
    }
  }

  /* Check if entry exists in cache */
  if (cache_entry == NULL) {
    int new_entry_idx = replace_block(sector);
    cache_entry = &buffer_cache[new_entry_idx];
  }

  // lock_release(&buffer_cache_lock);

  /* Read data from buffer cache into buffer. */
  /* Note: This must be outside of buffer_cache_lock acquired to support concurrent reads/writes to different blocks */
  if (cache_entry != NULL) {
    // lock_acquire(&(cache_entry->b_lock));
    /* Check if data changed between releasing buffer cache lock and acquiring cache entry's lock */
    if (cache_entry->sector != sector) {
      /* Data has changed, so try to find it again in the cache. */
      // lock_release(&(cache_entry->b_lock));
      lock_release(&buffer_cache_lock);
      return cache_read(sector, buffer);
    }

    /* Data is consistent, read into buffer. */
    memcpy(buffer, cache_entry->data, BLOCK_SECTOR_SIZE);
    cache_entry->clock_state = 1;
    // lock_release(&(cache_entry->b_lock));
    lock_release(&buffer_cache_lock);
    return;
  } else {
    /* cache_entry is NULL, repeat process */
    lock_release(&buffer_cache_lock);
    return cache_read(sector, buffer);
  }
}

/* Write an entry to the cache from buffer, pulling in a sector from disk into the cache for writing if the sector is not in the cache already. */
void cache_write(block_sector_t sector, void *buffer) {
  /* Acquire lock to iterate through buffer cache and evict if necessary */
  lock_acquire(&buffer_cache_lock);
  block *cache_entry = NULL;
  block* temp_entry;
  /* Find entry in buffer cache */
  for (int i = 0; i < 64; i++) {
    temp_entry = &buffer_cache[i];
    if (temp_entry->valid && temp_entry->sector == sector) {
      cache_entry = temp_entry;
      break;
    }
  }

  /* Check if entry exists in cache */
  if (cache_entry == NULL) {
    int new_entry_idx = replace_block(sector);
    cache_entry = &buffer_cache[new_entry_idx];
  }

  // lock_release(&buffer_cache_lock);

  /* Write data from buffer into cache block. */
  /* Note: This must be outside of acquiring buffer_cache_lock to support concurrent reads/writes to different blocks */
  if (cache_entry != NULL) {
    // lock_acquire(&(cache_entry->b_lock));
    /* Check if data changed between releasing buffer cache lock and acquiring cache entry's lock */
    if (cache_entry->sector != sector) {
      /* Data has changed, so try to find it again in the cache. */
      // lock_release(&(cache_entry->b_lock));
      lock_release(&buffer_cache_lock);
      return cache_write(sector, buffer);
    }

    /* Data is consistent, write buffer into cache block. */
    memcpy(cache_entry->data, buffer, BLOCK_SECTOR_SIZE);
    cache_entry->dirty = true;
    cache_entry->clock_state = 1;
    // lock_release(&(cache_entry->b_lock));
    lock_release(&buffer_cache_lock);
    return;
  } else {
    /* cache_entry is NULL, repeat process */
    lock_release(&buffer_cache_lock);
    cache_write(sector, buffer);
  }
}
/* END TASK: Buffer Cache */
