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
  block_sector_t start; /* First data sector. */
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  uint32_t unused[125]; /* Not used. */
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
  struct inode_disk data; /* Inode content. */
};

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
    block *cache_entry = &buffer_cache[i];

    /* Malloc space on heap for data in block. */
    cache_entry->data = (char *) malloc(sizeof(char) * BLOCK_SECTOR_SIZE);
    /* Set entry to invalid (no data in block yet). */
    cache_entry->valid = false;
    /* Set dirty bit to false */
    cache_entry->dirty = false;
    /* Set clock state to 0 (ready for eviction) */
    cache_entry->clock_state = 0;
    /* Set sector's default value to 0. */
    cache_entry->sector = 0;
    /* Initialize block's lock */
    lock_init(&(cache_entry->b_lock));
  }

  /* Intiialize clock_pos */
  clock_pos = 0;
  /* Initialize buffer cache lock */
  lock_init(&buffer_cache_lock);
}

/* Flushes buffer cache out to disk and deallocates buffer cache memory at system shut down. */
void flush_cache(void) {
  lock_acquire(&buffer_cache_lock);
  
  for (int i = 0; i < 64; i++) {
    block *cache_entry = &buffer_cache[i];
    /* Make sure all reads/writes before system shutdown finishes before flushing */
    lock_acquire(&(cache_entry->b_lock));

    /* Only flush if data is valid and dirty. */
    if (cache_entry->valid && cache_entry->dirty) {
      /* Write block's data out to disk. */
      block_write(fs_device, cache_entry->sector, cache_entry->data);
    }
    /* Free cache_entry's allocated data. */
    free(cache_entry->data);

    lock_release(&(cache_entry->b_lock));
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
    lock_acquire(&(cache_entry->b_lock));
    /* Check if data changed after acquiring evicted block's lock */
    if (evicted_sector != cache_entry->sector) {
      /* Find another eviction target */
      lock_release(&(cache_entry->b_lock));
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
    lock_release(&(cache_entry->b_lock));
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

  /* Find entry in buffer cache */
  for (int i = 0; i < 64; i++) {
    block* temp_entry = &buffer_cache[i];
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

  lock_release(&buffer_cache_lock);

  /* Read data from buffer cache into buffer. */
  /* Note: This must be outside of buffer_cache_lock acquired to support concurrent reads/writes to different blocks */
  if (cache_entry != NULL) {
    lock_acquire(&(cache_entry->b_lock));
    /* Check if data changed between releasing buffer cache lock and acquiring cache entry's lock */
    if (cache_entry->sector != sector) {
      /* Data has changed, so try to find it again in the cache. */
      lock_release(&(cache_entry->b_lock));
      return cache_read(sector, buffer);
    }

    /* Data is consistent, read into buffer. */
    memcpy(buffer, cache_entry->data, BLOCK_SECTOR_SIZE);
    cache_entry->clock_state = 1;
    lock_release(&(cache_entry->b_lock));
    return;
  } else {
    /* cache_entry is NULL, repeat process */
    cache_read(sector, buffer);
  }
}

/* Write an entry to the cache from buffer, pulling in a sector from disk into the cache for writing if the sector is not in the cache already. */
void cache_write(block_sector_t sector, void *buffer) {
  /* Acquire lock to iterate through buffer cache and evict if necessary */
  lock_acquire(&buffer_cache_lock);
  block *cache_entry = NULL;

  /* Find entry in buffer cache */
  for (int i = 0; i < 64; i++) {
    block* temp_entry = &buffer_cache[i];
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

  lock_release(&buffer_cache_lock);

  /* Write data from buffer into cache block. */
  /* Note: This must be outside of acquiring buffer_cache_lock to support concurrent reads/writes to different blocks */
  if (cache_entry != NULL) {
    lock_acquire(&(cache_entry->b_lock));
    /* Check if data changed between releasing buffer cache lock and acquiring cache entry's lock */
    if (cache_entry->sector != sector) {
      /* Data has changed, so try to find it again in the cache. */
      lock_release(&(cache_entry->b_lock));
      return cache_write(sector, buffer);
    }

    /* Data is consistent, write buffer into cache block. */
    memcpy(cache_entry->data, buffer, BLOCK_SECTOR_SIZE);
    cache_entry->dirty = true;
    cache_entry->clock_state = 1;
    lock_release(&(cache_entry->b_lock));
    return;
  } else {
    /* cache_entry is NULL, repeat process */
    cache_write(sector, buffer);
  }
}
/* END TASK: Buffer Cache */

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

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
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    if (free_map_allocate(sectors, &disk_inode->start)) {
      block_write(fs_device, sector, disk_inode);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          block_write(fs_device, disk_inode->start + i, zeros);
      }
      success = true;
    }
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
      free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
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
      /* START TASK: Buffer Cache */
      cache_read(sector_idx, buffer + bytes_read);
      // block_read(fs_device, sector_idx, buffer + bytes_read);
      /* END TASK: Buffer Cache */
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      /* START TASK: Buffer Cache */
      cache_read(sector_idx, bounce);
      // block_read(fs_device, sector_idx, bounce);
      /* END TASK: Buffer Cache */
      
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
      /* START TASK: Buffer Cache */
      cache_write(sector_idx, (void*)(buffer + bytes_written));
      // block_write(fs_device, sector_idx, buffer + bytes_written);
      /* END TASK: Buffer Cache */
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
        /* START TASK: Buffer Cache */
        cache_read(sector_idx, bounce);
        // block_read(fs_device, sector_idx, bounce);
        /* END TASK: Buffer Cache */
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      /* START TASK: Buffer Cache */
      cache_write(sector_idx, bounce);
      // block_write(fs_device, sector_idx, bounce);
      /* END TASK: Buffer Cache */
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
