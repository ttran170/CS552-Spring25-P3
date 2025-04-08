#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);          \
    } while (0)

/**
 * @brief Convert bytes to the correct K value
 *
 * @param bytes the number of bytes
 * @return size_t the K value that will fit bytes
 */
size_t btok(size_t bytes)
{
    size_t k = 0;
    size_t b = UINT64_C(1);
    if (bytes == 0)
        return 0;
    while (bytes > b)
    {
        b <<= 1;
        k++;
    }
    return k;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy)
{
    //Find the buddy of the block
    size_t offset = (size_t)buddy - (size_t)pool->base;
    size_t buddy_offset = offset ^ (UINT64_C(1) << buddy->kval);
    struct avail *b = (struct avail *)((char *)pool->base + buddy_offset);

    return b;
}

void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    if (pool == NULL)
    {
        errno = EINVAL;
        return NULL;
    }

    if (size == 0)
    {
        return NULL;
    }
    
    //get the kval for the requested size with enough room for the tag and kval fields
    size_t kval = btok(size + sizeof(struct avail));

    if (kval > pool->kval_m)
    {
        errno = ENOMEM;
        return NULL;
    }
    
    
    //R1 Find a block

    struct avail *block = NULL;
    size_t j = kval;
    for (j; j <= pool->kval_m; j++)
    {
        if (pool->avail[j].next != &pool->avail[j])
        {
            block = pool->avail[j].next;
            break;
        }
    }

    //There was not enough memory to satisfy the request thus we need to set error and return NULL
    if (block == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }
    //R2 Remove from list;
    block->prev->next = block->next;
    block->next->prev = block->prev;
    block->tag = BLOCK_RESERVED;
    block->kval = kval;
    //R3 Split required?
    // Since j >= kval, we need only check if j > kval
    // If j == kval, then we are done and can return the block
    // Otherwise, we begin splitting the block until j == kval
    while (j>kval)
    {
        //R4 Add buddy to list
        j--;
        struct avail *buddy = buddy_calc(pool, block);
        buddy->tag = BLOCK_AVAIL;
        buddy->kval = j;
        buddy->next = pool->avail[j].next;
        buddy->prev = &pool->avail[j];
        pool->avail[j].next = buddy;
        buddy->next->prev = buddy;
        block = buddy;
    }

    //R5 Return the block to the user
    // Move the pointer to the user memory
    void *ptr = (char *)block + sizeof(struct avail);
    return ptr;

}

void buddy_free(struct buddy_pool *pool, void *ptr)
{
    ptr = (char *)ptr - sizeof(struct avail);
    struct avail *block = (struct avail *)ptr;
    if (block->tag != BLOCK_RESERVED)
    {
        handle_error_and_die("buddy_free invalid block");
    }
    block->tag = BLOCK_AVAIL;

    // Check if buddy exists and is available
    // If buddy has more available buddies, while loop is used
    struct avail *buddy = buddy_calc(pool, block);
    while (buddy->tag == BLOCK_AVAIL && buddy->kval == block->kval)
    {
        // Check if buddy is the last block in the list
        if (buddy->next == buddy)
        {
            break;
        }
        // Remove buddy from list
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;
        // Merge the blocks
        if (block < buddy)
        {
            block->kval++;
            block->next = buddy->next;
            block->prev = &pool->avail[block->kval];
            pool->avail[block->kval].next = block;
            block->next->prev = block;
        }
        else
        {
            buddy->kval++;
            buddy->next = block->next;
            buddy->prev = &pool->avail[buddy->kval];
            pool->avail[buddy->kval].next = buddy;
            buddy->next->prev = buddy;
            block = buddy;
        }
        buddy = buddy_calc(pool, block);
    }

}

/**
 * @brief This is a simple version of realloc.
 *
 * @param poolThe memory pool
 * @param ptr  The user memory
 * @param size the new size requested
 * @return void* pointer to the new user memory
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size){
    //Required for Grad Students
    //Optional for Undergrad Students
    if (ptr == NULL)
    {
        return buddy_malloc(pool, size);
    }
    
    void* new_ptr =  buddy_malloc(pool, size);
    if (new_ptr == NULL){
        return NULL;
    }else{
        // Copy the old data to the new location
        size_t old_size = ((struct avail *)ptr)->kval;
        if (old_size > size)
        {
            old_size = size;
        }
        memcpy(new_ptr, ptr, old_size);
        // Free the old block
        buddy_free(pool, ptr);
        return new_ptr;
    }
}


void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    //make sure pool struct is cleared out
    memset(pool,0,sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);
    //Memory map a block of raw memory to manage
    pool->base = mmap(
        NULL,                               /*addr to map to*/
        pool->numbytes,                     /*length*/
        PROT_READ | PROT_WRITE,             /*prot*/
        MAP_PRIVATE | MAP_ANONYMOUS,        /*flags*/
        -1,                                 /*fd -1 when using MAP_ANONYMOUS*/
        0                                   /* offset 0 when using MAP_ANONYMOUS*/
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    //Set all blocks to empty. We are using circular lists so the first elements just point
    //to an available block. Thus the tag, and kval feild are unused burning a small bit of
    //memory but making the code more readable. We mark these blocks as UNUSED to aid in debugging.
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    //Add in the first block
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    //Zero out the array so it can be reused it needed
    memset(pool,0,sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

/**
 * This function can be useful to visualize the bits in a block. This can
 * help when figuring out the buddy_calc function!
 */
static void printb(unsigned long int b)
{
     size_t bits = sizeof(b) * 8;
     unsigned long int curr = UINT64_C(1) << (bits - 1);
     for (size_t i = 0; i < bits; i++)
     {
          if (b & curr)
          {
               printf("1");
          }
          else
          {
               printf("0");
          }
          curr >>= 1L;
     }
}
