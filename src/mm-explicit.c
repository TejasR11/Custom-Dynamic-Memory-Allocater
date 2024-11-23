/*
 * mm-implicit.c - The best malloc package EVAR!
 *
 * TODO (bug): mm_realloc and mm_calloc don't seem to be working...
 * TODO (bug): The allocator doesn't re-use space very well...
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct block{
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;

typedef struct free_block{
    size_t header;
    struct free_block *next;
    struct free_block *prev;
} free_block_t;


/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;
static free_block_t *mm_free_list = NULL;

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}

/** Set's a block's header with the given size and allocation state */
static void set_header_footer(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
    *((size_t *)((void *)block + size - sizeof(size_t))) = size | is_allocated;
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

/** Adds a node to the start of the free list */
static void add_block(free_block_t *block) {
    block->next = mm_free_list;
    block->prev = NULL;
    if (mm_free_list) {
        mm_free_list->prev = block;
    }
    mm_free_list = block;
}

static void remove_block(free_block_t *block) {
    if (!block->prev) {
        mm_free_list = block->next;
    }
    else {
        block->prev->next = block->next;
    }
    if (block->next) {
        block->next->prev = block->prev;
    }
}

/** Coelesces by combining a block with the block (if free) directly to the right */
static void coelescing_helper(block_t *block) {
    if ((void *)block != (void *)mm_heap_first) {
        block_t *left = (block_t *)((void *)block - get_size((block_t *)((void *)block - sizeof(size_t))));
        if (!(is_allocated(left))) {
            size_t new_size = get_size(left) + get_size(block);
            remove_block((free_block_t *)left);
            set_header_footer(left, new_size, false);
            block = left;
        }
    }
    block_t *right = (block_t *)((void *)block + get_size(block));
    if ((void *)right < (void *)mm_heap_last && !(is_allocated(right))) {
        size_t new_size = get_size(block) + get_size(right);
        remove_block((free_block_t *)right);
        set_header_footer(block, new_size, false);
    }

    add_block((free_block_t *)block);
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    // Traverse the blocks in the heap using the explicit list
    free_block_t *curr = mm_free_list;
    while (curr != NULL) {
        if (get_size((block_t *)curr) >= size) {
            return (block_t *)curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }

    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;
    mm_free_list = NULL;
    return true;
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    size = round_up(sizeof(block_t) + size + sizeof(size_t), ALIGNMENT);

    // If there is a large enough free block, use it
    block_t *block = find_fit(size);
    if (block != NULL) {
        size_t block_size = get_size(block);
        remove_block((free_block_t *)block);
        if (block_size - size > round_up(sizeof(block_t) + sizeof(size_t), ALIGNMENT)) {
            set_header_footer(block, size, true);
            block_t *left_over = (block_t *) ((void *) block + size);
            set_header_footer(left_over, block_size - size, false);
            add_block((free_block_t *)left_over);
            if (block == mm_heap_last) {
                mm_heap_last = left_over;
            }
        }
        else {
            set_header_footer(block, get_size(block), true);
        }
        return block->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;

    // Initialize the block with the allocated size
    set_header_footer(block, size, true);
    return block->payload;
}

/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }

    // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    set_header_footer(block, get_size(block), false);
    coelescing_helper(block);
}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if (!old_ptr) {
        return mm_malloc(size);
    }
    if (size == 0) {
        mm_free(old_ptr);
        return NULL;
    }
    void *new_ptr = mm_malloc(size);
    if (!new_ptr) {
        return NULL;
    }
    size_t aligned_size = round_up(sizeof(block_t) + size + sizeof(size_t), ALIGNMENT);
    block_t *old_block = block_from_payload(old_ptr);
    size_t old_block_size = get_size(old_block);
    if (old_block_size >= aligned_size) {
        memcpy(new_ptr, old_ptr, aligned_size - sizeof(block_t) - sizeof(size_t));
        mm_free(old_ptr);
        return new_ptr;
    }

    memcpy(new_ptr, old_ptr, old_block_size - sizeof(block_t) - sizeof(size_t));
    mm_free(old_ptr);

    return new_ptr;
}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    void *new_block = mm_malloc(nmemb * size);
    if (!new_block) {
        return NULL;
    }
    memset(new_block, 0, size * nmemb);
    return new_block;
}

/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {
    printf("Heap -  First: %p, last: %p, free: %p\n", mm_heap_first, mm_heap_last, mm_free_list);
    free_block_t *curr = mm_free_list;
    while (curr) {
        printf("free block - pointer: %p, size: %zu\n", curr, get_size((block_t *)curr));
        curr = curr->next;
    }
}
