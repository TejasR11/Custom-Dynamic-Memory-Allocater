# Custom Dynamic Memory Allocator

A general-purpose memory allocator implementing malloc, free, realloc, and calloc with explicit free-list management for optimized performance.

## Features

- Drop-in replacement for standard malloc functions
- Explicit free-list with doubly-linked structure
- Block splitting for efficient space utilization  
- Automatic coalescing to reduce fragmentation
- Header/footer boundary tags for corruption detection
- 16-byte alignment for optimal performance

## Building

```bash
make all
```

This builds `bin/mdriver-explicit` - the test driver.

## Testing

Run the allocator against various workload traces:

```bash
./bin/mdriver-explicit
```

Test traces include realistic programs like `xterm`, `perl`, `login` and stress tests for coalescing and random allocation patterns.

## Implementation

- **mm_malloc()**: First-fit allocation with block splitting
- **mm_free()**: Immediate coalescing with adjacent free blocks  
- **mm_realloc()**: In-place expansion when possible
- **mm_calloc()**: Zero-initialized allocation

The allocator uses boundary tags (headers/footers) to enable bidirectional coalescing and maintains an explicit free-list for O(1) free block management.

## Performance

Optimized for both space utilization and throughput:
- Reduces fragmentation through immediate coalescing
- Fast allocation via explicit free-list traversal
- Efficient memory usage with boundary tag overhead 