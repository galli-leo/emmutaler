#ifndef __HEAP_H
#define __HEAP_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define HEAP_START (0x690000000)

#define PAGE_SIZE (0x1000)

typedef struct heap_chunk {
    void* addr;
    struct heap_chunk* next;
    struct heap_chunk* prev;
    size_t size;
    bool mapped;
    void* snapshot;
} heap_chunk_t;

void initialize_chunk(heap_chunk_t* chunk);

/**
 * @brief Remove chunk from the linked list.
 * 
 * @param chunk 
 */
void remove_chunk(heap_chunk_t* chunk);

void insert_chunk(heap_chunk_t* chunk);

void* map_chunk(heap_chunk_t* chunk);
void unmap_chunk(heap_chunk_t* chunk);

void init_heap();
void snapshot_heap();
void restore_snapshot();


void* checked_heap_alloc(size_t size);
void checked_heap_free(void* ptr);
void* checked_heap_memalign(size_t size, size_t constraint);

#endif /* __HEAP_H */
