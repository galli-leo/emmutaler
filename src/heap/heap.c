#include "heap.h"
#include <pthread.h>
#include <stddef.h>
#include <sys/mman.h>
#include "debug/log.h"

heap_chunk_t start;
void* curr_addr = HEAP_START;

pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;

size_t roundUp(size_t numToRound, size_t multiple) 
{
    // assert(multiple && ((multiple & (multiple - 1)) == 0));
    return (numToRound + multiple - 1) & -multiple;
}

size_t paged_size(size_t size)
{
    size_t minSize = size + sizeof(heap_chunk_t*);
    return roundUp(minSize, PAGE_SIZE);
}

void* get_user_addr(heap_chunk_t* chunk)
{
    size_t pagedSize = paged_size(chunk->size);
    void* end_addr = chunk->addr + pagedSize;
    void* chunk_addr = end_addr - chunk->size;
    return chunk_addr;
}

void initialize_chunk(heap_chunk_t *chunk)
{
    chunk->addr = 0;
    chunk->snapshot = NULL;
    chunk->mapped = false;
    chunk->next = chunk;
    chunk->prev = chunk;
}

// assumes we have the mutex
void insert_chunk(heap_chunk_t *chunk)
{
    heap_chunk_t* prev = start.prev;
    start.prev = chunk;
    chunk->next = &start;
    chunk->prev = prev;
    prev->next = chunk;
}

// assumes we have the mutex
void remove_chunk(heap_chunk_t *chunk)
{
    heap_chunk_t* prev = chunk->prev;
    prev->next = chunk->next;
    chunk->next->prev = prev;
}

void* map_chunk(heap_chunk_t* chunk)
{
    void* user_addr = get_user_addr(chunk);

    if (chunk->mapped) return user_addr;
    size_t pagedSize = paged_size(chunk->size);
    void* res = mmap(chunk->addr, pagedSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res != chunk->addr) {
        log_error("FAILED TO ALLOCATE PAGE AT %p", chunk->addr);
        abort();
    }
    
    heap_chunk_t** chunk_ptr = (heap_chunk_t**)(user_addr - sizeof(heap_chunk_t*));
    *chunk_ptr = chunk;
    chunk->mapped = true;

    return user_addr;
}

void unmap_chunk(heap_chunk_t *chunk)
{
    if (!chunk->mapped) return;

    size_t pagedSize = paged_size(chunk->size);

    int res = munmap(chunk->addr, pagedSize);
    if (res != 0) {
        log_error("FAILED TO UNMAP PAGE AT %p", chunk->addr);
        abort();
    }

    chunk->mapped = false;
}

void* checked_heap_alloc(size_t size)
{
    // log_warn("heap_alloc(0x%x)", size);
    heap_chunk_t* chunk = calloc(1, sizeof(heap_chunk_t));
    chunk->size = size;
    size_t pagedSize = paged_size(chunk->size);

    pthread_mutex_lock(&heap_mutex);

    chunk->addr = curr_addr;

    insert_chunk(chunk);

    // Should have guard page!
    curr_addr += pagedSize + PAGE_SIZE;

    void* user_addr = map_chunk(chunk);

    pthread_mutex_unlock(&heap_mutex);
    
    return user_addr;
}

// not actually necessary for securerom.
void* checked_heap_memalign(size_t size, size_t constraint)
{
    void* addr = checked_heap_alloc(size);
    // log_debug("heap_memalign(0x%x, 0x%x) = %p", size, constraint, addr);
    return addr;
}

void checked_heap_free(void *ptr)
{
    // bruh why
    if (ptr == NULL) return;
    void* user_addr = ptr;
    heap_chunk_t** chunk_ptr = (heap_chunk_t**)(user_addr - sizeof(heap_chunk_t*));
    heap_chunk_t* chunk = *chunk_ptr;
    // log_warn("heap_free(%p)", chunk->addr);
    pthread_mutex_lock(&heap_mutex);
    unmap_chunk(chunk);
    pthread_mutex_unlock(&heap_mutex);
}

void init_heap()
{
    initialize_chunk(&start);
}

void snapshot_heap()
{
    pthread_mutex_lock(&heap_mutex);
    for (heap_chunk_t* curr = start.next; curr != &start; curr = curr->next)
    {
        if (curr->snapshot == NULL && curr->mapped)
        {
            size_t pagedSize = paged_size(curr->size);
            void* snapshot = mmap(0, pagedSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            curr->snapshot = snapshot;
            memcpy(curr->snapshot, curr->addr, pagedSize);
        }
    }
    pthread_mutex_unlock(&heap_mutex);
}

void restore_snapshot()
{
    // we need a fake here, so that we can safely delete chunks while traversing!
    heap_chunk_t fake;
    pthread_mutex_lock(&heap_mutex);
    for (heap_chunk_t* curr = start.next; curr != &start; curr = curr->next)
    {
        // we had the page before
        if (curr->snapshot != NULL)
        {
            // ensure it is mapped
            map_chunk(curr);
            memcpy(curr->addr, curr->snapshot, paged_size(curr->size));
        } else {
            // We did not have it before, remove chunk from list and free it.
            unmap_chunk(curr);
            remove_chunk(curr);
            heap_chunk_t* to_free = curr;
            curr = &fake;
            curr->next = to_free->next;
            curr->prev = to_free->prev;
            free(to_free);
        }
    }
    pthread_mutex_unlock(&heap_mutex);
}