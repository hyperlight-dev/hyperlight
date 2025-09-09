#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <mimalloc.h>

// -----------------------------------------------------------------------------
// Static variables for sbrk region_
// -----------------------------------------------------------------------------
static char *heap_start = NULL;
static char *heap_end   = NULL;
static char *brk_ptr    = NULL;

/*
 * Initialize a mimalloc arena on the donated memory region.
 * After this call, all allocations use only the pre‐reserved arena.
 */
void init_arena(void *donated_ptr, size_t donated_size) {
    /* do not use OS memory for allocation */
    mi_option_set_enabled(mi_option_limit_os_alloc, true);

    mi_arena_id_t arena_id = 0;
    bool ok = mi_manage_os_memory_ex(
        donated_ptr,
        donated_size,
        1 /* committed */,
        0 /* large     */,
        0 /* zero      */,
        -1 /* numa_node */,
        1 /* exclusive */,
        &arena_id
    );

    if (!ok) {
        fprintf(stderr, "mi_manage_os_memory_ex failed\n");
        abort();
    }

    /* create a heap in the donated arena and set it as default */
    mi_heap_t *heap = mi_heap_new_in_arena(arena_id);
    mi_heap_set_default(heap);
}

/*
 * Register the heap region to be used by sbrk().
 * Must be called before any sbrk() invocation.
 */
void init_sbrk(void *start, size_t size) {
    heap_start = (char*)start;
    heap_end   = heap_start + size;
    brk_ptr    = heap_start;
}

/*
 * Unix‐style sbrk implementation over the registered heap region.
 * On success returns the previous break; on failure returns (void*)-1
 * and sets errno = ENOMEM.
 */
void *sbrk(ptrdiff_t incr) {
    if (heap_start == NULL) {
        errno = ENOMEM;
        return (void*)-1;
    }

    if (incr < 0) {
        /* shrink: ensure we don't move below heap_start */
        size_t dec = (size_t)(-incr);
        if ((size_t)(brk_ptr - heap_start) < dec) {
            errno = ENOMEM;
            return (void*)-1;
        }
    } else {
        /* grow: ensure we don't move past heap_end */
        size_t inc = (size_t)incr;
        if ((size_t)(heap_end - brk_ptr) < inc) {
            errno = ENOMEM;
            return (void*)-1;
        }
    }

    void *old_brk = brk_ptr;
    brk_ptr += incr;
    return old_brk;
}
