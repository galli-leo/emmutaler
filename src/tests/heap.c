#include "heap.h"
#include "rom/rom_extra.h"
#include "types.h"
#include "rom.h"

static void* heap_base = 0x19C028000LL;
static size_t heap_size = 0x8000uLL;

void*
setup_heap(const MunitParameter params[], void* user_data)
{
    
    uint64_t g_heap_cookie[2] = { 0xa7fa3a2e367917fcULL, 0x64636b783132322fULL };
    munit_logf(MUNIT_LOG_INFO, "Initializing heap at %p\n", heap_base);
    rom_heap_set_cookie(g_heap_cookie); // TODO: Randomized heap cookie?
    munit_logf(MUNIT_LOG_INFO, "Randomized heap cookie...\n", 0);
    rom_heap_add_chunk(heap_base, heap_size, 1);
}

static char* heap_sizes[] = {
    "0x10",
    "0x100",
    "0x12",
    "0x173",
    NULL
};

static MunitParameterEnum test_params[] = {
  { "size", heap_sizes },
  { NULL, NULL },
};

MunitResult test_malloc(const MunitParameter params[], void* user_data_or_fixture)
{
    char* size_str = munit_parameters_get(params, "size");
    uint64_t alloc_size = strtol(size_str, NULL, 16);
    heap_block* chunk = rom_heap_alloc(alloc_size);
    munit_assert_ptr_not_null(chunk);
    heap_block* act_chunk = chunk-1;
    // munit_assert_ptr_equal(act_chunk->chunk_ptr, heap_base - heap_size);
    munit_assert_size(act_chunk->this_size << 6, >=, alloc_size);
    munit_assert_int64(act_chunk->this_free, ==, 0);
    rom_heap_free(chunk);
    munit_assert_int64(act_chunk->this_free, ==, 1);
    return MUNIT_OK;
}

const MunitTest heap_tests[] = {
  {
    (char*)"/malloc", /* name */
    test_malloc, /* test */
    setup_heap, /* setup */
    NULL, /* tear_down */
    MUNIT_TEST_OPTION_NONE, /* options */
    test_params /* parameters */
  },
  /* Mark the end of the array with an entry where the test
   * function is NULL */
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};