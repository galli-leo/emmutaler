#include "heap.h"
#include "rom/rom_extra.h"
#include "types.h"
#include "rom.h"
#include "platform.h"
#include "platform/chipid.h"

MunitResult test_chipid(const MunitParameter params[], void* user_data_or_fixture)
{
    uint64_t board_id = 6;
    uint64_t epoch = 1;
    uint64_t prod_mode = 1;
    uint64_t sec_mode = 1;
    uint64_t ecid = 5973101246447662;
    uint64_t sec_dom = 1;
    set_board_id(board_id);
    munit_assert_ulong(board_id, ==, get_board_id());
    set_security_epoch(epoch);
    munit_assert_ulong(epoch, ==, get_security_epoch());
    set_raw_prod_mode(prod_mode);
    munit_assert_ulong(prod_mode, ==, get_raw_prod_mode());
    set_secure_mode(sec_mode);
    munit_assert_ulong(sec_mode, ==, get_secure_mode());
    set_ecid(ecid);
    munit_assert_ulong(ecid, ==, get_ecid());
    set_sec_domain(sec_dom);
    munit_assert_ulong(sec_dom, ==, get_sec_domain());
    return MUNIT_OK;
}

const MunitTest platform_tests[] = {
  {
    (char*)"/chipid", /* name */
    test_chipid, /* test */
    NULL, /* setup */
    NULL, /* tear_down */
    MUNIT_TEST_OPTION_NONE, /* options */
    NULL /* parameters */
  },
  /* Mark the end of the array with an entry where the test
   * function is NULL */
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};