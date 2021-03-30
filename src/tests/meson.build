def_lib = get_option('default_library')
message('default_library: ', def_lib)

# munit = dependency('munit', fallback: ['munit', 'munit_dep'])
munit = subproject('munit')
munit_dep = munit.get_variable('munit_dep')

tests_src = common_src + [
    # 'subprojects/munit/libmunit.a',
    'heap.c',
    'heap.h',
    'platform.h',
    'platform.c',
    'main.c'
]

emmu_tests = executable('emmu_tests', tests_src, dependencies : munit_dep, include_directories: inc, link_args: std_link_flags, c_args: std_flags)

# test_list = run_command( emmu_tests, '--list' ).stdout().split()
# foreach test : test_list
# 	test(test, emmu_tests, args: [test, '--color', 'always'])
# endforeach

test('all', emmu_tests, args: ['--color', 'always'],is_parallel: false)