fbs_py_files = [
    'BuildInfo.py'
]

custom_target('fbs_python',
    command: [flatc, '--gen-mutable', '--gen-object-api', '--python', '-o', join_paths(meson.current_source_dir(), 'emmutaler'), '--include-prefix', 'emmutaler', '@INPUT@'],
    input: fbs_files,
    output: fbs_py_files,
    build_by_default: true
)