fbs_py_files = []
fbs_py_out_files = []

foreach f : fbs_out_files
    fname = f + '.py'
    fbs_py_files += [fname]
    # fbs_py_out_files += files()
endforeach

fbs_python = custom_target('fbs_python',
    command: [flatc, '--gen-mutable', '--gen-object-api', '--python', '-o', meson.current_source_dir(), '--include-prefix', 'emmutaler', '@INPUT@'],
    input: fbs_files,
    output: fbs_py_files,
    build_by_default: true
)

input_files = [
    'emmutaler/log.py',
    'emmutaler/typeinf.py'
]
# input_files += fbs_files
# TODO

symb_script = meson.current_source_dir() / 'scripts' / 'symbolicate.py'

types_h = custom_target(
    'symbolicate',
    input: input_files + ['scripts/symbolicate.py'] + rom_dep,
    output: 'types.h',
    command : ida_cmd + ['script', symb_script, meson.current_build_dir() / 'types.h'],
    # depends: [fbs_python]
)
