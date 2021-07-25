# flatbuffers

fbs_go_files = [
    'BuildInfo.go',
    'LinkedSection.go',
    'LinkerMeta.go',
    'ROMMeta.go',
    'Symbol.go',
    'VirtualSegment.go'
]

custom_target('fbs_go',
    command: [flatc, '--gen-mutable', '--gen-object-api', '--go', '-o', meson.current_source_dir(), '@INPUT@'],
    input: fbs_files,
    output: fbs_go_files,
    build_by_default: false
)

# Actual go part
go = find_program('go')
go_build_wrapper_file = files('go-build-wrapper')
go_build_wrapper_program = find_program('go-build-wrapper')

go_sources = files(
    'go.mod',
    'go.sum',
    'main.go',
    # cmd
    'cmd/ida.go',
    'cmd/meta.go',
    'cmd/root.go',
    'cmd/asm.go',
    'cmd/header.go',
    'cmd/symbols.go',
    'cmd/usbMsg.go',
    # ida
    'ida/cmd.go',
    'ida/file_pipe.go',
    'ida/redirected_cmd.go',
    'ida/run.go',
    # meta
    'meta/types.go',
    # rom
    'rom/chunk.go',
    'rom/chunk_tree.go',
    'rom/gen.go',
    'rom/instr_test.go',
    'rom/instr.go',
    'rom/meta.go',
    'rom/patcher.go',
    'rom/patching.go',
    'rom/rom.go',
    'rom/symbols.go',
    'rom/tmpl.go',
    'rom/version.go',
    # rom/templates
    'rom/templates/rom.S.tmpl',
    'rom/templates/symbols.go.tmpl',
    'rom/templates/rom.h.tmpl',
    'rom/templates/gen_header.tmpl',
    'rom/templates/symbols_list.h.tmpl',
    # usb_msg
    'usb_msg/generator.go'
)

emmu = custom_target(
    'emmu-go',
    build_by_default: true,
    command: [go_build_wrapper_program, meson.current_source_dir(), '@OUTPUT@'],
    input: go_sources,
    output: 'emmu'
)

rom_cmd = [emmu, 'rom', '--rom', rom, '--out', meson.current_build_dir()]
ida_cmd = [emmu, 'ida', '-i', rom, '--gui=false', '-t']

symbols_file = custom_target(
    'symbols_go',
    output: 'symbols.go',
    command : rom_cmd + ['symbols', '--out', meson.current_source_dir() / 'rom']
)

# if shellcheck.found()
# test('shellcheck go-build-wrapper', shellcheck, args: [go_build_wrapper_file])
# endif
