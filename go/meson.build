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
    build_by_default: true
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
    # ida
    'ida/redirected_cmd.go',
    'ida/run.go',
    # meta
    'meta/types.go'
)

custom_target(
    'emmu-go',
    build_by_default: true,
    command: [go_build_wrapper_program, meson.current_source_dir(), meson.current_build_dir()],
    input: go_sources,
    output: 'emmu'
)

# if shellcheck.found()
# test('shellcheck go-build-wrapper', shellcheck, args: [go_build_wrapper_file])
# endif
