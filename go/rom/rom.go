package rom

import (
	"log"
	"path/filepath"

	"github.com/galli-leo/emmutaler/fbs"
)

func FromPath(romFile string) *ROM {
	r := &ROM{
		inputPath:    romFile,
		meta:         &fbs.ROMMetaT{State: fbs.MetaStateUninitialized, BuildInfo: &fbs.BuildInfoT{}, LinkerInfo: &fbs.LinkerMetaT{}},
		Instructions: []*Instr{},
	}
	return r
}

// ROM represents a SecureROM image "read" from disk.
// Depending on the stage in the build process, it may even have no metadata information yet!
type ROM struct {
	// Path where we originall found the binary image.
	inputPath string

	version VersionInfo
	// Metadata information, either loaded from the .emmu file or parsed from the binary image.
	meta            *fbs.ROMMetaT
	TextSection     *ChunkTree
	ExtraTextChunks []*Chunk
	DataSection     *ChunkTree

	Instructions []*Instr
}

func (r *ROM) Symbols() []*fbs.SymbolT {
	return r.meta.Symbols
}

func (r *ROM) BinaryPath() string {
	ret, err := filepath.Abs(r.inputPath)
	if err != nil {
		log.Fatalf("Failed to get absolute binary path %s: %v", r.inputPath, err)
	}
	return ret
}

const DATA_ALIGN = 0x3FFF

func (r *ROM) DataFileStart() int64 {
	return (int64(r.meta.LinkerInfo.TextSize) + DATA_ALIGN) & (^DATA_ALIGN)
}

func (r *ROM) BSSSize() int64 {
	return int64(r.meta.LinkerInfo.Bss.End - r.meta.LinkerInfo.Bss.Start)
}

func (r *ROM) StacksSize() int64 {
	return int64(r.meta.LinkerInfo.Stacks.Size)
}

func (r *ROM) PTSize() int64 {
	return int64(r.meta.LinkerInfo.PageTables.Size)
}
