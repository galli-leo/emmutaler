package rom

import (
	"log"
	"path/filepath"

	"github.com/galli-leo/emmutaler/fbs"
)

func FromPath(romFile string) *ROM {
	r := &ROM{
		inputPath:  romFile,
		meta:       &fbs.ROMMetaT{State: fbs.MetaStateUninitialized},
		TextChunks: []*Chunk{},
		DataChunks: []*Chunk{},
	}
	return r
}

// ROM represents a SecureROM image "read" from disk.
// Depending on the stage in the build process, it may even have no metadata information yet!
type ROM struct {
	// Path where we originall found the binary image.
	inputPath string
	// Metadata information, either loaded from the .emmu file or parsed from the binary image.
	meta *fbs.ROMMetaT
	// Chunks of Text Section
	TextChunks []*Chunk
	// Chunks of Data Section
	DataChunks []*Chunk
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

func (r *ROM) DataFileStart() int64 {
	return int64(r.meta.LinkerInfo.TextSize)
}
