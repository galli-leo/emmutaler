package rom

import (
	"fmt"
	"log"
	"os"

	"github.com/galli-leo/emmutaler/fbs"
	"golang.org/x/xerrors"
)

func ChunkOfSymb(s *fbs.SymbolT) *Chunk {
	return &Chunk{
		FileStart: int64(s.FileStart),
		FileEnd:   int64(s.FileEnd),
		Symb:      s,
	}
}

func ChunkOfRange(start, end int64) *Chunk {
	return &Chunk{
		FileStart: start,
		FileEnd:   end,
	}
}

// A chunk is a small region of the ROM, that either is associated with a symbol or describes raw data.
// We use this in the generation, to make sure we include all data as we should.
type Chunk struct {
	// Start and end in the file. End is non inclusive, i.e. the next byte of the next chunk.
	FileStart int64
	FileEnd   int64
	// Potentially a symbol associated with this chunk.
	Symb *fbs.SymbolT
}

func (c *Chunk) Size() int64 {
	return c.FileEnd - c.FileStart
}

func (c *Chunk) String() string {
	name := ""
	if c.Symb != nil {
		name = " " + c.Symb.Name
	}
	return fmt.Sprintf("[0x%x-0x%x]%s", c.FileStart, c.FileEnd, name)
}

// Appends the chunk to the correct array, depending on where in the file it resides.
// Is safe to call on a nil chunk (ignored).
func (r *ROM) AppendChunk(c *Chunk) {
	if c == nil {
		return
	}
	if c.FileStart < r.DataFileStart() {
		r.TextChunks = append(r.TextChunks, c)
	} else {
		r.DataChunks = append(r.DataChunks, c)
	}
}

func (r *ROM) BuildChunks() error {
	info, err := os.Stat(r.inputPath)
	if err != nil {
		return xerrors.Errorf("failed to get info about input file %s: %w", r.inputPath, err)
	}
	currFileOffset := int64(0)
	currSymb := 0
	var c *Chunk = nil
	for currFileOffset < info.Size() && currSymb < len(r.meta.Symbols) {
		symb := r.meta.Symbols[currSymb]
		if c != nil {
			c.FileEnd = currFileOffset
		}
		if symb.FileStart < uint64(currFileOffset) {
			log.Printf("Symbol %s overlaps with previous symbol %s", symb.Name, r.meta.Symbols[currSymb-1].Name)
			currSymb++
			continue
		} else if symb.FileStart == uint64(currFileOffset) {
			r.AppendChunk(c)
			cs := ChunkOfSymb(symb)
			r.AppendChunk(cs)
			currFileOffset += cs.Size()
			currSymb += 1
			c = nil
			continue
		} else if currFileOffset == r.DataFileStart() {
			r.AppendChunk(c)
			if c == nil {
				c = ChunkOfRange(currFileOffset, currFileOffset+1)
			} else {
				c = nil
				continue
			}
		} else if c == nil {
			c = ChunkOfRange(currFileOffset, currFileOffset+1)
		}
		currFileOffset += 1
	}
	if c != nil {
		c.FileEnd = info.Size()
		r.AppendChunk(c)
	} else {
		r.AppendChunk(ChunkOfRange(currFileOffset, info.Size()))
	}
	return nil
}
