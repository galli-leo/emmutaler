package rom

import (
	"fmt"
	"os"

	"github.com/Workiva/go-datastructures/augmentedtree"
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
	// Potentially we have raw assembly instead.
	RawASM string
}

func (c *Chunk) Size() int64 {
	return c.FileEnd - c.FileStart
}

func (c *Chunk) String() string {
	name := ""
	if c.Symb != nil {
		name = " " + c.Symb.Name
	}
	if c.RawASM != "" {
		name = " " + c.RawASM
	}
	return fmt.Sprintf("[0x%x-0x%x]%s", c.FileStart, c.FileEnd, name)
}

func (c *Chunk) Empty() bool {
	return c.FileStart >= c.FileEnd
}

func (c *Chunk) LowAtDimension(uint64) int64 {
	return c.FileStart
}

func (c *Chunk) HighAtDimension(uint64) int64 {
	return c.FileEnd - 1
}

func (c *Chunk) OverlapsAtDimension(other augmentedtree.Interval, dim uint64) bool {
	return false
}

func (c *Chunk) ID() uint64 {
	return uint64(c.FileStart)
}

func QueryPoint(addr int64) *ROMPoint {
	return &ROMPoint{Address: addr}
}

type ROMPoint struct {
	Address int64
}

func (c *ROMPoint) LowAtDimension(uint64) int64 {
	return c.Address
}

func (c *ROMPoint) HighAtDimension(uint64) int64 {
	return c.Address
}

func (c *ROMPoint) OverlapsAtDimension(other augmentedtree.Interval, dim uint64) bool {
	lo := other.LowAtDimension(dim)
	hi := other.HighAtDimension(dim)
	return lo <= c.Address && c.Address < hi
}

func (c *ROMPoint) ID() uint64 {
	return uint64(c.Address)
}

// Appends the chunk to the correct array, depending on where in the file it resides.
// Is safe to call on a nil chunk (ignored).
func (r *ROM) AppendChunk(c *Chunk) {
	if c == nil || c.Empty() {
		return
	}
	if c.FileStart < r.DataFileStart() {
		r.TextSection.Add(c)
	} else {
		r.DataSection.Add(c)
	}
}

func (r *ROM) BuildChunks() error {
	info, err := os.Stat(r.inputPath)
	if err != nil {
		return xerrors.Errorf("failed to get info about input file %s: %w", r.inputPath, err)
	}

	r.TextSection = NewChunkTree(0, r.DataFileStart())
	r.DataSection = NewChunkTree(r.DataFileStart(), info.Size())
	r.ExtraTextChunks = []*Chunk{}

	for _, symb := range r.meta.Symbols {
		cs := ChunkOfSymb(symb)
		r.AppendChunk(cs)
	}
	// r.TextChunks, err = r.buildChunksSection(r.TextSection, 0, r.DataFileStart())
	return err
}

// func (r *ROM) BuildChunks() error {
// 	info, err := os.Stat(r.inputPath)
// 	if err != nil {
// 		return xerrors.Errorf("failed to get info about input file %s: %w", r.inputPath, err)
// 	}
// 	currFileOffset := int64(0)
// 	currSymb := 0
// 	var c *Chunk = nil
// 	for currFileOffset < info.Size() && currSymb < len(r.meta.Symbols) {
// 		symb := r.meta.Symbols[currSymb]
// 		if c != nil {
// 			c.FileEnd = currFileOffset
// 		}
// 		if symb.FileStart < uint64(currFileOffset) {
// 			log.Printf("Symbol %s overlaps with previous symbol %s", symb.Name, r.meta.Symbols[currSymb-1].Name)
// 			currSymb++
// 			continue
// 		} else if symb.FileStart == uint64(currFileOffset) {
// 			r.AppendChunk(c)
// 			cs := ChunkOfSymb(symb)
// 			r.AppendChunk(cs)
// 			currFileOffset += cs.Size()
// 			currSymb += 1
// 			c = nil
// 			continue
// 		} else if currFileOffset == r.DataFileStart() {
// 			r.AppendChunk(c)
// 			if c == nil {
// 				c = ChunkOfRange(currFileOffset, currFileOffset+1)
// 			} else {
// 				c = nil
// 				continue
// 			}
// 		} else if c == nil {
// 			c = ChunkOfRange(currFileOffset, currFileOffset+1)
// 		}
// 		currFileOffset += 1
// 	}
// 	if c != nil {
// 		c.FileEnd = info.Size()
// 		r.AppendChunk(c)
// 	} else {
// 		r.AppendChunk(ChunkOfRange(currFileOffset, info.Size()))
// 	}
// 	return nil
// }
