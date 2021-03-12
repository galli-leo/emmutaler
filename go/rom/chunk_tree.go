package rom

import "github.com/Workiva/go-datastructures/augmentedtree"

func NewChunkTree(start, end int64) *ChunkTree {
	t := &ChunkTree{
		t:     augmentedtree.New(1),
		space: ChunkOfRange(start, end),
	}
	t.t.Add(t.space)
	return t
}

type ChunkTree struct {
	t augmentedtree.Tree
	// The space the whole tree spans.
	space *Chunk
}

// Invariant: t.space is spanned by non overlapping chunks.
func (t *ChunkTree) Add(c *Chunk) {
	// Get chunks overlapping with c
	existing := t.t.Query(c)
	if len(existing) == 0 {
		panic("chunk must be inside space!")
	}
	// toDelete := []augmentedtree.Interval{}
	var splitLeft augmentedtree.Interval = nil
	var splitRight augmentedtree.Interval = nil
	newLo := c.LowAtDimension(0)
	newHi := c.HighAtDimension(0)
	for _, exist := range existing {
		lo := exist.LowAtDimension(0)
		hi := exist.HighAtDimension(0)
		if lo < newLo {
			splitLeft = exist
		}
		if newHi < hi {
			splitRight = exist
		}
	}
	// Delete all overlapping chunks.
	t.t.Delete(existing...)
	if splitLeft != nil {
		lo := splitLeft.LowAtDimension(0)
		hi := c.FileStart
		splitted := ChunkOfRange(lo, hi)
		leftC := splitLeft.(*Chunk)
		splitted.Symb = leftC.Symb
		t.t.Add(splitted)
	}
	t.t.Add(c)
	if splitRight != nil {
		hi := splitRight.HighAtDimension(0) + 1
		lo := c.FileEnd
		splitted := ChunkOfRange(lo, hi)
		t.t.Add(splitted)
	}
}

func (t *ChunkTree) Chunks() []*Chunk {
	ret := []*Chunk{}
	for _, i := range t.t.Query(t.space) {
		c, ok := i.(*Chunk)
		if !ok {
			panic("unexpected non chunk entry")
		}
		ret = append(ret, c)
	}
	return ret
}
