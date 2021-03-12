package rom

import "testing"

func checkChunksTree(t *testing.T, tr *ChunkTree) {
	prevEnd := tr.space.FileStart
	chunks := tr.Chunks()
	for _, chunk := range chunks {
		if chunk.FileStart != prevEnd {
			t.Fatalf("Chunk %s should start at 0x%x but it starts at 0x%x", chunk, prevEnd, chunk.FileStart)
		}
		prevEnd = chunk.FileEnd
	}
	if prevEnd != tr.space.FileEnd {
		t.Fatalf("Final chunk should have ended at 0x%x but it ends at 0x%x", tr.space.FileEnd, prevEnd)
	}
}

func TestTree(t *testing.T) {
	tr := NewChunkTree(0, 0x100)
	chunks := []*Chunk{
		{0x10, 0x100, nil, ""},
		{0x20, 0x30, nil, ""},
		{0x0, 0x15, nil, ""},
	}
	for _, chunk := range chunks {
		tr.Add(chunk)
	}
	checkChunksTree(t, tr)
}
