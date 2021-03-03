package rom

import (
	"os"
	"testing"
)

const testFile = "../../../SecureROMs-master/SecureROM for t8030si, iBoot-4479.0.0.100.4"

func checkChunks(t *testing.T, chunks []*Chunk, start int64) {
	prevEnd := start
	for _, chunk := range chunks {
		if chunk.FileStart != prevEnd {
			t.Fatalf("Chunk %s should start at 0x%x but it starts at 0x%x", chunk, prevEnd, chunk.FileStart)
		}
		prevEnd = chunk.FileEnd
	}
}

func TestBuildChunks(t *testing.T) {
	r := FromPath(testFile)
	err := r.LoadMeta()
	if err != nil {
		t.Fatalf("Failed to load meta: %s", err)
	}
	err = r.BuildChunks()
	if err != nil {
		t.Fatalf("Failed to build chunks: %s", err)
	}
	t.Logf("Got %d, %d many chunks", len(r.TextChunks), len(r.DataChunks))
	// check that chunks are correct and cover whole file.
	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("Failed to get filesize: %s", err)
	}
	checkChunks(t, r.TextChunks, 0)
	lastText := r.TextChunks[len(r.TextChunks)-1]
	if lastText.FileEnd != r.DataFileStart() {
		t.Fatalf("Last chunk in text region should end at 0x%x not 0x%x", r.DataFileStart(), lastText.FileEnd)
	}
	checkChunks(t, r.DataChunks, lastText.FileEnd)
	lastData := r.DataChunks[len(r.DataChunks)-1]
	if lastData.FileEnd != info.Size() {
		t.Fatalf("Last chunk in data region should end at 0x%x not 0x%x", info.Size(), lastData.FileEnd)
	}
}
