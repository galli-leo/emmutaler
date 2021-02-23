package meta

import (
	"github.com/galli-leo/emmutaler/Emmutaler"
	flatbuffers "github.com/google/flatbuffers/go"
)

type VirtualSegment struct {
	Start, Size uint64
}

func (v *VirtualSegment) ToFlatBuffer(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return Emmutaler.CreateVirtualSegment(builder, v.Start, v.Size)
}

type LinkedSection struct {
	Start, End uint64
}

func (v *LinkedSection) ToFlatBuffer(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return Emmutaler.CreateLinkedSection(builder, v.Start, v.End)
}

type LinkerMeta struct {
	// Information about the text section.
	Text LinkedSection
	/*
	   How large the text actually is.
	   !!Important!!: This is not text.end - text.start, this is how much space was actually needed.
	*/
	TextSize uint64
	/*
	   Where inside the RO text section, the (initial) data starts at.
	*/
	DataROStart uint64
	Data        LinkedSection
	BSS         LinkedSection
	Stacks      VirtualSegment
	PageTables  VirtualSegment
	// The end of the heap segment.
	HeapGuard      uint64
	BootTrampoline LinkedSection
	// Where in memory the boot trampoline should be located.
	BootTrampolineDest uint64
}

type BuildInfo struct {
	// Mostly copyright and board id
	Banner [0x40]byte
	// Style of build, e.g. RELEASE or DEBUG
	Style [0x40]byte
	// TODO: IDK??
	Tag [0x80]byte

	// Three unecessary pointers.
	_ [0x18]byte
}

func clen(n []byte) int {
	for i := 0; i < len(n); i++ {
		if n[i] == 0 {
			return i
		}
	}
	return len(n)
}

func stringFromBytes(data []byte) string {
	return string(data[:clen(data)])
}

func (bi *BuildInfo) BannerS() string {
	return stringFromBytes(bi.Banner[:])
}

func (bi *BuildInfo) StyleS() string {
	return stringFromBytes(bi.Style[:])
}

func (bi *BuildInfo) TagS() string {
	return stringFromBytes(bi.Tag[:])
}

type EmbeddedInfo struct {
	Build      BuildInfo
	LinkerInfo LinkerMeta
}
