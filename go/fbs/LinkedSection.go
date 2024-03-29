// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package fbs

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type LinkedSectionT struct {
	Start uint64
	End uint64
}

func (t *LinkedSectionT) Pack(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	if t == nil { return 0 }
	return CreateLinkedSection(builder, t.Start, t.End)
}
func (rcv *LinkedSection) UnPackTo(t *LinkedSectionT) {
	t.Start = rcv.Start()
	t.End = rcv.End()
}

func (rcv *LinkedSection) UnPack() *LinkedSectionT {
	if rcv == nil { return nil }
	t := &LinkedSectionT{}
	rcv.UnPackTo(t)
	return t
}

type LinkedSection struct {
	_tab flatbuffers.Struct
}

func (rcv *LinkedSection) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *LinkedSection) Table() flatbuffers.Table {
	return rcv._tab.Table
}

func (rcv *LinkedSection) Start() uint64 {
	return rcv._tab.GetUint64(rcv._tab.Pos + flatbuffers.UOffsetT(0))
}
func (rcv *LinkedSection) MutateStart(n uint64) bool {
	return rcv._tab.MutateUint64(rcv._tab.Pos+flatbuffers.UOffsetT(0), n)
}

func (rcv *LinkedSection) End() uint64 {
	return rcv._tab.GetUint64(rcv._tab.Pos + flatbuffers.UOffsetT(8))
}
func (rcv *LinkedSection) MutateEnd(n uint64) bool {
	return rcv._tab.MutateUint64(rcv._tab.Pos+flatbuffers.UOffsetT(8), n)
}

func CreateLinkedSection(builder *flatbuffers.Builder, start uint64, end uint64) flatbuffers.UOffsetT {
	builder.Prep(8, 16)
	builder.PrependUint64(end)
	builder.PrependUint64(start)
	return builder.Offset()
}
