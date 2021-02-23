# automatically generated by the FlatBuffers compiler, do not modify

# namespace: flatbuffers

import flatbuffers
from flatbuffers.compat import import_numpy
np = import_numpy()

class Symbol(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAsSymbol(cls, buf, offset):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = Symbol()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def SymbolBufferHasIdentifier(cls, buf, offset, size_prefixed=False):
        return flatbuffers.util.BufferHasIdentifier(buf, offset, b"\x53\x52\x4F\x4D", size_prefixed=size_prefixed)

    # Symbol
    def Init(self, buf, pos):
        self._tab = flatbuffers.table.Table(buf, pos)

    # Symbol
    def Name(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # Symbol
    def Address(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Uint64Flags, o + self._tab.Pos)
        return 0

def SymbolStart(builder): builder.StartObject(2)
def SymbolAddName(builder, name): builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(name), 0)
def SymbolAddAddress(builder, address): builder.PrependUint64Slot(1, address, 0)
def SymbolEnd(builder): return builder.EndObject()