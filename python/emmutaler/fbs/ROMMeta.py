# automatically generated by the FlatBuffers compiler, do not modify

# namespace: fbs

import flatbuffers
from flatbuffers.compat import import_numpy
np = import_numpy()

class ROMMeta(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAsROMMeta(cls, buf, offset):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = ROMMeta()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def ROMMetaBufferHasIdentifier(cls, buf, offset, size_prefixed=False):
        return flatbuffers.util.BufferHasIdentifier(buf, offset, b"\x53\x52\x4F\x4D", size_prefixed=size_prefixed)

    # ROMMeta
    def Init(self, buf, pos):
        self._tab = flatbuffers.table.Table(buf, pos)

    # ROMMeta
    def BuildInfo(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            from emmutaler.fbs.BuildInfo import BuildInfo
            obj = BuildInfo()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # ROMMeta
    def LinkerInfo(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            x = self._tab.Indirect(o + self._tab.Pos)
            from emmutaler.fbs.LinkerMeta import LinkerMeta
            obj = LinkerMeta()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # ROMMeta
    def Symbols(self, j):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            from emmutaler.fbs.Symbol import Symbol
            obj = Symbol()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # ROMMeta
    def SymbolsLength(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # ROMMeta
    def SymbolsIsNone(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        return o == 0

    # ROMMeta
    def State(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.Get(flatbuffers.number_types.Int32Flags, o + self._tab.Pos)
        return 0

def ROMMetaStart(builder): builder.StartObject(4)
def ROMMetaAddBuildInfo(builder, buildInfo): builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(buildInfo), 0)
def ROMMetaAddLinkerInfo(builder, linkerInfo): builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(linkerInfo), 0)
def ROMMetaAddSymbols(builder, symbols): builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(symbols), 0)
def ROMMetaStartSymbolsVector(builder, numElems): return builder.StartVector(4, numElems, 4)
def ROMMetaAddState(builder, state): builder.PrependInt32Slot(3, state, 0)
def ROMMetaEnd(builder): return builder.EndObject()

import emmutaler.fbs.BuildInfo
import emmutaler.fbs.LinkerMeta
import emmutaler.fbs.Symbol
try:
    from typing import List, Optional
except:
    pass

class ROMMetaT(object):

    # ROMMetaT
    def __init__(self):
        self.buildInfo = None  # type: Optional[emmutaler.fbs.BuildInfo.BuildInfoT]
        self.linkerInfo = None  # type: Optional[emmutaler.fbs.LinkerMeta.LinkerMetaT]
        self.symbols = None  # type: List[emmutaler.fbs.Symbol.SymbolT]
        self.state = 0  # type: int

    @classmethod
    def InitFromBuf(cls, buf, pos):
        rOMMeta = ROMMeta()
        rOMMeta.Init(buf, pos)
        return cls.InitFromObj(rOMMeta)

    @classmethod
    def InitFromObj(cls, rOMMeta):
        x = ROMMetaT()
        x._UnPack(rOMMeta)
        return x

    # ROMMetaT
    def _UnPack(self, rOMMeta):
        if rOMMeta is None:
            return
        if rOMMeta.BuildInfo() is not None:
            self.buildInfo = emmutaler.fbs.BuildInfo.BuildInfoT.InitFromObj(rOMMeta.BuildInfo())
        if rOMMeta.LinkerInfo() is not None:
            self.linkerInfo = emmutaler.fbs.LinkerMeta.LinkerMetaT.InitFromObj(rOMMeta.LinkerInfo())
        if not rOMMeta.SymbolsIsNone():
            self.symbols = []
            for i in range(rOMMeta.SymbolsLength()):
                if rOMMeta.Symbols(i) is None:
                    self.symbols.append(None)
                else:
                    symbol_ = emmutaler.fbs.Symbol.SymbolT.InitFromObj(rOMMeta.Symbols(i))
                    self.symbols.append(symbol_)
        self.state = rOMMeta.State()

    # ROMMetaT
    def Pack(self, builder):
        if self.buildInfo is not None:
            buildInfo = self.buildInfo.Pack(builder)
        if self.linkerInfo is not None:
            linkerInfo = self.linkerInfo.Pack(builder)
        if self.symbols is not None:
            symbolslist = []
            for i in range(len(self.symbols)):
                symbolslist.append(self.symbols[i].Pack(builder))
            ROMMetaStartSymbolsVector(builder, len(self.symbols))
            for i in reversed(range(len(self.symbols))):
                builder.PrependUOffsetTRelative(symbolslist[i])
            symbols = builder.EndVector(len(self.symbols))
        ROMMetaStart(builder)
        if self.buildInfo is not None:
            ROMMetaAddBuildInfo(builder, buildInfo)
        if self.linkerInfo is not None:
            ROMMetaAddLinkerInfo(builder, linkerInfo)
        if self.symbols is not None:
            ROMMetaAddSymbols(builder, symbols)
        ROMMetaAddState(builder, self.state)
        rOMMeta = ROMMetaEnd(builder)
        return rOMMeta
