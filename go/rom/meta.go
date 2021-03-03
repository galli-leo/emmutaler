package rom

import (
	"encoding/binary"
	"os"

	"github.com/galli-leo/emmutaler/fbs"
	"github.com/galli-leo/emmutaler/meta"
	flatbuffers "github.com/google/flatbuffers/go"
	"golang.org/x/xerrors"
)

func (r *ROM) MetaFilename() string {
	return r.inputPath + ".emmu"
}

func (r *ROM) LoadMetaFromFile() error {
	buf, err := os.ReadFile(r.MetaFilename())
	if err != nil {
		return xerrors.Errorf("failed to read input meta file %s: %w", r.MetaFilename(), err)
	}
	meta := fbs.GetRootAsROMMeta(buf, 0)
	r.meta = meta.UnPack()
	return nil
}

func (r *ROM) LoadMetaFromBinary() error {
	inFile, err := os.Open(r.inputPath)
	if err != nil {
		return xerrors.Errorf("failed to open input file %s: %w", r.inputPath, err)
	}

	info := &meta.EmbeddedInfo{}
	err = binary.Read(inFile, binary.LittleEndian, info)
	if err != nil {
		return xerrors.Errorf("failed to read into embbeded info struct: %w", err)
	}
	// BuildInfo
	r.meta.BuildInfo.Banner = info.Build.BannerS()
	r.meta.BuildInfo.Style = info.Build.StyleS()
	r.meta.BuildInfo.Tag = info.Build.TagS()

	// LinkerInfo
	r.meta.LinkerInfo.Text = &info.LinkerInfo.Text
	r.meta.LinkerInfo.TextSize = info.LinkerInfo.TextSize
	r.meta.LinkerInfo.DataRoStart = info.LinkerInfo.DataROStart
	r.meta.LinkerInfo.Data = &info.LinkerInfo.Data
	r.meta.LinkerInfo.Bss = &info.LinkerInfo.BSS
	r.meta.LinkerInfo.Stacks = &info.LinkerInfo.Stacks
	r.meta.LinkerInfo.PageTables = &info.LinkerInfo.PageTables
	r.meta.LinkerInfo.HeapGuard = info.LinkerInfo.HeapGuard
	r.meta.LinkerInfo.BootTrampoline = &info.LinkerInfo.BootTrampoline
	r.meta.LinkerInfo.BootTrampolineDest = info.LinkerInfo.BootTrampolineDest

	r.meta.State = fbs.MetaStateSectionsDefined
	return nil
}

func (r *ROM) LoadMeta() error {
	err := r.LoadMetaFromFile()
	if xerrors.Unwrap(err) == os.ErrNotExist {
		// .emmu does not exist, we read from binary!
		err := r.LoadMetaFromBinary()
		if err != nil {
			return xerrors.Errorf("failed to read meta from binary file: %w", err)
		}
		// Create new .emmu file.
		return r.SaveMeta()
	}
	return err
}

func (r *ROM) SaveMeta() error {
	builder := flatbuffers.NewBuilder(1024)
	off := r.meta.Pack(builder)
	builder.Finish(off)
	buf := builder.FinishedBytes()
	return os.WriteFile(r.MetaFilename(), buf, 0777)
}
