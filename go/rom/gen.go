package rom

import (
	_ "embed"
	"html/template"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

//go:embed rom.h.tmpl
var tmplHeader []byte

//go:embed rom.S.tmpl
var tmplAsm []byte

//go:embed symbols.go.tmpl
var tmplSymbols []byte

type TemplateData struct {
	R *ROM
}

func (r *ROM) TmplData() *TemplateData {
	return &TemplateData{R: r}
}

func (r *ROM) GenerateHeader(output string) error {
	tmpl := template.New("rom.h")
	tmpl, err := tmpl.Parse(string(tmplHeader))
	if err != nil {
		return xerrors.Errorf("failed to parse template: %w, %s", err, string(tmplHeader))
	}
	filename := filepath.Join(output, "rom.h")
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
	if err != nil {
		return xerrors.Errorf("failed to create output file %s: %w", filename, err)
	}
	defer f.Close()
	return tmpl.Execute(f, r.TmplData())
}

func (r *ROM) GenerateASM(output string) error {
	err := r.BuildChunks()
	if err != nil {
		return xerrors.Errorf("failed to build chunks: %w", err)
	}
	tmpl := template.New("rom.S")
	tmpl, err = tmpl.Parse(string(tmplAsm))
	if err != nil {
		return xerrors.Errorf("failed to parse template: %w, %s", err, string(tmplAsm))
	}
	filename := filepath.Join(output, "rom.S")
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
	if err != nil {
		return xerrors.Errorf("failed to create output file %s: %w", filename, err)
	}
	defer f.Close()
	return tmpl.Execute(f, r.TmplData())
}

func (r *ROM) GenerateSymbols(output string) error {
	tmpl := template.New("symbols.go")
	tmpl, err := tmpl.Parse(string(tmplSymbols))
	if err != nil {
		return xerrors.Errorf("failed to parse template: %w, %s", err, string(tmplSymbols))
	}
	filename := filepath.Join(output, "symbols.go")
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
	if err != nil {
		return xerrors.Errorf("failed to create output file %s: %w", filename, err)
	}
	defer f.Close()
	return tmpl.Execute(f, r.TmplData())
}
