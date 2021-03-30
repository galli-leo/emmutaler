package rom

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"golang.org/x/xerrors"
)

//go:embed templates
var fs embed.FS

// Gives information about the invocation to the template.
// This is used to write useful stuff into the GENERATED DO NOT EDIT header.
type Invocation struct {
	Command string
	Date    string
}

func GetInvocation() Invocation {
	cmd := strings.Join(os.Args, " ")
	return Invocation{
		Command: cmd,
		Date:    time.Now().String(),
	}
}

type TemplateData struct {
	R          *ROM
	Invocation Invocation
}

func (r *ROM) TmplData() *TemplateData {
	return &TemplateData{R: r, Invocation: GetInvocation()}
}

func (r *ROM) GenerateTemplate(filename string, output string) error {
	tmplName := filename + ".tmpl"
	tmpl, err := template.ParseFS(fs, "templates/*.tmpl")
	if err != nil {
		return xerrors.Errorf("failed to parse templates: %w", err)
	}
	fp := filepath.Join(output, filename)
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
	if err != nil {
		return xerrors.Errorf("failed to create output file %s: %w", fp, err)
	}
	defer f.Close()
	return tmpl.ExecuteTemplate(f, tmplName, r.TmplData())
}
