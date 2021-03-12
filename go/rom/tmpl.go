package rom

import (
	"bytes"
	"fmt"
	"text/template"

	"golang.org/x/xerrors"
)

func TemplateString(tmpl string, data interface{}) (string, error) {
	t := template.New("my_template")
	t, err := t.Parse(tmpl)
	if err != nil {
		return "", xerrors.Errorf("failed to parse template %s: %w", tmpl, err)
	}
	return ExecuteString(t, data)
}

func ExecuteString(t *template.Template, data interface{}) (string, error) {
	buf := bytes.NewBuffer([]byte{})
	err := t.Execute(buf, data)
	return buf.String(), err
}

func MustTemplate(tmpl string) *template.Template {
	return template.Must(template.New("random_ass_template").Parse(tmpl))
}

func MustExecute(t *template.Template, data interface{}) string {
	ret, err := ExecuteString(t, data)
	if err != nil {
		panic(fmt.Sprintf("Failed to execute template %v: %s", t, err))
	}
	return ret
}
