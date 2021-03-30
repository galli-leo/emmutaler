package ida

import "os/exec"

func NewRedirected() *RedirectedCommand {
	return &RedirectedCommand{files: []*FilePipe{}}
}

type RedirectedCommand struct {
	*exec.Cmd
	files []*FilePipe
}

func (r *RedirectedCommand) NewPipe(purpose string) (string, error) {
	p := &FilePipe{}
	name, err := p.Setup(purpose + ".log")
	if err != nil {
		return "", err
	}
	r.files = append(r.files, p)
	return name, nil
}

func (r *RedirectedCommand) Run() error {
	for _, p := range r.files {
		p.Start()
	}
	defer func() {
		for _, p := range r.files {
			p.Stop()
		}
	}()

	return r.Cmd.Run()
}
