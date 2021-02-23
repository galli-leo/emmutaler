package ida

import (
	"io"
	"log"
	"os"
	"os/exec"

	"golang.org/x/xerrors"
)

type RedirectedCommand struct {
	*exec.Cmd
	tmpDir   string
	logFile  string
	openFile *os.File
}

func (r *RedirectedCommand) Run() error {
	go r.Reader()
	defer func() {
		log.Printf("Removing tmp dir")
		err := os.RemoveAll(r.tmpDir)
		if err != nil {
			log.Printf("Failed to remove temp dir %s: %v", r.tmpDir, err)
		}
		err = r.openFile.Close()
		if err != nil {
			log.Printf("Failed to close open file: %v", err)
		}
	}()
	return r.Cmd.Run()
}

func (r *RedirectedCommand) Setup() error {
	log.Printf("Setting up named pipe for logging at %s", r.logFile)
	var err error
	r.openFile, err = os.OpenFile(r.logFile, os.O_CREATE|os.O_RDONLY, 0777)
	if err != nil {
		return xerrors.Errorf("failed to create fifo pipe %s: %w", r.logFile, err)
	}
	log.Printf("Created named pipe at %s", r.logFile)
	return nil
}

func (r *RedirectedCommand) Reader() {
	var err error
	log.Printf("Starting read copy")
	for {
		_, err = io.Copy(os.Stdout, r.openFile)
		if err != nil {
			log.Printf("Failed to copy from log pipe to stdout: %v", err)
			break
		}
	}

}
