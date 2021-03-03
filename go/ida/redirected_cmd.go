package ida

import (
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/xerrors"
)

type RedirectedCommand struct {
	*exec.Cmd
	tmpDir   string
	logFile  string
	openFile *os.File
	watcher  *fsnotify.Watcher
	done     chan struct{}
}

func (r *RedirectedCommand) Run() error {
	go r.Reader()
	defer func() {
		r.done <- struct{}{}
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
	r.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return xerrors.Errorf("failed to create watcher: %w", err)
	}
	r.watcher.Add(r.logFile)
	r.done = make(chan struct{})
	return nil
}

func (r *RedirectedCommand) Reader() {
	var err error
	log.Printf("Starting read copy")
	for {
		_, err = io.Copy(os.Stdout, r.openFile)
		if err != nil {
			log.Printf("Failed to copy from log pipe to stdout: %v", err)
			return
		}
		select {
		case <-r.done:
			log.Printf("IDA done, we are done")
			return
		case ev, ok := <-r.watcher.Events:
			if !ok {
				log.Printf("Had event but was not ok!")
				return
			}
			if ev.Op&fsnotify.Write == fsnotify.Write {
				continue
			}
		case err, ok := <-r.watcher.Errors:
			if !ok {
				log.Printf("Had error but was not ok!")
				return
			}
			log.Printf("Had error while watching: %v", err)
			return
		}
	}

}
