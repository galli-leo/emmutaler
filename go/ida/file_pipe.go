package ida

import (
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/xerrors"
)

// An empty struct takes 0 allocation in go, so this is the most efficient way :)
type doneChan chan struct{}

// Represents a shared pipe, but instead of using e.g. mkfifo, we use a standard file.
// We need to do it this way, since IDA doesn't support logging to pipes :(
type FilePipe struct {
	openFile *os.File
	watcher  *fsnotify.Watcher
	done     doneChan
}

func (fp *FilePipe) Setup(purpose string) (string, error) {
	var err error
	fp.openFile, err = ioutil.TempFile("", purpose)
	if err != nil {
		return "", xerrors.Errorf("failed to create fifo pipe %s: %w", purpose, err)
	}

	log.Printf("Created named pipe at %s", fp.openFile.Name())
	fp.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return "", xerrors.Errorf("failed to create watcher: %w", err)
	}
	fp.watcher.Add(fp.openFile.Name())
	fp.done = make(doneChan)
	return fp.openFile.Name(), nil
}

func (fp *FilePipe) Start() {
	go func() {
		fp.Reader()
		fp.Cleanup()
	}()
}

func (fp *FilePipe) Stop() {
	fp.done <- struct{}{}
}

func (fp *FilePipe) Cleanup() {
	fp.openFile.Close()
	os.Remove(fp.openFile.Name())
}

func (fp *FilePipe) Reader() {
	var err error
	// log.Printf("Starting read copy")
	for {
		_, err = io.Copy(os.Stdout, fp.openFile)
		if err != nil {
			log.Printf("Failed to copy from log pipe to stdout: %s", err)
			return
		}
		select {
		case <-fp.done:
			log.Printf("IDA done, we are done")
			return
		case ev, ok := <-fp.watcher.Events:
			if !ok {
				log.Printf("Had event but was not ok!")
				return
			}
			if ev.Op&fsnotify.Write == fsnotify.Write {
				continue
			}
		case err, ok := <-fp.watcher.Errors:
			if !ok {
				log.Printf("Had error but was not ok!")
				return
			}
			log.Printf("Had error while watching: %s", err)
			return
		}
	}

}
