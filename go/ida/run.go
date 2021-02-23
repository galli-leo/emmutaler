package ida

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

const DefaultPath = "/Applications/IDA Pro 7.5/ida64.app/Contents/MacOS/"

type LaunchOptions struct {
	DeleteDB   bool
	Compiler   string
	LogFile    string
	Processor  string
	ScriptArgs []string
	FileType   string
	InputFile  string
	EnableGUI  bool
}

func quoteArg(short string, args string) string {
	return fmt.Sprintf(`-%s"%s"`, short, strings.ReplaceAll(args, `"`, `\"`))
}

func (o *LaunchOptions) Command(path string) *exec.Cmd {
	executable := filepath.Join(path, "idat64")
	if o.EnableGUI {
		executable = filepath.Join(path, "ida64")
	}

	args := []string{"-A"}
	if o.DeleteDB {
		args = append(args, "-c")
	}
	if o.Compiler != "" {
		args = append(args, quoteArg("C", o.Compiler))
	}
	if o.LogFile != "" {
		args = append(args, "-L"+o.LogFile)
	}
	if o.Processor != "" {
		args = append(args, quoteArg("p", o.Processor))
	}
	if len(o.ScriptArgs) > 0 {
		quoted := []string{}
		for _, arg := range o.ScriptArgs {
			quoted = append(quoted, fmt.Sprintf(`"%s"`, arg))
		}

		args = append(args, quoteArg("S", strings.Join(quoted, " ")))
	}
	if o.FileType != "" {
		args = append(args, quoteArg("T", o.FileType))
	}
	args = append(args, o.InputFile)
	cmd := exec.Command(executable, args...)
	log.Printf("Created Command: %s %s", executable, strings.Join(args, " "))
	return cmd
}

func (o *LaunchOptions) RedirectedCommand(path string) *RedirectedCommand {
	tempDir, err := ioutil.TempDir("", "emmutaler")
	if err != nil {
		log.Fatalf("Failed to create temporary directory: %v", err)
	}
	o.LogFile = filepath.Join(tempDir, "ida.log")
	cmd := o.Command(path)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	ret := &RedirectedCommand{
		Cmd:     cmd,
		tmpDir:  tempDir,
		logFile: o.LogFile,
	}
	ret.Setup()
	return ret
}

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
