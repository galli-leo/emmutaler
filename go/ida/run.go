package ida

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		quoted := []string{o.ScriptArgs[0]}
		for _, arg := range o.ScriptArgs[1:] {
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
