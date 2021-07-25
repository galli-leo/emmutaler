package ida

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const DefaultPath = "/Applications/IDA Pro 7.6/ida64.app/Contents/MacOS/"

type LaunchOptions struct {
	DeleteDB     bool
	Compiler     string
	Processor    string
	ScriptArgs   []string
	PluginArgs   []string
	FileType     string
	InputFile    string
	EnableGUI    bool
	AutoAccept   bool
	ShowIDALog   bool
	TempDatabase bool
	extraArgs    []string
}

func quoteArg(short string, args string) string {
	return fmt.Sprintf(`-%s"%s"`, short, strings.ReplaceAll(args, `"`, `\"`))
}

func (o *LaunchOptions) Command(path string) *exec.Cmd {
	executable := filepath.Join(path, "idat64")
	if o.EnableGUI {
		executable = filepath.Join(path, "ida64")
	}

	args := []string{}
	if !o.EnableGUI || o.AutoAccept {
		args = append(args, "-A")
	}
	if o.TempDatabase {
		args = append(args, "-DABANDON_DATABASE=YES")
	}
	if o.DeleteDB {
		args = append(args, "-c")
	}
	if o.Compiler != "" {
		args = append(args, quoteArg("C", o.Compiler))
	}
	if o.Processor != "" {
		args = append(args, quoteArg("p", o.Processor))
	}
	if len(o.ScriptArgs) > 0 {
		quoted := []string{o.ScriptArgs[0]}
		for _, arg := range o.ScriptArgs[1:] {
			quoted = append(quoted, fmt.Sprintf(`"%s"`, arg))
		}

		// Doesn't really work, probably some escaping issue :/
		// args = append(args, quoteArg("S", strings.Join(o.ScriptArgs[:], " ")))
		args = append(args, fmt.Sprintf("-OIDAPython:run_script=%s", o.ScriptArgs[0]))
	}
	if len(o.PluginArgs) > 0 {
		if len(o.ScriptArgs) > 0 {
			origArgs := o.PluginArgs
			o.PluginArgs = o.ScriptArgs
			o.PluginArgs = append(o.PluginArgs, origArgs...)
		} else {
			o.PluginArgs = append([]string{"no_script"}, o.PluginArgs...)
		}
		for _, arg := range o.PluginArgs[:] {
			args = append(args, fmt.Sprintf("-Oemmu:%s", arg))
		}
	}
	if o.FileType != "" {
		args = append(args, quoteArg("T", o.FileType))
	}
	args = append(args, o.extraArgs...)
	args = append(args, o.InputFile)
	cmd := exec.Command(executable, args...)
	log.Printf("Created Command: %s %s", executable, strings.Join(args, " "))
	return cmd
}

func (o *LaunchOptions) RedirectedCommand(path string) *RedirectedCommand {
	r := NewRedirected()
	pyLog, err := r.NewPipe("python")
	if err != nil {
		log.Fatalf("Failed to setup pipe: %s", err)
	}
	o.PluginArgs = append(o.PluginArgs, "--log-file", pyLog)
	if o.ShowIDALog {
		idaLog, err := r.NewPipe("ida")
		if err != nil {
			log.Fatalf("Failed to setup pipe: %s", err)
		}
		o.extraArgs = append(o.extraArgs, "-L"+idaLog)
	}
	cmd := o.Command(path)
	if o.ShowIDALog {
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		cmd.Stdin = os.Stdin
	}
	r.Cmd = cmd
	return r
}
