/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"log"

	"github.com/galli-leo/emmutaler/ida"
	"github.com/spf13/cobra"
)

var idaPath string = ida.DefaultPath
var launchOpts ida.LaunchOptions

// idaCmd represents the ida command
var idaCmd = &cobra.Command{
	Use:   "ida",
	Short: "Facilitates writing scripts for IDA.",
	Long: `In particular, this is useful for debugging / testing plugins, loaders, etc.
	It launches a new instance of IDA in batch mode (optionally with UI), streaming the output window log to stdout and analyzing the given input file.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		inputFile := args[0]
		launchOpts.InputFile = inputFile
		launchOpts.DeleteDB = true
		c := launchOpts.RedirectedCommand(idaPath)
		err := c.Run()
		if err != nil {
			log.Fatalf("Failed to run command: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(idaCmd)

	idaCmd.Flags().StringVar(&idaPath, "ida", ida.DefaultPath, "Path to the ida installation")
	idaCmd.Flags().BoolVarP(&launchOpts.EnableGUI, "gui", "g", true, "Whether to enable the GUI or not.")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// idaCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// idaCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
