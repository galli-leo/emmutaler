package cmd

import (
	"log"

	"github.com/galli-leo/emmutaler/ida"
	"github.com/spf13/cobra"
)

var idaPath string = ida.DefaultPath
var launchOpts ida.LaunchOptions
var script string

func launchCommand() {
	c := launchOpts.RedirectedCommand(idaPath)
	err := c.Run()
	if err != nil {
		log.Fatalf("Failed to run command: %v", err)
	}
}

// idaCmd represents the ida command
var idaCmd = &cobra.Command{
	Use:   "ida",
	Short: "Facilitates interacting with the IDA command line.",
	Long: `In particular, this is useful for debugging / testing plugins, loaders, etc.
	It launches a new instance of IDA in batch mode (optionally with UI), streaming the output window log to stdout and analyzing the given input file.`,
	// Args: cobra.ExactArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {

	},
	Run: func(cmd *cobra.Command, args []string) {
		launchCommand()
	},
}

func init() {
	rootCmd.AddCommand(idaCmd)

	idaCmd.PersistentFlags().StringVar(&idaPath, "ida", ida.DefaultPath, "Path to the ida installation")
	idaCmd.PersistentFlags().BoolVarP(&launchOpts.EnableGUI, "gui", "g", true, "Whether to enable the GUI or not.")
	// idaCmd.Flags().StringVarP(&script, "script", "s", "", "Path to script to run on load")
	idaCmd.PersistentFlags().BoolVarP(&launchOpts.DeleteDB, "delete", "c", false, "Whether to delete the database on start or not.")
	idaCmd.PersistentFlags().StringVarP(&launchOpts.InputFile, "input", "i", "", "Input file to load, can have existing database, but should not be open!")
	idaCmd.MarkFlagRequired("input")
	idaCmd.PersistentFlags().BoolVarP(&launchOpts.ShowIDALog, "log", "l", false, "Whether to show the IDA log on stdout. Otherwise only python log will be shown.")
	idaCmd.PersistentFlags().BoolVarP(&launchOpts.TempDatabase, "temp", "t", false, "Whether to not save database changes on exit.")
	idaCmd.PersistentFlags().BoolVarP(&launchOpts.AutoAccept, "auto", "a", false, "Whether to automatically answer any dialogs that come up. Enabled whenever gui == false and disabled by default if gui == true")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// idaCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// idaCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
