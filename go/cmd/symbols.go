package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

// symbolsCmd represents the symbols command
var symbolsCmd = &cobra.Command{
	Use:   "symbols",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if outputDirectory == "build" {
			outputDirectory = "rom"
		}
		err := r.GenerateTemplate("symbols.go", outputDirectory)
		if err != nil {
			log.Fatalf("Failed to generate symbols: %v", err)
		}
	},
}

func init() {
	romCmd.AddCommand(symbolsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// symbolsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// symbolsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
