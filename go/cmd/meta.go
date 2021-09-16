package cmd

import (
	"github.com/spf13/cobra"
)

var outputFile string = ""

// metaCmd represents the meta command
var metaCmd = &cobra.Command{
	Use:   "meta",
	Short: "Extract meta information from SecureROM image.",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		r.LoadMetaFromBinary()
		r.SaveMeta()
	},
}

func init() {
	romCmd.AddCommand(metaCmd)

	// metaCmd.Flags().StringVarP(&outputFile, "--output", "o", "", "Path to output file, by default we will use the same name & location as the image")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// metaCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// metaCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
