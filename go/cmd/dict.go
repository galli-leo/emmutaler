package cmd

import (
	"github.com/galli-leo/emmutaler/img"
	"github.com/spf13/cobra"
)

var dictFile string

// dictCmd represents the dict command
var dictCmd = &cobra.Command{
	Use:   "dict",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		img.GenerateDict(dictFile)
	},
}

func init() {
	imgCmd.AddCommand(dictCmd)

	dictCmd.Flags().StringVarP(&dictFile, "out", "o", "../../img/img4.dict", "Where to output dictionary file to.")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dictCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dictCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
