package cmd

import (
	"github.com/galli-leo/emmutaler/img/certs"
	"github.com/spf13/cobra"
)

var rootInfo = certs.DefaultRootInfo()

// caCmd represents the ca command
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		certs.GenerateRoot(&rootInfo, certDir)
	},
}

func init() {
	imgCmd.AddCommand(caCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// caCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// caCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
