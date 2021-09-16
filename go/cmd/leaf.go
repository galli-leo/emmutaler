package cmd

import (
	"github.com/galli-leo/emmutaler/img/certs"
	"github.com/spf13/cobra"
)

var leafInfo = certs.DefaultLeafInfo()

// leafCmd represents the leaf command
var leafCmd = &cobra.Command{
	Use:   "leaf",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		rootKey, rootCert := certs.LoadRoot(certDir)
		certs.GenerateLeaf(&leafInfo, rootCert, rootKey, certDir)
	},
}

func init() {
	imgCmd.AddCommand(leafCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// leafCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// leafCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
