package cmd

import (
	"github.com/galli-leo/emmutaler/rom"
	"github.com/spf13/cobra"
)

var inputFile string
var outputDirectory string
var r *rom.ROM

// romCmd represents the rom command
var romCmd = &cobra.Command{
	Use:   "rom",
	Short: "Responsible for building the ROM image that is supposed to be loaded in with the binary.",
	Long:  `The main command runs all the subcommands in the correct order.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		r = rom.FromPath(inputFile)
		return r.LoadMeta()
	},
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {
	rootCmd.AddCommand(romCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// romCmd.PersistentFlags().String("foo", "", "A help for foo")
	romCmd.PersistentFlags().StringVarP(&inputFile, "rom", "r", "", "Path to the ROM file to use for the build.")
	romCmd.PersistentFlags().StringVarP(&outputDirectory, "out", "o", "build", "Path to were built output should be stored.")
	AddStructFlags(romCmd.PersistentFlags(), &rom.GenConf)
	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// romCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
